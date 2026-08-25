# Lab 11: Blind SQL Injection with Conditional Responses


## 1. Lỗ hổng này là gì?

**Blind SQL Injection (SQLi mù) dựa trên phản hồi có điều kiện (conditional responses)** — một biến thể của SQL Injection, thuộc nhóm **Inferential / Blind**.

Điểm khác biệt so với các dạng SQLi bạn đã học trước đó (Union-based):

| Đặc điểm | Union-based SQLi | Blind SQLi (conditional response) |
|---|---|---|
| Kết quả truy vấn | Hiển thị trực tiếp ra trang | **Không** hiển thị |
| Thông báo lỗi SQL | Có thể thấy (Error-based) | **Không** hiển thị bất kỳ lỗi nào |
| Cách "đọc" dữ liệu | Đọc trực tiếp | Chỉ suy luận qua **1 tín hiệu gián tiếp** duy nhất |

Ở lab này, ứng dụng dùng 1 **cookie tracking** (`TrackingId`) cho mục đích phân tích (analytics), và đưa thẳng giá trị cookie vào 1 câu truy vấn SQL phía backend — **không lọc/không kiểm tra dữ liệu đầu vào**. Tín hiệu duy nhất bạn có được là: nếu truy vấn trả về ≥1 dòng, trang sẽ hiện dòng chữ **`Welcome back`**; nếu không trả về dòng nào, sẽ **không** có dòng chữ đó.

➡️ Vì không thấy dữ liệu, không thấy lỗi — bạn phải khai thác bằng cách đặt hàng loạt **câu hỏi đúng/sai (true/false)** cho database, và dựa vào có/không có `Welcome back` để suy ra từng mảnh dữ liệu thật.

---

## 2. Root cause (nguyên nhân gốc rễ) là gì?

Nguyên nhân gốc — giống hệt mọi lỗi SQL Injection khác — nằm ở cách backend xử lý dữ liệu đầu vào:

1. **Backend nối chuỗi (string concatenation) trực tiếp** giá trị cookie `TrackingId` vào câu truy vấn SQL, thay vì dùng **parameterized query / prepared statement**.

   Câu truy vấn thật (suy luận được) có dạng tương tự:
   ```sql
   SELECT trackingId FROM tracking_table WHERE trackingId = '<giá_trị_cookie>'
   ```
   Vì giá trị cookie được chèn thẳng vào giữa cặp dấu nháy đơn `'...'` mà **không qua bước làm sạch (sanitize) hay escape ký tự đặc biệt**, nên bất kỳ ai gửi cookie chứa cú pháp SQL (`'`, `AND`, `OR`, subquery...) đều có thể **thay đổi cấu trúc logic** của câu truy vấn gốc.

2. **Input không được kiểm tra kiểu dữ liệu / không dùng whitelist.** Lẽ ra `TrackingId` chỉ nên là 1 chuỗi định danh ngẫu nhiên (ví dụ UUID) — backend hoàn toàn có thể validate rằng giá trị chỉ chứa ký tự hex/alphanumeric và từ chối mọi ký tự khác. Nhưng ở đây backend chấp nhận **bất kỳ chuỗi nào**, kể cả chuỗi chứa cú pháp SQL.

3. **Cookie bị xem là input "tin cậy ngầm".** Một sai lầm phổ biến: lập trình viên coi cookie do chính server sinh ra ban đầu là dữ liệu "an toàn" vì "chỉ mình server tạo ra nó". Nhưng thực tế, **cookie hoàn toàn nằm trong tầm kiểm soát của client** — người dùng (hoặc kẻ tấn công) có thể sửa bất kỳ giá trị nào trong request trước khi gửi lên server (qua Burp Proxy, DevTools...). Mọi input từ client — dù là query param, body, header hay cookie — đều phải được coi là **không đáng tin cậy (untrusted)**.

➡️ Tóm gọn root cause: **dữ liệu không tin cậy từ client được nối trực tiếp vào câu lệnh SQL mà không qua tham số hóa (parameterization) hoặc kiểm tra/lọc đầu vào.**

---

## 3. Cách khai thác (khai thác thủ công + tự động hóa)

### 3.1. Nguyên lý cốt lõi

Vì chỉ có 1 tín hiệu true/false (`Welcome back` có/không), toàn bộ kỹ thuật khai thác xoay quanh việc:
1. Chèn thêm điều kiện `AND <biểu_thức>` vào sau giá trị cookie hợp lệ.
2. Nếu `<biểu_thức>` đúng → toàn bộ mệnh đề `WHERE` vẫn đúng → có dòng trả về → `Welcome back` xuất hiện.
3. Nếu `<biểu_thức>` sai → mệnh đề `WHERE` sai → không có dòng nào → không có `Welcome back`.

Bằng cách thiết kế `<biểu_thức>` thông minh (dùng subquery, `LENGTH()`, `SUBSTRING()`...), bạn có thể biến câu hỏi đúng/sai thành công cụ **dựng lại toàn bộ dữ liệu thật từng ký tự một**.

### 3.2. Quy trình khai thác tổng quát (5 giai đoạn)

```
Giai đoạn 1: Xác nhận tham số bị lỗi (test case đúng vs sai)
        ↓
Giai đoạn 2: Xác nhận tồn tại bảng cần nhắm tới (users)
        ↓
Giai đoạn 3: Xác nhận tồn tại record cần nhắm tới (username = administrator)
        ↓
Giai đoạn 4: Dò độ dài dữ liệu cần lấy (LENGTH(password) > N)
        ↓
Giai đoạn 5: Dò từng ký tự dữ liệu (SUBSTRING(password, i, 1) = 'x') → dùng Intruder
```

### 3.3. Vì sao không dùng Union-based được ở đây?

Vì kết quả truy vấn **không được trả về** trong response (không có bảng dữ liệu nào hiện ra, kể cả khi UNION thành công về mặt cú pháp) — nên kỹ thuật UNION (đọc dữ liệu trực tiếp) **vô dụng** trong tình huống này. Đây chính là điểm phân biệt then chốt giữa **In-band SQLi** và **Blind SQLi**: chọn kỹ thuật khai thác nào phụ thuộc vào việc *ứng dụng có phản hồi dữ liệu ra ngoài hay không*.

### 3.4. Kỹ thuật dùng subquery để hỏi "dữ liệu X có tồn tại không?"

```sql
(SELECT 'x' FROM users LIMIT 1) = 'x'
```
- Nếu bảng `users` tồn tại và có ≥1 dòng → subquery trả về chuỗi `'x'` → so sánh `'x' = 'x'` → **true**.
- Nếu bảng không tồn tại hoặc rỗng → subquery trả về NULL → so sánh với `'x'` → **false**.
- `LIMIT 1` bắt buộc phải có để subquery chỉ trả về đúng 1 giá trị (nếu trả về nhiều dòng, một số DB sẽ báo lỗi "subquery returns more than 1 row" và phá vỡ toàn bộ truy vấn).

Muốn kiểm tra 1 điều kiện cụ thể hơn (ví dụ user có tồn tại), thêm `WHERE` vào trong subquery:
```sql
(SELECT username FROM users WHERE username = 'administrator') = 'administrator'
```

### 3.5. Kỹ thuật dò độ dài chuỗi

```sql
(SELECT username FROM users WHERE username = 'administrator' AND LENGTH(password) > N) = 'administrator'
```
Tăng dần `N` (hoặc dùng binary search) cho đến khi kết quả chuyển từ true → false. Giá trị `N` cuối cùng còn true chính là độ dài thật của chuỗi.

**Cách tăng tốc bằng Burp Intruder (Sniper attack):**
- Đánh dấu vị trí số `N` làm payload position.
- Payload type: **Numbers**, sequential, from `1` to `50`, step `1` (chọn 50 vì chắc chắn độ dài không vượt quá).
- Dùng bộ lọc / Grep-Match tìm chuỗi `Welcome back` trong kết quả → tìm ranh giới true→false.

### 3.6. Kỹ thuật dò từng ký tự bằng `SUBSTRING()`

```sql
(SELECT SUBSTRING(password, i, 1) FROM users WHERE username = 'administrator') = 'c'
```
- `SUBSTRING(password, i, 1)`: lấy ra đúng 1 ký tự ở vị trí `i` của chuỗi password.
- So sánh với từng ký tự thử `'a'`, `'b'`, `'c'`... cho đến khi true.

**Vì phải thử ~36 ký tự (a-z, 0-9) × số vị trí trong password → cần tự động hóa bằng Burp Intruder**, dùng kiểu tấn công **Cluster bomb** với **2 payload position** cùng lúc:
- Payload 1 (vị trí `i` trong `SUBSTRING`): kiểu **Numbers**, sequential, `1` → độ dài password đã xác định (ví dụ 20), step 1.
- Payload 2 (ký tự thử `'x'`): kiểu **Brute forcer**, character set gồm `a-z0-9`, min length = 1, max length = 1.

→ Cluster bomb sẽ chạy **tất cả tổ hợp** giữa 2 payload (số vị trí × số ký tự) — với ví dụ 20 vị trí × 36 ký tự = **720 request**, tự động dò ra toàn bộ password chỉ trong 1 lần tấn công, thay vì phải chạy tay 20 lần Sniper riêng lẻ.

### 3.7. Đọc kết quả

Dùng bộ lọc/Grep-Match tìm `Welcome back` trong bảng kết quả Intruder — mỗi dòng có tick chính là 1 cặp (vị trí ký tự, giá trị ký tự) đúng. Sắp xếp lại theo thứ tự vị trí → ghép thành password hoàn chỉnh.

### 3.8. Sai lầm cần tránh: đừng brute-force nguyên cụm mật khẩu qua form login

Một cách "khai thác" sai lầm phổ biến: thử so sánh `password = 'giá_trị_đoán_bừa'` trực tiếp trong subquery — về bản chất **tương đương với việc brute-force password qua chính form đăng nhập**, không tận dụng được lợi thế mà lỗ hổng SQLi mang lại (đọc từng ký tự độc lập, không phụ thuộc độ phức tạp của password). Kỹ thuật đúng là chia nhỏ bài toán thành "dò từng ký tự" như mục 3.6 — số lượng request cần thiết giảm từ *(số ký tự)^(độ dài)* xuống còn *(số ký tự) × (độ dài)*.

---

## 4. Cách phòng chống

### 4.1. Biện pháp chính — Parameterized Queries (Prepared Statements)

Đây là biện pháp phòng chống **triệt để nhất và bắt buộc** đối với mọi loại SQL Injection, kể cả Blind SQLi. Thay vì nối chuỗi:

```php
// ❌ SAI — dễ bị SQLi
$query = "SELECT trackingId FROM tracking_table WHERE trackingId = '" . $trackingId . "'";
```

Dùng tham số hóa để database driver tự tách biệt code và data:

```php
// ✅ ĐÚNG — parameterized query
$stmt = $pdo->prepare("SELECT trackingId FROM tracking_table WHERE trackingId = ?");
$stmt->execute([$trackingId]);
```

**Vì sao hiệu quả?** Với prepared statement, giá trị `$trackingId` — dù chứa `'`, `AND`, `OR`, hay bất kỳ cú pháp SQL nào — **luôn được driver xử lý như 1 chuỗi dữ liệu thuần túy**, không bao giờ được diễn giải lại thành cú pháp SQL. Kẻ tấn công không còn cách nào "thoát" ra khỏi giá trị chuỗi để chèn logic mới.

### 4.2. Biện pháp bổ sung (defense in depth — không thay thế được mục 4.1)

| Biện pháp | Mô tả |
|---|---|
| **Input validation / whitelist** | Vì `TrackingId` về bản chất chỉ nên là 1 chuỗi định danh (UUID/hex), backend nên validate format nghiêm ngặt (regex, độ dài cố định) và từ chối mọi input không khớp — chặn được cuộc tấn công *trước khi* chạm tới tầng database. |
| **Least privilege cho tài khoản DB** | Tài khoản kết nối DB của ứng dụng chỉ nên có quyền `SELECT` trên đúng những bảng cần thiết — hạn chế thiệt hại nếu SQLi vẫn xảy ra (không thể `DROP`, `UPDATE`, đọc bảng khác...). |
| **ORM (Object-Relational Mapping)** | Các ORM phổ biến (Eloquent, SQLAlchemy, Hibernate...) mặc định dùng parameterized query phía dưới — giảm rủi ro lập trình viên vô tình tự nối chuỗi SQL thủ công. |
| **WAF (Web Application Firewall)** | Có thể phát hiện và chặn các payload SQLi phổ biến ở tầng mạng — chỉ nên coi là lớp phòng thủ **bổ sung**, không thay thế việc sửa code, vì WAF có thể bị bypass bằng payload biến thể. |
| **Không hiển thị thông báo lỗi chi tiết** | Ẩn stack trace / thông báo lỗi SQL chi tiết ra ngoài production — dù không ngăn được Blind SQLi (vì loại này vốn không dựa vào lỗi), nhưng ngăn được Error-based SQLi. |
| **Rà soát cả header/cookie, không chỉrequest body/query param** | Như lab này minh chứng — SQLi có thể ẩn ở bất kỳ input nào backend đưa vào truy vấn, kể cả cookie. Quy trình test bảo mật (và cả code review) cần rà soát toàn bộ các nguồn input, không chỉ tham số hiển thị rõ trên form. |

---

## 5. Hướng dẫn thực hành từng bước chi tiết (Burp Suite)

### Bước 0 — Chuẩn bị môi trường
1. Bật **Proxy Intercept**, đảm bảo **Scope** đã set đúng domain của lab (`*.web-security-academy.net`).
2. Cấu hình FoxyProxy trỏ trình duyệt qua Burp.
3. Mở trang chủ shop của lab.

### Bước 1 — Quan sát cookie `TrackingId`
Mở tiện ích xem cookie (hoặc xem trực tiếp trong Burp) — bạn sẽ thấy 2 cookie:
- `session` — cookie phiên đăng nhập (không phải mục tiêu).
- `TrackingId` — cookie theo dõi, **đây là tham số nghi ngờ bị lỗi** (theo đề bài).

> Nếu không được đề bài mách trước, đây là lúc bạn phải **fuzzing từng tham số** (kể cả header/cookie) và quan sát phản hồi khác biệt để tự phát hiện ra tham số nào đáng nghi.

**Quan sát hành vi gốc:** Truy cập trang lần đầu với 1 `TrackingId` mới → **chưa** thấy `Welcome back` (vì đây là lần đầu tiên dùng ID này, DB chưa có record). Truy cập sang trang khác (cùng `TrackingId`) → **lần này thấy `Welcome back`** (vì ID đã tồn tại trong DB từ lần truy cập trước). Đây chính là hành vi "true → hiện thông báo" mà bạn sẽ khai thác.

**Việc cần làm:** Bắt 1 request bất kỳ có cookie `TrackingId`, gửi sang **Repeater**, tắt Intercept.

### Bước 2 — Xác nhận tham số dễ bị SQL Injection

**Hình dung câu truy vấn phía server (giả định hợp lý):**
```sql
SELECT trackingId FROM tracking_table WHERE trackingId = '<giá_trị_TrackingId>'
```

**2.1. Test case ĐÚNG (true) — chèn `' OR 1=1-- -` (dùng `)` + comment để giữ nguyên cú pháp hợp lệ):**

Sửa giá trị cookie thành (ví dụ TrackingId gốc là `borm7vxpAaYhQkvy`):
```
TrackingId=borm7vxpAaYhQkvy' AND 1=1-- -
```
Bấm **Ctrl+U** (URL-encode) trên phần payload vừa gõ, rồi **Send**.

✅ **Kết quả mong đợi:** Có `Welcome back` (vì `TrackingId = 'borm7vxpAaYhQkvy'` đúng, và `1=1` luôn đúng → `AND` của 2 vế đúng = đúng → có dòng trả về).

**2.2. Test case SAI (false) — đổi `1=1` thành `1=0`:**
```
TrackingId=borm7vxpAaYhQkvy' AND 1=0-- -
```
Ctrl+U → Send.

✅ **Kết quả mong đợi:** **Không** có `Welcome back` (vì `1=0` luôn sai → toàn bộ điều kiện sai → không có dòng trả về).

➡️ **Kết luận:** Ứng dụng phản hồi khác nhau tùy theo giá trị đúng/sai bạn chèn vào → **xác nhận lỗ hổng Blind SQL Injection tồn tại**, và bạn hoàn toàn kiểm soát được kết quả true/false thông qua cookie.

> 💡 **Lưu ý cú pháp quan trọng:** Nhớ bấm **Ctrl+U đúng 1 lần** trên payload thuần (chưa encode) để tránh double-encode — vấn đề bạn đã từng gặp ở các lab trước.

### Bước 3 — Xác nhận bảng `users` tồn tại

Thay vì `1=1`, dùng subquery kiểm tra sự tồn tại của bảng:
```
TrackingId=borm7vxpAaYhQkvy' AND (SELECT 'x' FROM users LIMIT 1)='x
```
Ctrl+U → Send.

**Giải thích logic:** Nếu bảng `users` tồn tại và có ≥1 dòng, subquery `(SELECT 'x' FROM users LIMIT 1)` trả về chuỗi `'x'` cho **mỗi dòng thỏa mãn**, nhưng nhờ `LIMIT 1` nên chỉ lấy đúng 1 giá trị `'x'` → so sánh `'x'='x'` → true → `TrackingId='borm7vxpAaYhQkvy'` (true) AND true = true → có dòng → `Welcome back`.

✅ **Kết quả mong đợi:** Có `Welcome back` → xác nhận bảng `users` tồn tại.

### Bước 4 — Xác nhận username `administrator` tồn tại

```
TrackingId=borm7vxpAaYhQkvy' AND (SELECT username FROM users WHERE username='administrator')='administrator
```
Ctrl+U → Send.

**Giải thích:** Nếu có dòng với `username = 'administrator'`, subquery trả về chính chuỗi `'administrator'` → so sánh với `'administrator'` → true → `Welcome back`.

✅ **Kết quả mong đợi:** Có `Welcome back`.

**Kiểm chứng ngược (sanity check):** Thử với 1 username chắc chắn không tồn tại (ví dụ `notarealuser`):
```
TrackingId=borm7vxpAaYhQkvy' AND (SELECT username FROM users WHERE username='notarealuser')='notarealuser
```
✅ **Kết quả mong đợi:** **Không** có `Welcome back` → củng cố thêm độ tin cậy của kỹ thuật.

### Bước 5 — Dò độ dài password bằng Burp Intruder (Sniper)

**5.1. Chuẩn bị payload cơ sở:**
```
TrackingId=borm7vxpAaYhQkvy' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password) > 1)='administrator
```
Gửi thử ở Repeater trước để xác nhận: ✅ có `Welcome back` (password chắc chắn dài hơn 1 ký tự).

**5.2. Gửi sang Intruder:**
1. Chuột phải trên request ở Repeater → **Send to Intruder**.
2. Tab **Positions** → **Clear §** hết các vị trí mặc định.
3. Bôi đen đúng số `1` trong `LENGTH(password) > 1` → bấm **Add §** để đánh dấu vị trí payload.
4. Attack type: **Sniper** (mặc định, vì chỉ có 1 vị trí).

**5.3. Cấu hình Payloads:**
- Payload type: **Numbers**
- Type: **Sequential**
- From: `1`, To: `50` (chọn số đủ lớn để chắc chắn bao trùm độ dài thật), Step: `1`

**5.4. Chạy tấn công:** Bấm **Start attack**.

**5.5. Đọc kết quả:**
- Cách 1 — quan sát cột **Length** (độ dài response): các dòng có `Welcome back` sẽ có độ dài response giống nhau (ví dụ ~11403 byte); dòng nào độ dài khác biệt hẳn là dấu hiệu không còn `Welcome back`.
- Cách 2 (khuyến nghị, cần bản Pro) — dùng **filter**: gõ `Welcome` vào ô filter kết quả → **Apply** → chỉ hiển thị các dòng có match.

✅ **Kết quả mong đợi:** Các giá trị `N` từ 1 đến 19 đều còn `Welcome back`; đến `N=20` thì **biến mất**.

➡️ **Kết luận: độ dài password chính xác = 20 ký tự.**

> 💡 **Tối ưu hơn:** Có thể áp dụng **tìm kiếm nhị phân (binary search)** — thử `N=50` (false) → thử `N=25` → chia đôi dần — giảm số request cần gửi. Video minh họa cách brute-force tuần tự để dễ hình dung, nhưng với password dài hơn, binary search sẽ hiệu quả hơn nhiều.

### Bước 6 — Dò từng ký tự password bằng Intruder (Cluster bomb, 2 payload position)

**6.1. Chuẩn bị payload cơ sở với `SUBSTRING()`:**
```
TrackingId=borm7vxpAaYhQkvy' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a
```
*(Test nhanh ở Repeater: không có `Welcome back` → xác nhận ký tự đầu tiên không phải `'a'` — đúng như video đã thử.)*

**6.2. Gửi sang Intruder, đánh dấu 2 vị trí payload:**
1. Send to Intruder → tab **Positions** → Clear hết.
2. Bôi đen số `1` (offset trong `SUBSTRING(password, 1, 1)`) → **Add §** → đây là **payload position 1**.
3. Bôi đen ký tự `a` cuối cùng (giá trị so sánh) → **Add §** → đây là **payload position 2**.
4. Attack type: đổi từ **Sniper** sang **Cluster bomb** (vì có 2 vị trí độc lập cần chạy hết mọi tổ hợp).

**6.3. Cấu hình payload cho vị trí 1 (offset ký tự):**
- Payload set: **1**
- Payload type: **Numbers**
- Sequential, From `1` → To `20` (đúng độ dài đã xác định ở Bước 5), Step `1`.

**6.4. Cấu hình payload cho vị trí 2 (ký tự thử):**
- Payload set: **2**
- Payload type: **Brute forcer**
- Character set: `abcdefghijklmnopqrstuvwxyz0123456789` (chỉ chữ thường + số, theo đúng hint đề bài)
- Min length: `1`, Max length: `1`

**6.5. Chạy tấn công:** Bấm **Start attack**.

> ⚠️ Với Cluster bomb, tổng số request = (số vị trí) × (số ký tự thử) = `20 × 36 = 720` request. Bản Community sẽ chạy chậm hơn đáng kể (video cảnh báo có thể mất hàng giờ) — nếu dùng Community, cân nhắc viết script Python tự động hóa thay thế (xem mục 5.6 bên dưới).

**6.6. Đọc kết quả:**
1. Dùng **filter** gõ `Welcome` → Apply, để chỉ hiển thị các dòng match.
2. Mỗi dòng match sẽ cho biết 1 cặp **(offset, ký tự)** đúng — ví dụ: offset=10 → ký tự `'a'`; offset=5 → ký tự `'b'`; offset=17 → ký tự `'b'`...
3. **Lưu ý:** Kết quả filter thường không tự sắp xếp đúng theo thứ tự số học của offset (vì Burp coi offset là chuỗi, không phải số) — bạn cần **tự sắp xếp lại thủ công** theo đúng offset 1→20 rồi ghép ký tự tương ứng để ra password hoàn chỉnh.

**6.7. Ghép password:**
Ghi lại từng cặp (offset, ký tự) theo đúng thứ tự offset tăng dần, ghép lại thành 1 chuỗi 20 ký tự → đó chính là password của `administrator`.

### Bước 7 — Đăng nhập bằng password vừa khai thác được
1. Trong trình duyệt, vào **My account**.
2. Username: `administrator`
3. Password: chuỗi 20 ký tự vừa ghép được.
4. Đăng nhập → nếu thành công, lab hiện thông báo hoàn thành (**"Congratulations, you solved it"**).

---

## 6. Tổng kết nhanh (cheat-sheet)

| Việc cần làm | Payload mẫu |
|---|---|
| Test điều kiện luôn đúng | `xyz' AND 1=1-- -` |
| Test điều kiện luôn sai | `xyz' AND 1=0-- -` |
| Xác nhận bảng tồn tại | `xyz' AND (SELECT 'x' FROM users LIMIT 1)='x` |
| Xác nhận user tồn tại | `xyz' AND (SELECT username FROM users WHERE username='administrator')='administrator` |
| Dò độ dài password | `xyz' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH(password)>N)='administrator` |
| Dò từng ký tự password | `xyz' AND (SELECT SUBSTRING(password,i,1) FROM users WHERE username='administrator')='c'` |
| Attack type cho dò độ dài | Sniper, 1 payload position (Numbers) |
| Attack type cho dò ký tự | **Cluster bomb**, 2 payload position (Numbers × Brute forcer) |

## 7. Bảng thuật ngữ

| Thuật ngữ | Ý nghĩa |
|---|---|
| Oracle / tín hiệu | Dấu hiệu duy nhất trong response giúp phân biệt true/false (ở đây: `Welcome back`) |
| Parameterized query | Kỹ thuật tách biệt code SQL và dữ liệu, ngăn SQLi triệt để |
| `LIMIT 1` | Ép subquery chỉ trả về đúng 1 giá trị, tránh lỗi khi có nhiều dòng thỏa điều kiện |
| Sniper attack | Kiểu tấn công Intruder chỉ có 1 payload position |
| Cluster bomb | Kiểu tấn công Intruder chạy hết mọi tổ hợp giữa ≥2 payload position |
| Grep-Match / Filter | Tính năng tự động quét response tìm 1 chuỗi cho trước để lọc kết quả |
| Binary search | Kỹ thuật chia đôi khoảng tìm kiếm để giảm số request cần thử |