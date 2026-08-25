# Tất Tần Tật Về SQL Injection Cho Người Mới

> Tổng hợp lại từ bài giảng "Tất Tần Tật Về SQL Injection Cho Người Mới – Không Cần Kiến Thức Chuyên Sâu" (khóa Web Penetration Testing for Beginner) + tham khảo thêm PortSwigger Web Security Academy (https://portswigger.net/web-security/sql-injection) để bạn đối chiếu khi làm lab.

---

## 1. SQL Injection là gì?

SQL Injection (SQLi) thuộc **nhóm lỗ hổng server-side**. Cái tên đã nói lên bản chất: input mà mình truyền vào sẽ là **một câu lệnh SQL** (hoặc một mảnh của câu lệnh SQL), giống hệt logic của các lỗ hổng khác:

| Lỗ hổng | Input truyền vào là gì |
|---|---|
| OS Command Injection | Một câu lệnh hệ điều hành |
| SSRF | Một URL |
| Path Traversal | Một đường dẫn file (tương đối/tuyệt đối) |
| **SQL Injection** | **Một câu lệnh SQL** |

SQL (Structured Query Language) là ngôn ngữ truy vấn có cấu trúc, dùng để **thao tác và truy vấn cơ sở dữ liệu**: lấy ra bản ghi, thêm, sửa, xóa. Cú pháp SQL sẽ khác nhau đôi chút tùy hệ quản trị CSDL (MySQL, PostgreSQL, Oracle, SQL Server, SQLite, MariaDB...) — giống như PHP, Java, Python đều có vòng lặp `for`, điều kiện `if`, nhưng cách viết khác nhau.

**Lưu ý quan trọng khi test:** Trong pentest, bạn luôn làm việc ở dạng **black-box** — không biết backend dùng ngôn ngữ gì, database gì. Việc xác định đúng loại database giúp viết câu truy vấn chính xác — vì SQL sai cú pháp (syntax) thì sẽ không chạy được.

### Tài nguyên luyện SQL cơ bản (nếu chưa quen viết SQL)
- Các trang học tương tác kiểu bài tập (ví dụ dạng sqlzoo, sqlbolt...)
- SQL online sandbox (mysql/sqlite/mariadb/postgres online) để tự viết, test rồi xóa mà không cần cài gì lên máy

---

## 2. Ôn nhanh cú pháp SQL cơ bản (bắt buộc phải nắm trước khi khai thác)

Muốn khai thác SQLi, bạn **bắt buộc** phải viết được câu truy vấn SQL tương đối — không cần giỏi như DBA, nhưng phải hiểu cú pháp cơ bản của 4 lệnh sau:

### 2.1. SELECT — lấy dữ liệu ra
```sql
SELECT * FROM users WHERE user_id = 1
```
- `SELECT *` : lấy hết toàn bộ cột trong bảng.
- Mỗi dòng dữ liệu = 1 record, mỗi cột chứa 1 loại thông tin.
- `WHERE` : điều kiện lọc — ví dụ chỉ lấy dòng có `user_id = 1`.

### 2.2. INSERT — thêm bản ghi
```sql
INSERT INTO users (username, password) VALUES ('ga', 'cooky')
```
- Sau `INTO` là tên bảng.
- Nếu không khai đủ số cột, bắt buộc phải liệt kê rõ cột nào tương ứng giá trị nào.
- **INSERT có thể chèn nhiều dòng cùng lúc**, mỗi cặp `(...)` là một dòng:
```sql
INSERT INTO users (username, password) VALUES ('ga', 'cooky'), ('ha', 'hoa')
```

### 2.3. UPDATE — sửa dữ liệu
```sql
UPDATE users SET password = 'cooky' WHERE username = 'ga'
```
> ⚠️ **Cực kỳ quan trọng:** Nếu **không có điều kiện `WHERE`**, `UPDATE` sẽ sửa **toàn bộ** các dòng trong bảng — tất cả user sẽ bị đổi chung 1 password.

### 2.4. DELETE — xóa dữ liệu
```sql
DELETE FROM users WHERE username = 'ga'
```
> ⚠️ Tương tự UPDATE — thiếu `WHERE` là xóa sạch cả bảng.

**Vì sao lưu ý 2 lệnh này quan trọng với pentest?** Vì khi test SQLi ở chức năng `UPDATE`/`DELETE`, nếu bạn chèn dấu comment (xóa mất điều kiện `WHERE`) thì có thể vô tình **update/xóa toàn bộ dữ liệu thật** của hệ thống. Đây là lý do cần cẩn trọng, hạn chế chạy scan tự động bừa bãi vào các chức năng update/delete.

---

## 3. Cơ chế lỗi SQL Injection xảy ra như thế nào?

### 3.1. Ví dụ minh họa: form login

Giao diện login truyền `username` + `password` lên server qua HTTP POST đến `/login`. Backend sẽ ghép giá trị người dùng nhập vào **thẳng vào trong** câu truy vấn SQL đã viết sẵn, kiểu:

```sql
SELECT * FROM users WHERE username = 'admin' AND password = 'cooky'
```

Nếu có 1 dòng thỏa cả 2 điều kiện → backend hiểu là "user tồn tại" → cho đăng nhập. Đây là logic check login cơ bản, áp dụng cho mọi ngôn ngữ, mọi database.

### 3.2. Vấn đề: lập trình viên quên xử lý (sanitize) input

Nếu backend **không lọc / không xử lý** ký tự đặc biệt trong input, người dùng có thể nhập tùy ý — kể cả các ký tự thuộc cú pháp SQL. Ví dụ nhập `admin'` (có dấu nháy đơn):

```sql
SELECT * FROM users WHERE username = 'admin'' AND password = '...'
```

Vì SQL dùng cặp dấu nháy đơn (`'...'`) hoặc nháy kép (`"..."`) để định nghĩa 1 chuỗi, dấu nháy đơn bạn truyền vào **bị thừa một dấu** so với cặp mà lập trình viên đã viết sẵn → gây ra lỗi **Syntax Error**.

➡️ **Khi thấy lỗi syntax xuất hiện chỉ vì bạn thêm 1 ký tự đặc biệt, đó chính là dấu hiệu lỗ hổng SQL Injection.**

### 3.3. Test case ký tự đặc biệt để phát hiện lỗi

| Input truyền vào | Kết quả thường gặp |
|---|---|
| `admin'` | Lỗi (nếu backend dùng nháy đơn để bọc chuỗi) |
| `admin"` | Không lỗi nếu backend chỉ dùng nháy đơn (vì nháy kép chỉ được coi là 1 ký tự bình thường nằm trong cặp nháy đơn) |
| `admin"` (backend dùng nháy kép để bọc) | Lỗi |
| Cả nháy đơn và nháy kép đều lỗi | Có thể input không cần bọc chuỗi (ví dụ tham số kiểu số nguyên, WHERE id = ...) |

**Nguyên tắc chung:** Đưa các payload/test case vào để cố tình sinh lỗi syntax. Khi lỗi xảy ra → xác nhận input đó có khả năng bị SQL Injection.

---

## 4. Hai cách "vô hiệu hóa" phần câu lệnh SQL viết sẵn phía sau

Sau khi xác định input có lỗi, bước tiếp theo (dành cho pentester, không chỉ dừng ở tester) là khai thác dữ liệu. Muốn vậy phải làm sao để câu lệnh mình chèn vào **chạy hợp lệ** — tức phải vô hiệu hóa phần code SQL mặc định phía sau input của mình. Có 2 cách:

### 4.1. Cách 1: Dùng dấu Comment (bình luận)

Cú pháp comment SQL phổ biến:
- `-- ` (2 dấu gạch ngang + **1 khoảng trắng bắt buộc** theo sau) → comment hết phần còn lại trên dòng
- `#` → tương tự (MySQL)
- `/* ... */` → comment cả một đoạn

⚠️ **Lưu ý cực kỳ quan trọng:** Sau `--` phải có **khoảng trắng** thì phần phía sau mới được hiểu là comment đúng cú pháp. Nếu viết sát liền `--admin` mà không có dấu cách, một số hệ thống sẽ báo lỗi syntax vì không nhận diện đây là comment.

**Vấn đề khi backend dùng hàm `TRIM()`:** Một số lập trình viên dùng lệnh trim để loại bỏ khoảng trắng ở đầu/cuối input (vì nghĩ input không có ý nghĩa). Nếu bạn viết `admin --` (có khoảng trắng cuối) thì khoảng trắng đó bị trim mất → dấu `--` sẽ dính liền vào phần phía sau và **không được hiểu là comment nữa** → lỗi vẫn xảy ra.

**Cách khắc chế TRIM:** Thêm 1 ký tự bất kỳ ngay sau dấu comment (trước khoảng trắng bị trim), ví dụ:
```
admin'-- -
```
Vì `TRIM()` chỉ cắt khoảng trắng ở 2 đầu chuỗi, không cắt ở giữa, nên khoảng trắng nằm **giữa** `--` và ký tự thêm vào sẽ không bị trim mất, và comment vẫn kích hoạt đúng.

**Ví dụ Bypass Login bằng comment:**
```
Username: admin'-- -
Password: (bất kỳ)
```
Câu truy vấn thực tế backend chạy sẽ là:
```sql
SELECT * FROM users WHERE username = 'admin'-- -' AND password = '...'
```
Phần `AND password = '...'` bị comment hết → chỉ còn kiểm tra `username = 'admin'` → **bypass được việc kiểm tra password**.

### 4.2. Trường hợp không biết chính xác username (dùng `OR 1=1`)

Nếu bạn không chắc trong DB có tồn tại tài khoản tên `admin` hay không, dùng toán tử luôn đúng:
```
Username: ' OR 1=1-- -
```
→ `1=1` luôn đúng, kết hợp `OR` với điều kiện phía trước (dù đúng hay sai) → luôn trả về **toàn bộ** các dòng trong bảng `users`. Đây chính là lý do bạn hay thấy payload kinh điển `' OR 1=1-- -` hoặc `' OR '1'='1`.

**Vấn đề mới phát sinh:** `OR 1=1` trả về *tất cả* user, chứ không chỉ 1 dòng. Vậy làm sao lấy đúng 1 tài khoản cụ thể (ví dụ chỉ muốn login vào tài khoản thứ 2 trong danh sách)?

➡️ Dùng **`LIMIT`** để phân trang kết quả:
```sql
LIMIT <điểm_bắt_đầu>, <số_dòng_lấy>
```
- `LIMIT 0,1` → lấy dòng đầu tiên
- `LIMIT 1,1` → lấy dòng thứ hai
- `LIMIT 2,1` → lấy dòng thứ ba

Payload ví dụ: `' OR 1=1 LIMIT 1,1-- -` → chỉ trả về đúng 1 dòng (dòng thứ 2), tránh trả về quá nhiều data gây lỗi ở backend.

### 4.3. Cách 2: Viết tiếp câu truy vấn (không dùng comment)

Không phải lúc nào comment cũng phù hợp — thực tế có nhiều tình huống bạn **không thể comment hết phần sau** (ví dụ vì cần giữ nguyên cấu trúc INSERT nhiều cột — xem phần 6). Khi đó, thay vì cắt bỏ, bạn **"hoàn thiện" cú pháp** bằng cách chủ động thêm dấu đóng (nháy đơn/kép, ngoặc...) cho khớp với phần code có sẵn phía sau, rồi viết tiếp câu lệnh của mình một cách hợp lệ về mặt cú pháp.

Đây là kỹ thuật khó hơn, đòi hỏi bạn phải "đoán" đúng cấu trúc câu SQL mà lập trình viên viết — càng luyện viết SQL nhiều, càng dễ đoán ra các biến thể test case (đây chính là lý do các công cụ như sqlmap, hay các payload trong Burp Intruder có hàng trăm biến thể khác nhau: `'`, `"`, `')`, `")`, `']`... vì không ai biết chắc backend viết kiểu gì).

---

## 5. Quy trình 4 bước tìm lỗ hổng SQL Injection (thủ công)

1. **Bước 1 — Nhập giá trị bình thường trước.** Đảm bảo chức năng đang hoạt động đúng (ví dụ ID = 1 thì cứ nhập 1). Ghi lại các "dấu hiệu chuẩn" để so sánh: HTTP status code, độ dài response (Content-Length), nội dung trả về... — giống ý tưởng "request gốc" khi dùng Burp Intruder.
2. **Bước 2 — Đưa giá trị bất thường vào để kích lỗi.** Thử `'`, `"`, hoặc không dùng gì cả, để xác định backend dùng nháy đơn hay nháy kép để bọc chuỗi (hoặc không bọc gì — tham số kiểu số). So sánh response với baseline ở bước 1.
3. **Bước 3 — Biến "bất thường" thành "bình thường".** Dùng comment (`-- `, `#`, `/*...*/`) hoặc kỹ thuật viết tiếp câu truy vấn để vô hiệu hóa phần syntax dư thừa, sao cho response trở lại giống baseline (không còn lỗi).
4. **Bước 4 — Viết câu truy vấn khai thác** vào **trước** phần comment (vì mọi thứ sau comment coi như bị xóa, viết ở đó vô nghĩa).

> Kinh nghiệm của pentester thể hiện rõ nhất ở **bước 2**: càng biết nhiều test case (biến thể ký tự đặc biệt: `'`, `"`, `')`, `")`, `']`, `"]`...) thì càng dễ tìm ra đúng cấu trúc backend đang dùng, vì kiểm thử ở chế độ black-box (không thấy source code).

---

## 6. Ba loại SQL Injection (theo cách khai thác)

| Loại | Tên gọi | Đặc điểm | Kỹ thuật con |
|---|---|---|---|
| **1. In-band** | Cổ điển, phổ biến & dễ khai thác nhất | Kết quả trả về **trực tiếp** trong response — nhiều dữ liệu | **Union-based**, **Error-based** |
| **2. Inferential (Blind)** | Loại "mù" | Response chỉ trả về **đúng/sai**, **có/không**, hoặc **nhanh/chậm** — không thấy data trực tiếp | **Boolean-based**, **Time-based** |
| **3. Out-of-band (OAST)** | Ngoài phạm vi | Lỗi xảy ra ở một hệ thống nội bộ khác (không phải hệ thống đang test trực tiếp) | Dùng kênh phụ (DNS/HTTP) để lấy dữ liệu |

Khóa học beginner này tập trung vào: **Union-based** và **Boolean-based / Time-based** (Blind). Error-based và Out-of-band sẽ học ở trình độ nâng cao.

**Vì sao SQLi được đánh giá là lỗ hổng cực kỳ nghiêm trọng?** Vì nó có thể vi phạm cả 3 yếu tố của tam giác CIA (Confidentiality - Integrity - Availability): đọc dữ liệu nhạy cảm, sửa/xóa dữ liệu (INSERT/UPDATE/DELETE), thậm chí đọc/ghi file hoặc DROP cả database, hoặc bypass xác thực để chiếm quyền truy cập.

---

## 7. Khai thác In-band bằng UNION (kỹ thuật chính trong bài)

`UNION` là lệnh SQL dùng để **gộp** (nối) kết quả của 2 câu SELECT lại với nhau. Ví dụ:
```sql
SELECT * FROM products
UNION
SELECT * FROM users
```
Kết quả trả về gồm cả 2 bảng — dữ liệu bảng `products` giữ nguyên, gộp thêm dữ liệu bảng `users` phía dưới.

### 7.1. Quy tắc bắt buộc khi dùng UNION

> **Số lượng cột ở vế trái phải bằng số lượng cột ở vế phải** — giống một cái cân, phải cân bằng.

Với một số hệ CSDL, còn yêu cầu khắt khe hơn: **kiểu dữ liệu của từng cột tương ứng cũng phải khớp** (cột 1 kiểu số phải khớp cột 1 kiểu số...). Tuy nhiên với các DB phổ biến (MySQL, PostgreSQL, MariaDB, SQL Server) thường không quá khắt khe về kiểu dữ liệu khi dùng `NULL`.

### 7.2. Bước 1: Xác định số lượng cột

**Cách 1 — dò dần bằng UNION SELECT NULL:**
```sql
' UNION SELECT NULL-- -
' UNION SELECT NULL,NULL-- -
' UNION SELECT NULL,NULL,NULL-- -
```
Tăng dần số `NULL` cho đến khi không còn báo lỗi → đó là số cột. **Nhược điểm:** tốn nhiều request nếu số cột lớn (15-20 cột).

**Cách 2 — dùng `ORDER BY` (nhanh hơn, áp dụng kỹ thuật tìm kiếm nhị phân - binary search):**
```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
...
```
`ORDER BY N` sắp xếp theo cột thứ N. Khi `N` vượt quá số cột thực tế → báo lỗi ("unknown column"). Thay vì tăng dần 1-1, hãy áp dụng chia đôi khoảng tìm kiếm:
- Thử `ORDER BY 50` → lỗi (giả sử) → số cột < 50
- Thử `ORDER BY 25` → lỗi → số cột < 25
- Thử `ORDER BY 15` → không lỗi → số cột ≥ 15
- Thử `ORDER BY 16` → lỗi → **kết luận: có đúng 15 cột**

→ Cách này tối ưu số lượng request phải gửi lên server (ít request hơn = ít "gây tiếng động"/ít khả năng bị phát hiện hơn khi pentest thật).

### 7.3. Bước 2: Xác định vị trí cột nào hiển thị ra ngoài (reflected)

Sau khi biết số cột, thay vì dùng `NULL`, điền số thứ tự vào từng vị trí để dễ nhận biết:
```sql
' UNION SELECT 1,2,3,4,5,...,15-- -
```
Quan sát response — con số nào xuất hiện trên trang (ví dụ vị trí tương ứng cột `name`, cột `price`...) chính là **cột đó được hiển thị (reflected) ra output**. Không phải cột nào cũng hiển thị — có cột lập trình viên không dùng để in ra trang, nên dù bạn có nhét data vào cột đó cũng "vô hình" với bạn.

**Kỹ thuật loại bỏ dữ liệu gốc gây nhiễu:** Nếu câu SELECT gốc trả về dữ liệu thật (ví dụ chi tiết sản phẩm ID=1) trước, dữ liệu UNION của bạn có thể bị đẩy xuống dưới hoặc bị che khuất. Thêm một điều kiện luôn **sai** vào câu truy vấn gốc để nó luôn trả về rỗng, buộc dữ liệu UNION của bạn nổi lên:
```sql
' AND 1=0 UNION SELECT 1,2,3,...,15-- -
```
hoặc dùng ID không tồn tại: `?id=-1' UNION SELECT ...`

Sau khi xác định được cột "hiển thị" (ví dụ cột số 2 và cột số 9), thử điền hàm để xác nhận:
```sql
' UNION SELECT 1,version(),3,4,5,6,7,8,database(),10,...-- -
```
`version()` cho biết phiên bản DB, `database()` cho biết tên database hiện tại đang dùng.

### 7.4. Bước 3: Liệt kê tên bảng, tên cột qua `information_schema`

Với MySQL ≥ 5, PostgreSQL, SQL Server, MariaDB — luôn có sẵn 1 database hệ thống tên **`information_schema`**, chứa metadata (thông tin mô tả) về toàn bộ bảng/cột của **tất cả** database trên server. (Với SQLite thì tương đương là bảng `sqlite_master`.)

**Bảng `information_schema.tables`:**
| Cột | Ý nghĩa |
|---|---|
| `table_name` | Tên bảng |
| `table_schema` | Tên database chứa bảng đó |

**Lấy tất cả tên bảng thuộc database hiện tại:**
```sql
SELECT table_name FROM information_schema.tables
WHERE table_schema = database()
```
(`database()` trả về tên database đang truy vấn — tránh phải tự gõ tên DB.)

**Bảng `information_schema.columns`:**
| Cột | Ý nghĩa |
|---|---|
| `column_name` | Tên cột |
| `table_name` | Tên bảng chứa cột đó |
| `table_schema` | Tên database |

**Lấy tất cả tên cột của một bảng cụ thể (ví dụ bảng `users`):**
```sql
SELECT column_name FROM information_schema.columns
WHERE table_schema = database() AND table_name = 'users'
```

> ⚠️ **Lưu ý quan trọng đã gặp trong lab của bạn:** cú pháp đúng là `FROM information_schema.columns` — viết `FROM information_schema.columns, columns` (viết trùng lặp, vô tình tạo phép JOIN 2 bảng) là **sai**, sẽ gây lỗi hoặc trả kết quả sai.

### 7.5. Bước 4: Gộp nhiều dòng kết quả thành 1 dòng bằng `GROUP_CONCAT()`

Vì mỗi lần UNION chỉ chèn ra 1 dòng dữ liệu vào các vị trí cột hiển thị, nếu có nhiều tên bảng/tên cột thì bạn phải `LIMIT` dò từng dòng — rất tốn thời gian. Cách nhanh hơn: dùng hàm gộp nhiều dòng thành 1 chuỗi (MySQL):
```sql
' UNION SELECT 1,GROUP_CONCAT(table_name),3,...
FROM information_schema.tables WHERE table_schema=database()-- -
```
→ Trả về tất cả tên bảng nối liền nhau trong 1 dòng duy nhất, tiết kiệm rất nhiều request so với `LIMIT` từng cái một.

### 7.6. Bước 5: Trích xuất dữ liệu thật (username/password)

Khi đã biết tên bảng (`users`) và tên cột (`username`, `password`), thay `FROM information_schema...` bằng bảng thật:
```sql
' UNION SELECT 1,username,3,4,5,6,7,8,password,10,...-- -
```
Nếu muốn gộp cả username:password vào 1 vị trí, có thể dùng `CONCAT()`:
```sql
' UNION SELECT 1,CONCAT(username,':',password),3,...-- -
```

### 7.7. Lưu ý về lỗi encoding khi query cross-schema

Đôi khi truy vấn đúng cú pháp 100% nhưng vẫn báo lỗi — nguyên nhân có thể do **encoding không khớp** giữa bảng hệ thống (`information_schema` thường là `utf8`) và database đang truy vấn (có thể đang ở collation khác, ví dụ `latin1`). Cách khắc phục: convert dữ liệu sang dạng **HEX** trước khi so sánh/hiển thị, sau đó dùng `UNHEX()` để đọc lại dạng chữ:
```sql
UNHEX(HEX(table_name))
```
Đây là mẹo hữu ích khi gặp lỗi lạ dù cú pháp đã đúng.

---

## 8. SQL Injection không chỉ nằm trong `SELECT`

Bài giảng nhấn mạnh: **input không nhất thiết phải là 1 câu SELECT hoàn chỉnh** — chỉ cần liên quan đến cú pháp SQL và làm cho câu truy vấn tổng thể **valid** (đúng cú pháp) là đủ để khai thác. Cụ thể video minh họa 2 trường hợp khác `SELECT`:

### 8.1. Lỗi trong câu lệnh `INSERT`

Ví dụ: 1 trang web log lại thông tin mỗi lượt truy cập (User-Agent, Referer, Cookie, IP...) vào database bằng câu `INSERT`. Đây là các vị trí "ẩn" hay bị bỏ sót khi test — không chỉ tham số trong URL/body, mà **cả header** (User-Agent, Referer, Cookie...) cũng có thể là input bị SQLi.

Khi lỗi nằm trong `INSERT`, để khai thác bạn cần:
1. Xác định lỗi nằm ở cột thứ mấy trong danh sách `VALUES (...)`.
2. Nếu dùng comment: phải **đóng dấu ngoặc `)`** cho đủ trước khi comment (vì `VALUES(...)` cần đóng ngoặc hợp lệ), rồi mới đặt `-- `.
3. Điền đủ số lượng cột còn thiếu bằng `NULL` cho các cột không quan tâm, và đặt giá trị mong muốn (ví dụ chuỗi bạn muốn chèn) vào đúng cột hiển thị ra ngoài (ví dụ cột IP).
4. Nếu không dùng comment: viết tiếp — thêm dấu đóng ngoặc, dấu phẩy, viết thêm 1 tuple `VALUES` mới đủ số cột, đóng ngoặc cuối cùng khớp với phần code có sẵn phía sau.

### 8.2. Mức độ nguy hiểm khác nhau giữa các loại lệnh

| Lệnh bị SQLi | Mức độ rủi ro khi lỡ tay dùng comment/OR 1=1 |
|---|---|
| `SELECT` | Thường chỉ lộ thông tin (đọc dữ liệu) |
| `INSERT` | Thường ít nghiêm trọng hơn (chỉ thêm dữ liệu rác) |
| `UPDATE` | **Nguy hiểm** — comment mất `WHERE` → đổi toàn bộ 1 cột (VD toàn bộ password) trong bảng |
| `DELETE` | **Rất nguy hiểm** — comment mất `WHERE` → xóa sạch toàn bộ bảng |

➡️ **Bài học thực tế cho pentest:** Khi test các chức năng liên quan `UPDATE`/`DELETE`, hạn chế chạy scan tự động (Burp Active Scan, sqlmap...) một cách bừa bãi — vì công cụ tự động không hiểu ngữ cảnh và có thể vô tình phá dữ liệu thật của khách hàng.

---

## 9. Công cụ hỗ trợ tìm payload (khi không đoán được cấu trúc)

Vì kiểm thử ở chế độ black-box, bạn không thể chắc chắn 100% backend viết theo cấu trúc nào. Đây là lý do các công cụ scan tự động (sqlmap, Burp Scanner/Intruder) thực chất là **tổng hợp sẵn hàng trăm payload/test case biến thể** (ví dụ: `'`, `"`, `')`, `")`, `']`, `"]`, `' OR '1'='1`, `admin'-- -`...) để thử lần lượt — tăng khả năng bắt trúng đúng cấu trúc backend đang dùng. Có thể tham khảo danh sách payload tổng hợp bằng cách search từ khóa "SQL injection payload" hoặc repo dạng "PayloadAllTheThings".

---

## 10. Cách test bằng Burp Suite (thủ công + tự động)

### 10.1. Test thủ công (theo đúng quy trình 4 bước ở mục 5)
1. Bắt request bằng Proxy Intercept → gửi sang **Repeater**.
2. Tại Repeater, thử lần lượt từng tham số một, đối chiếu với response gốc (status code, độ dài, nội dung).
3. Test không chỉ tham số GET/POST — thử cả **header** (Cookie, User-Agent, Referer...) nếu nghi ngờ backend có log/xử lý các giá trị này.

### 10.2. Test tự động bằng Burp Scanner
1. Chọn (bôi đen) đúng vị trí tham số nghi ngờ trong request.
2. Chuột phải → **Scan** (hoặc **Define insertion point** tùy phiên bản) → tương tự cách làm với các lỗ hổng khác.
3. Trong phần cấu hình scan (Scan configuration), tạo config mới (New) → đặt tên gợi nhớ (VD: "SQL Injection").
4. Ở phần chọn loại lỗ hổng để quét (Issues reported / equivalent), search từ khóa **"SQL"** và tick chọn tất cả mục liên quan đến SQL injection — để tránh Burp quét lan man sang các lỗ hổng khác.
5. Save → chạy scan → theo dõi kết quả trong Dashboard.

> ⚠️ Nhắc lại: khi scan tự động chạm vào các chức năng update/delete, rủi ro phá dữ liệu là có thật — cân nhắc kỹ trước khi bấm scan trên các trang không phải lab luyện tập.

---

## 11. Bảng tổng kết nhanh (cheat-sheet cá nhân)

| Việc cần làm | Ghi chú |
|---|---|
| Kiểm tra input dùng `'` hay `"` để bọc chuỗi | Test lần lượt từng dấu, so sánh response |
| Bypass login không biết username | `' OR 1=1-- -` |
| Bypass login biết chắc username là admin | `admin'-- -` |
| Dò xem có bao nhiêu cột | `ORDER BY N` (nhị phân) hoặc `UNION SELECT NULL,...` |
| Biết cột nào hiển thị ra ngoài | `UNION SELECT 1,2,3,...` rồi quan sát |
| Vô hiệu hóa data gốc để nổi rõ data UNION | Thêm `AND 1=0` hoặc dùng ID không tồn tại |
| Liệt kê tên bảng | `information_schema.tables WHERE table_schema=database()` |
| Liệt kê tên cột | `information_schema.columns WHERE table_schema=database() AND table_name='...'` |
| Gộp nhiều dòng kết quả về 1 dòng | `GROUP_CONCAT(...)` |
| Lỗi encoding dù cú pháp đúng | Bọc bằng `HEX()` / đọc lại bằng `UNHEX()` |
| Comment không ăn dù có khoảng trắng | Thêm ký tự đệm: `-- -` thay vì `--` |

---

## 12. Bài tập tự luyện (nhắc trong video, đối chiếu PortSwigger)

Video gợi ý luyện các dạng lab sau (đối chiếu tương đương trên PortSwigger Web Security Academy — mục **SQL injection**):
- Bypass login cơ bản → tương đương *"SQL injection vulnerability allowing login bypass"*
- SQLi trong mệnh đề `WHERE` (lấy dữ liệu) → *"SQL injection UNION attack, determining the number of columns returned by the query"* và các bài UNION tiếp theo
- SQLi có filter (ký tự bị chặn) → các bài *"...with filter bypass"*

Vì bạn đang học đúng path PortSwigger về UNION-based (enumerration qua `information_schema`), toàn bộ mục 7 ở trên chính là quy trình bạn đang áp dụng trong lab: xác định số cột → xác định cột hiển thị → liệt kê bảng → liệt kê cột → trích xuất dữ liệu admin.

---

## 13. Ghi chú riêng dựa trên các lỗi bạn đã từng gặp khi làm lab

- Cú pháp đúng: `FROM information_schema.columns` — **không** viết `FROM information_schema.columns, columns` (tạo nhầm phép JOIN).
- Trong Repeater: response ở Repeater **không tự động quay lại trình duyệt** — request gốc bị intercept vẫn phải bấm **Forward** riêng nếu muốn trình duyệt tiếp tục.
- Khi encode payload thủ công trong Burp: bấm **Ctrl+U đúng 1 lần** trên text thuần, tránh double-encode.
- Scope nên set là `web-security-academy.net` (bật subdomains) vì mỗi lab chạy trên 1 subdomain ngẫu nhiên khác nhau.
