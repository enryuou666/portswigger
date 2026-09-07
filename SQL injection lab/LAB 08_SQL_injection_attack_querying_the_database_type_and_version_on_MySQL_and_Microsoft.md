# Lab 8 — SQL Injection Attack, Querying the Database Type and Version on MySQL and Microsoft

## Mục tiêu
Khai thác lỗ hổng SQLi trong bộ lọc `category` bằng **UNION attack** để đọc chuỗi version của database — lần này trên **MySQL/MSSQL**, DBMS không bắt buộc `FROM` như Oracle ở Lab 7.

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab khác — `category` bị nối chuỗi trực tiếp vào SQL, không qua parameterized query.

**Kỹ thuật:** UNION attack — ghép thêm 1 câu SELECT mới vào kết quả trả về, đọc dữ liệu không thuộc bảng gốc (`products`).

**Điểm khác biệt cốt lõi so với Lab 7 (Oracle) — 2 chỗ đổi:**
| | Lab 7 (Oracle) | Lab 8 (MySQL/MSSQL) |
|---|---|---|
| Comment syntax | `--` (dấu gạch ngang đôi) | `#` (dấu thăng — chỉ MySQL hỗ trợ, MSSQL vẫn dùng `--`) |
| Mệnh đề `FROM` khi không cần bảng thật | Bắt buộc `FROM dual` | **Không cần `FROM`** — cả MySQL và MSSQL cho phép `SELECT <giá_trị>` trơn |
| Lấy version | `SELECT BANNER FROM v$version` (phải SELECT từ bảng hệ thống) | `SELECT @@version` (biến hệ thống, không cần bảng) |

→ Đây chính là bài học cốt lõi của lab này: **cùng 1 loại lỗ hổng (SQLi + UNION), nhưng cú pháp khai thác phải đổi hoàn toàn theo DBMS** — không có 1 payload "universal" dùng chung được cho mọi database.

---

## 2. Quy trình khai thác (2 bước theo solution)

### Bước 1 — Xác định số cột và kiểu dữ liệu

**Payload dò số cột bằng `ORDER BY` (giống mọi lab UNION khác, không đổi giữa các DBMS):**
```sql
' ORDER BY 1#
' ORDER BY 2#
' ORDER BY 3#   -- lỗi tại đây → số cột thật = 2
```

**Payload xác nhận cả 2 cột là text (payload solution đưa ra):**
```sql
' UNION SELECT 'abc','def'#
```

**Giải thích vì sao KHÔNG cần `FROM` ở đây, khác hẳn Lab 7:**
- MySQL và MSSQL đều cho phép `SELECT <literal>` mà không cần chỉ định bảng nguồn — vì các DBMS này coi 1 câu SELECT chỉ trả về giá trị hằng số là hợp lệ về mặt cú pháp, không bắt buộc phải "lấy dữ liệu từ đâu đó".
- Đây là điểm khác biệt thiết kế SQL giữa các DBMS đã ghi trong mind map tổng (NHÁNH 3 — fingerprint môi trường): việc 1 DBMS có bắt buộc `FROM` hay không là 1 trong các dấu hiệu để fingerprint loại DBMS đang gặp phải.

**Vì sao dùng `#` thay vì `--`:**
- `#` là comment syntax **đặc thù của MySQL** (không phải Oracle/PostgreSQL).
- MSSQL vẫn chấp nhận `--` như thường lệ; MySQL chấp nhận cả `--` (nhưng yêu cầu có dấu cách theo sau: `-- `) và `#` (không cần dấu cách) → dùng `#` cho MySQL để tránh rủi ro quên dấu cách sau `--`, an toàn và ngắn gọn hơn.
- Nếu chưa biết chắc là MySQL hay MSSQL, có thể thử `--` trước (an toàn cho MSSQL); nếu lỗi, thử `#` (chỉ MySQL nhận).

### Bước 2 — Đọc version string bằng biến hệ thống `@@version`

**Payload:**
```sql
' UNION SELECT @@version, NULL#
```

**Giải thích:**
- `@@version` là **biến hệ thống (system variable)** built-in, có sẵn trong cả MySQL và MSSQL, trả về ngay chuỗi version mà **không cần SELECT từ bảng nào** — khác hẳn Oracle phải SELECT từ bảng `v$version`.
- Cột thứ 2 vẫn để `NULL` — giữ đúng số cột đã xác định (2 cột), tương thích mọi kiểu dữ liệu, tránh lỗi convert.
- `#` ở cuối comment hết phần query gốc còn sót lại phía sau (điều kiện lọc theo category ban đầu).

**Kết quả:** Response hiển thị chuỗi version (VD MySQL: `8.0.31-0ubuntu0.20.04.1`; MSSQL: `Microsoft SQL Server 2019 (RTM)...`) ngay trong danh sách sản phẩm → lab solved.

---

## 3. Cách phân biệt MySQL vs MSSQL nếu chưa biết chắc DBMS nào

| Dấu hiệu | MySQL | MSSQL |
|---|---|---|
| Comment `#` | Chấp nhận | **Không** chấp nhận (`#` gây lỗi cú pháp) |
| Comment `--` | Chấp nhận (cần dấu cách sau) | Chấp nhận |
| Nối chuỗi | `CONCAT(a, b)` | `a + b` |
| Chuỗi version trả về | Thường có dạng `x.y.z-...` | Thường có dòng `Microsoft SQL Server <year>...` |
| Stacked queries (`;`) | Thường **không** cho phép qua driver mặc định | Thường **cho phép** |

→ Nếu payload dùng `#` chạy thành công → gần như chắc chắn là MySQL. Nếu `#` gây lỗi nhưng `--` vẫn chạy được → khả năng cao là MSSQL (cần xác nhận thêm qua nội dung chuỗi `@@version` trả về).

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Payload lỗi cú pháp khi dùng `#` | Đang thực chất là MSSQL, không phải MySQL — MSSQL không hỗ trợ `#` | Đổi sang `--` |
| `#` bị mất tác dụng sau khi URL-encode | Một số framework decode `%23` (`#`) thành fragment identifier ở tầng HTTP trước khi tới server, gây cắt mất phần payload | Kiểm tra tab Raw xem `#` có được gửi nguyên trong body/query đúng vị trí không; nếu bị cắt, thử `-- ` thay thế |
| Không thấy version dù payload chạy không lỗi | Cột 1 và cột 2 bị đảo ngược vị trí hiển thị trên UI so với dự đoán | Thử đổi `@@version, NULL` thành `NULL, @@version` |
| Double-encode dấu `#` | Bấm Ctrl+U 2 lần | Chỉ bấm đúng 1 lần trên payload plain text |

---

## 5. So sánh tổng hợp: lấy version giữa 4 DBMS phổ biến (cập nhật từ Lab 7)

| DBMS | Lấy version | Comment | Cần `FROM` khi UNION không truy vấn bảng? |
|---|---|---|---|
| **Oracle** | `SELECT BANNER FROM v$version` | `--` | **Có**, bắt buộc `FROM dual` |
| **MySQL** | `SELECT @@version` | `--·` (có dấu cách) hoặc `#` | Không |
| **MSSQL** | `SELECT @@version` | `--` | Không |
| PostgreSQL | `SELECT version()` | `--` | Không |

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị parser SQL hiểu thành cú pháp UNION mới, bất kể DBMS nào.

**Bổ sung (defense in depth):**
- Least privilege cho DB account: hạn chế quyền truy vấn các biến hệ thống nhạy cảm nếu ứng dụng không thực sự cần.
- Input validation/whitelist: nếu `category` chỉ nên nằm trong tập giá trị cố định, chặn mọi input khác trước khi chạm SQL.

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao cùng là lỗ hổng UNION-based SQLi, payload đọc version giữa Oracle và MySQL/MSSQL lại khác nhau hoàn toàn về cú pháp — sự khác biệt này nằm ở đâu trong thiết kế SQL của từng DBMS?
2. Vì sao MySQL hỗ trợ cả `--` và `#` làm comment, trong khi Oracle/PostgreSQL/MSSQL chỉ nhận `--`?
3. Nếu bạn không biết trước DBMS là gì, chiến lược thử payload nào (thứ tự thử `--` hay `#` trước) sẽ tối ưu số lần thử cần thiết để fingerprint đúng DBMS?
4. Vì sao việc DBMS có yêu cầu bắt buộc `FROM` khi SELECT hằng số hay không lại là 1 dấu hiệu fingerprint đáng tin cậy, thay vì chỉ dựa vào nội dung chuỗi version trả về?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: dò số cột
' ORDER BY 1#
' ORDER BY 2#
' ORDER BY 3#   -- lỗi tại đây → 2 cột thật

-- Bước 2: xác nhận cả 2 cột là text
' UNION SELECT 'abc','def'#

-- Bước 3: đọc version string
' UNION SELECT @@version, NULL#
```

**Lưu ý:** Nếu DBMS thực chất là MSSQL, thay `#` bằng `--` ở toàn bộ payload trên.

**Kết quả:** Response hiển thị chuỗi version đầy đủ của MySQL/MSSQL → lab solved.
