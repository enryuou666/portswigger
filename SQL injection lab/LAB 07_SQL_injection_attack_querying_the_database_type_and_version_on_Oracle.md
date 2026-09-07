# Lab 7 — SQL Injection Attack, Querying the Database Type and Version on Oracle

## Mục tiêu
Khai thác lỗ hổng SQLi trong bộ lọc `category` bằng kỹ thuật **UNION attack** để đọc trực tiếp chuỗi version của database (Oracle).

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab khác — tham số `category` bị nối chuỗi trực tiếp vào câu SQL backend, không qua parameterized query, cho phép thoát khỏi ngữ cảnh string literal và chèn thêm cú pháp SQL mới.

**Kỹ thuật dùng ở lab này — UNION attack:** Khác Lab 1/2 (sửa logic điều kiện `WHERE` của **cùng 1 câu SELECT gốc**), UNION attack **ghép thêm 1 câu SELECT hoàn toàn mới** vào kết quả trả về, cho phép đọc dữ liệu **không liên quan gì tới bảng gốc** (ở đây là bảng hệ thống chứa thông tin version, không phải bảng `products`).

**Điều kiện bắt buộc để UNION hoạt động:**
1. Số cột của câu SELECT chèn thêm phải **khớp chính xác** số cột của câu SELECT gốc
2. Kiểu dữ liệu ở từng vị trí cột phải **tương thích** giữa 2 câu SELECT (ít nhất không gây lỗi convert)
3. Kết quả UNION phải **được hiển thị ra response** (đây là điều kiện để UNION-based là in-band, phân biệt với blind)

---

## 2. Quy trình khai thác (đúng theo 2 bước solution — dò cột trước, đọc version sau)

### Bước 1 — Xác định số cột và kiểu dữ liệu (kế thừa kỹ thuật từ lab UNION cơ bản)

**Payload dò số cột bằng `ORDER BY`:**
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- nếu lỗi tại đây → số cột thật = 2
```
Tăng dần cho tới khi gặp lỗi — số cuối cùng còn chạy được chính là số cột thật.

**Payload xác nhận kiểu dữ liệu (cả 2 cột đều là text) — đây là payload solution đưa ra ở bước 2:**
```sql
' UNION SELECT 'abc','def' FROM dual--
```

**Giải thích vì sao phải có `FROM dual` (điểm đặc thù Oracle, nhắc lại từ hint đề bài):**
- Oracle **bắt buộc mọi câu `SELECT` phải có mệnh đề `FROM`**, kể cả khi không cần lấy dữ liệu từ bảng thật nào — khác MySQL/PostgreSQL (không cần `FROM` nếu không truy vấn bảng).
- `dual` là bảng ảo có sẵn trong Oracle, chỉ có 1 dòng 1 cột, tồn tại **chỉ để phục vụ mục đích này** — chạy các câu SELECT không cần bảng thật (VD `SELECT 'abc' FROM dual` trả về đúng 1 dòng chứa `'abc'`).
- Nếu quên `FROM dual` trên Oracle → lỗi cú pháp ngay lập tức, dù logic UNION và số cột đều đúng.

**Kết quả mong đợi:** Payload chạy không lỗi (không 500) → xác nhận: đây là Oracle DB, và cả 2 cột đều chấp nhận kiểu text.

### Bước 2 — Đọc version string qua bảng hệ thống `v$version`

**Payload:**
```sql
' UNION SELECT BANNER, NULL FROM v$version--
```

**Giải thích:**
- `v$version` là bảng hệ thống (dynamic performance view) đặc thù của Oracle, chứa thông tin version của database engine.
- Cột `BANNER` trong bảng này chứa chuỗi mô tả version đầy đủ (VD `Oracle Database 19c Enterprise Edition Release 19.0.0.0.0 - Production`).
- Cột thứ 2 để `NULL` — không cần dữ liệu gì thêm ở vị trí này, nhưng **vẫn phải giữ đúng 2 cột** để khớp với số cột đã xác định ở Bước 1 (nếu chỉ SELECT 1 cột, UNION sẽ báo lỗi "different number of columns").
- `NULL` được chọn thay vì 1 chuỗi rác vì `NULL` tương thích với **mọi kiểu dữ liệu** — an toàn tuyệt đối để "lấp chỗ trống" cho cột không cần dùng, tránh lỗi convert kiểu nếu cột đó ở câu SELECT gốc là kiểu số/ngày tháng.

**Kết quả:** Response hiển thị chuỗi version Oracle ngay trong danh sách sản phẩm (do UNION ghép trực tiếp vào kết quả gốc) → lab solved.

---

## 3. Các cách khác để lấy version trên Oracle (mở rộng, không nằm trong solution chính nhưng nên biết)

```sql
-- Cách 2: dùng hàm banner_full (nếu v$version bị hạn chế quyền)
' UNION SELECT banner, NULL FROM v$version--

-- Cách 3: một số phiên bản Oracle mới hơn dùng
' UNION SELECT version, NULL FROM product_component_version--
```
Ghi nhớ: khác với MySQL (`@@version`) hay PostgreSQL (`version()`), Oracle **không có hàm scalar đơn giản trả thẳng version** — buộc phải SELECT từ 1 bảng hệ thống như `v$version`.

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| `ORA-00923: FROM keyword not found where expected` | Thiếu `FROM dual` trong `UNION SELECT` không truy vấn bảng thật | Luôn thêm `FROM dual` sau mọi `UNION SELECT` trên Oracle nếu không có bảng thật |
| `ORA-01789: query block has incorrect number of result columns` | Số cột ở `UNION SELECT` không khớp số cột câu gốc | Đếm lại đúng số cột bằng `ORDER BY` ở Bước 1 trước khi viết UNION |
| Lỗi convert kiểu dữ liệu (VD `ORA-01722: invalid number`) | Cột `NULL` bị thay bằng 1 giá trị text/số không tương thích với kiểu cột gốc ở vị trí đó | Dùng `NULL` cho cột không cần dùng — tương thích mọi kiểu |
| Payload chạy nhưng version không hiện trên trang | Trang chỉ hiển thị 1 số cột nhất định trong UI (VD chỉ hiện cột đầu, không hiện cột 2) | Đặt giá trị cần đọc (`BANNER`) vào đúng vị trí cột được hiển thị ra UI, không phải cột bị ẩn |

---

## 5. So sánh nhanh: lấy version giữa các DBMS (bổ sung kiến thức nền)

| DBMS | Cách lấy version |
|---|---|
| **Oracle** | `SELECT BANNER FROM v$version` (bắt buộc `FROM`) |
| MySQL | `SELECT @@version` (không cần `FROM`) |
| PostgreSQL | `SELECT version()` (không cần `FROM`) |
| Microsoft SQL Server | `SELECT @@version` (không cần `FROM`) |

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** Loại bỏ khả năng input của `category` được parser SQL hiểu thành cú pháp `UNION SELECT` — input luôn được driver xử lý như 1 chuỗi dữ liệu thuần, không bao giờ ghép được thêm câu SELECT mới vào query.

**Bổ sung (defense in depth):**
- **Least privilege cho DB account của ứng dụng:** tài khoản kết nối DB không nên có quyền `SELECT` trên các bảng hệ thống như `v$version`, `all_tables`... — hạn chế khả năng leak thông tin fingerprint ngay cả khi injection vẫn tồn tại.
- Input validation: nếu `category` chỉ nên là 1 trong tập giá trị cố định (whitelist danh mục sản phẩm có sẵn), từ chối mọi input khác trước khi chạm tới tầng SQL.

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao Oracle bắt buộc `FROM dual` trong khi MySQL/PostgreSQL không cần `FROM` — sự khác biệt này phản ánh điều gì về thiết kế cú pháp SQL của từng DBMS?
2. Vì sao phải xác định đúng số cột **trước khi** viết payload UNION đọc version, thay vì đoán đại số cột rồi thử?
3. Vì sao dùng `NULL` cho cột không cần dùng lại an toàn hơn dùng 1 chuỗi text/số bất kỳ?
4. Nếu ứng dụng chỉ hiển thị đúng 1 cột đầu tiên ra UI (cột thứ 2 luôn bị ẩn dù query trả về), làm sao vẫn đọc được version — có cần đổi vị trí đặt `BANNER` không?
5. Vì sao việc leak được version string qua UNION lại được xem là bước "fingerprint" quan trọng cho toàn bộ quá trình khai thác các bước sau (VD chọn đúng cú pháp `all_tables` thay vì `information_schema`)?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: dò số cột
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- lỗi tại đây → 2 cột thật

-- Bước 2: xác nhận cả 2 cột là text (đồng thời xác nhận đây là Oracle)
' UNION SELECT 'abc','def' FROM dual--

-- Bước 3: đọc version string
' UNION SELECT BANNER, NULL FROM v$version--
```

**Kết quả:** Response hiển thị chuỗi version đầy đủ của Oracle Database → lab solved.
