# Lab 5 — SQL Injection UNION Attack, Retrieving Data From Other Tables

## Mục tiêu
Kết hợp toàn bộ kỹ thuật đã luyện ở Lab 3 (dò số cột) và Lab 4 (dò cột text) để thực hiện **UNION attack thật sự đầu tiên trong chuỗi này** — đọc dữ liệu từ bảng `users` (đã biết trước tên bảng và tên cột), lấy username/password của `administrator`, đăng nhập thành công.

---

## 1. Vị trí của lab này trong chuỗi kỹ năng UNION

Đây là lab đầu tiên **ghép lại toàn bộ 3 giai đoạn** thành 1 cuộc tấn công hoàn chỉnh, khác với Lab 3/4 (chỉ luyện từng kỹ năng riêng lẻ):

| Giai đoạn | Câu hỏi | Lab luyện tập trước đó |
|---|---|---|
| 1. Số cột | Có bao nhiêu cột? | Lab 3 |
| 2. Cột nào nhận text | Đặt dữ liệu đọc được vào cột nào? | Lab 4 |
| 3. Đọc dữ liệu thật | Tên bảng/cột đã biết trước — SELECT trực tiếp | **Lab 5 (lab này)** |

**Điểm khác biệt so với Lab 9 (đã note trước đó):** Ở Lab 9, tên bảng (`users_ssypfc`) và tên cột (`username_hcyhfy`, `password_dmgnxd`) đều có hậu tố ngẫu nhiên, phải tự dò qua `information_schema`. Ở lab này, đề bài **cho biết trước** tên bảng (`users`) và tên cột (`username`, `password`) — nên có thể bỏ qua bước dò schema, SELECT thẳng vào bước cuối. Đây là phiên bản "đơn giản hóa" giúp tập trung luyện đúng kỹ thuật UNION cốt lõi, chưa cần kết hợp thêm bước enumerate schema.

---

## 2. Quy trình khai thác (3 bước, đúng theo solution)

### Bước 1 — Xác định số cột và kiểu dữ liệu (kế thừa Lab 3 + Lab 4, gộp thành 1 payload)

```sql
' UNION SELECT 'abc','def'--
```

**Giải thích:** Vì đề bài đã gợi ý bảng `users` chỉ có 2 cột (`username`, `password`) cần lấy, nên có thể **giả định trước** số cột của câu SELECT gốc cũng là 2 và thử luôn — nếu đúng, tiết kiệm được các bước thử tăng dần từng `NULL` như Lab 3. Nếu payload này lỗi, mới cần quay lại quy trình đầy đủ (`ORDER BY` hoặc `UNION SELECT NULL,...` tăng dần).

✅ Không lỗi → xác nhận: 2 cột, cả 2 đều nhận kiểu text.

### Bước 2 — SELECT trực tiếp từ bảng `users` (bỏ qua bước dò schema vì đã biết tên)

```sql
' UNION SELECT username, password FROM users--
```

**Giải thích:**
- Vì `username` và `password` đều là kiểu text (giống `'abc'`, `'def'` đã test ở Bước 1), UNION hợp lệ về kiểu dữ liệu.
- Không cần `NULL` ở vị trí nào — cả 2 vị trí cột đều dùng để lấy dữ liệu thật, khác Lab 7/8 (chỉ cần đọc 1 giá trị version, cột còn lại phải để `NULL`).

### Bước 3 — Tìm dòng `administrator` và đăng nhập

Response trả về sẽ hiển thị **toàn bộ danh sách username/password** (lẫn trong phần liệt kê sản phẩm). Tìm dòng có `username = administrator`, lấy password tương ứng, vào trang login, đăng nhập bằng cặp thông tin đó.

→ Lab chuyển "Not solved" → **"Solved"**.

---

## 3. Vì sao lab này không cần `NULL` ở cột nào, khác hẳn Lab 7/8/9

| Lab | Số cột cần đọc dữ liệu thật | Số cột phải để `NULL` |
|---|---|---|
| Lab 7/8 (đọc version) | 1 (`BANNER`/`@@version`) | 1 (cột thừa) |
| Lab 9 (đọc credential, tên cột ngẫu nhiên) | 2 (`username_xxx`, `password_xxx`) | 0 |
| **Lab 5 (lab này)** | **2 (`username`, `password`)** | **0** |

→ Quy tắc chung: `NULL` chỉ cần dùng cho **cột nào không có dữ liệu thật để lấy** ở vị trí đó (để giữ đúng số cột theo yêu cầu UNION). Nếu số cột thật của câu SELECT gốc trùng khớp với đúng số trường dữ liệu cần đọc, không cần `NULL` ở đâu cả.

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Lỗi "different number of columns" | Câu SELECT gốc thực chất có nhiều hơn 2 cột (giả định sai) | Quay lại quy trình dò đầy đủ bằng `ORDER BY`/`UNION SELECT NULL,...` |
| Không tìm thấy bảng `users` | Gõ sai tên bảng/cột (case-sensitive tùy DBMS, VD PostgreSQL phân biệt hoa thường nếu có dấu ngoặc kép) | Kiểm tra lại chính xác tên đề bài cung cấp, thử thêm biến thể viết hoa/thường nếu DBMS nhạy cảm |
| Thấy dữ liệu nhưng không rõ dòng nào là `administrator` | Danh sách user dài, dễ nhìn nhầm | Dùng Ctrl+F trên response để tìm chính xác chuỗi `administrator` |
| Double-encode | Bấm Ctrl+U 2 lần | Chỉ bấm đúng 1 lần trên payload plain text |

---

## 5. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị hiểu thành `UNION SELECT username, password FROM users` — input luôn được xử lý như chuỗi dữ liệu thuần túy.

**Bổ sung (defense in depth):**
- **Hash password** (bcrypt/argon2) — dù bị UNION đọc được cột `password`, giá trị leak ra vẫn là hash, không phải plaintext, cần thêm bước crack mới dùng được.
- Least privilege cho DB account: nếu tài khoản DB của ứng dụng chỉ có quyền `SELECT` trên đúng bảng `products`, sẽ không thể UNION sang bảng `users` dù injection vẫn tồn tại — đây là ví dụ rõ ràng cho việc defense-in-depth giảm thiểu impact ngay cả khi lỗ hổng gốc chưa được vá.

---

## 6. Câu hỏi tự kiểm tra

1. Vì sao ở lab này không cần dùng `NULL` cho cột nào, trong khi Lab 7/8 bắt buộc phải có 1 cột `NULL`?
2. Nếu bảng `users` thực tế có 3 cột (`id`, `username`, `password`) nhưng câu SELECT gốc chỉ có 2 cột, làm sao đưa cả 3 giá trị vào response chỉ với 2 vị trí cột khả dụng?
3. Vì sao việc biết trước tên bảng/cột (như lab này) lại là tình huống "lý tưởng hóa" so với thực tế pentest — trong thực chiến, bước nào ở Lab 9 sẽ luôn cần thiết mà lab này bỏ qua?
4. Vì sao giới hạn quyền `SELECT` của DB account xuống đúng 1 bảng lại được xem là biện pháp defense-in-depth hiệu quả cho riêng dạng tấn công UNION, dù không vá được injection point?

---

## 7. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: xác nhận số cột + kiểu text
' UNION SELECT 'abc','def'--

-- Bước 2: đọc trực tiếp username/password
' UNION SELECT username, password FROM users--
```

**Kết quả:** Response hiển thị toàn bộ username/password → tìm dòng `administrator` → đăng nhập → lab solved.
