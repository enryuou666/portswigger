# Lab 4 — SQL Injection UNION Attack, Finding a Column Containing Text

## Mục tiêu
Tiếp nối Lab 3 (đã xác định số cột), lab này yêu cầu xác định **cột nào trong số các cột đó chấp nhận kiểu dữ liệu text/string** — bằng cách thay lần lượt từng `NULL` bằng 1 chuỗi ký tự do lab cung cấp, cho tới khi giá trị đó xuất hiện trong response.

---

## 1. Vì sao cần bước này — vấn đề chưa giải quyết ở Lab 3

Lab 3 chỉ trả lời câu hỏi **"có bao nhiêu cột"**, dùng `NULL` cho mọi vị trí vì `NULL` tương thích với mọi kiểu dữ liệu. Nhưng để khai thác thực sự hữu ích sau này (đọc username, password, table_name — đều là dữ liệu **text**), cần biết chính xác **vị trí cột nào trong số N cột đó chấp nhận được kiểu text**, vì:

- Không phải cột nào trong câu SELECT gốc cũng cùng kiểu dữ liệu (VD cột `id` có thể là `int`, cột `price` có thể là `decimal`, chỉ cột `name`/`description` mới là `varchar`/`text`).
- Nếu đặt 1 chuỗi text vào đúng vị trí 1 cột kiểu số → DBMS sẽ báo lỗi convert kiểu (VD `ORA-01722: invalid number` ở Oracle, hoặc lỗi tương đương ở MySQL/MSSQL) → UNION thất bại ngay tại vị trí đó, dù số cột đã đúng.

→ Đây là bước "dò kiểu dữ liệu từng cột", nằm giữa bước dò số cột (Lab 3) và bước khai thác thật (đọc dữ liệu — Lab 5, 6...).

---

## 2. Kỹ thuật — thay `NULL` bằng chuỗi kiểm tra, dò từng vị trí

**Bước 1 — Xác nhận lại số cột (kế thừa từ Lab 3):**
```sql
' UNION SELECT NULL,NULL,NULL--
```
✅ Không lỗi → xác nhận đúng 3 cột (số cột của lab này, có thể khác lab khác).

**Bước 2 — Thay lần lượt từng vị trí `NULL` bằng 1 chuỗi ký tự bất kỳ để tìm vị trí chấp nhận text:**
```sql
' UNION SELECT 'a',NULL,NULL--
```
→ Nếu lỗi (convert kiểu thất bại) → cột 1 không phải text → thử tiếp cột 2:
```sql
' UNION SELECT NULL,'a',NULL--
```
→ Nếu vẫn lỗi → thử cột 3:
```sql
' UNION SELECT NULL,NULL,'a'--
```
→ Cột nào **không lỗi** chính là cột chấp nhận kiểu text.

**Bước 3 — Sau khi xác định đúng vị trí, thay `'a'` bằng đúng chuỗi random mà lab yêu cầu phải hiện ra:**
```sql
' UNION SELECT 'sCexOT',NULL,NULL--
```
(ví dụ vị trí cột 1 là cột text, và `sCexOT` là chuỗi ngẫu nhiên do lab cung cấp)

**Bước 4 — Kiểm tra response:** nếu chuỗi `sCexOT` xuất hiện đúng nguyên văn trong danh sách sản phẩm trả về → xác nhận đã dò đúng cột text → lab solved.

---

## 3. Vì sao lab yêu cầu chuỗi ngẫu nhiên do lab cấp, thay vì tự chọn `'a'`

Đây là thiết kế của PortSwigger để **buộc bạn phải thực sự chứng minh** injection đã thành công qua đúng cột đó, thay vì chỉ "đoán mò không lỗi là xong". Nếu chỉ cần không lỗi 500 là đủ, có thể vô tình đặt giá trị vào 1 cột không hiển thị ra UI (VD cột bị ẩn trong HTML) mà vẫn tưởng đã đúng. Yêu cầu **chuỗi cụ thể phải hiện ra trong response** đảm bảo bạn xác nhận đúng cả 2 điều kiện: (1) cột đó nhận kiểu text, và (2) cột đó **thực sự được hiển thị ra giao diện** — điều kiện bắt buộc để UNION attack có ý nghĩa thực tế (nếu cột nhận text nhưng không hiển thị ra UI, đọc được dữ liệu vào cột đó cũng vô dụng vì không nhìn thấy được).

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Thử hết cả N cột đều lỗi | Số cột xác định sai từ đầu (Lab 3 làm chưa đúng) | Quay lại xác nhận số cột bằng `ORDER BY`/`UNION SELECT NULL` trước khi dò kiểu |
| Không lỗi ở 1 cột, nhưng không thấy chuỗi random trong response | Cột đó nhận kiểu text nhưng không hiển thị ra UI (VD cột bị ẩn) | Thử tiếp các cột còn lại — có thể có nhiều cột nhận text nhưng chỉ 1 số cột hiển thị |
| Nhầm giữa lỗi cú pháp và lỗi convert kiểu | Không kiểm tra kỹ nội dung lỗi trả về | Đọc kỹ response — lỗi convert kiểu thường khác message so với lỗi cú pháp SQL (VD "invalid number" vs "syntax error") |
| Double-encode dấu nháy đơn quanh chuỗi | Bấm Ctrl+U 2 lần | Chỉ bấm đúng 1 lần trên payload plain text |

---

## 5. So sánh với các lab UNION đã làm trước — vị trí của lab này trong quy trình chung

| Giai đoạn | Lab tương ứng | Câu hỏi cần trả lời |
|---|---|---|
| 1. Xác định số cột | Lab 3 | "Có bao nhiêu cột?" |
| **2. Xác định cột chấp nhận text** | **Lab 4 (lab này)** | **"Cột nào trong số đó nhận được kiểu text và hiển thị ra UI?"** |
| 3. Khai thác thật (đọc dữ liệu khác bảng) | Lab 5, 6, 7, 8, 9, 10 | "Dữ liệu tôi cần nằm ở đâu, đưa vào đúng cột nào?" |

Ở các lab 7, 9, 10 đã note trước đó, bước này thường được **gộp chung** vào 1 payload xác nhận nhanh (VD `UNION SELECT 'abc','def' FROM dual--`) vì đề bài đã biết trước số cột đều là text — lab này tách riêng ra để luyện đúng kỹ năng dò kiểu dữ liệu khi **chưa biết trước** cột nào là text.

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị hiểu thành cú pháp `UNION SELECT` ở bất kỳ vị trí cột nào.

**Bổ sung:** Không có biện pháp chặn riêng hiệu quả ở tầng ứng dụng — việc 1 số cột nhận text còn cột khác không nhận là đặc tính tự nhiên của schema, không phải điểm có thể "vá" riêng lẻ; giải pháp vẫn quy về parameterization.

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao dò xong số cột (Lab 3) chưa đủ để bắt đầu khai thác thật — cần thêm thông tin gì nữa và tại sao?
2. Vì sao lab yêu cầu 1 chuỗi ngẫu nhiên cụ thể phải xuất hiện trong response, thay vì chỉ cần "không lỗi 500" để coi là thành công?
3. Nếu có nhiều hơn 1 cột chấp nhận kiểu text trong cùng 1 câu SELECT, chiến lược chọn cột nào để đặt dữ liệu cần đọc (VD password) nên dựa vào tiêu chí gì?
4. Vì sao lỗi convert kiểu dữ liệu (đặt text vào cột số) lại là 1 tín hiệu hữu ích để xác định kiểu dữ liệu, thay vì chỉ gây phiền toái cần tránh?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Bước 1: xác nhận lại số cột
' UNION SELECT NULL,NULL,NULL--

-- Bước 2: dò từng vị trí bằng chuỗi test
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--

-- Bước 3: thay 'a' bằng chuỗi random do lab cấp, đặt đúng vị trí cột text đã xác định
' UNION SELECT 'sCexOT',NULL,NULL--
```

**Kết quả:** Chuỗi random hiện ra trong response tại đúng cột đã xác định → lab solved.
