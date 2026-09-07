# Lab 3 — SQL Injection UNION Attack, Determining the Number of Columns Returned by the Query

## Mục tiêu
Khai thác lỗ hổng SQLi trong bộ lọc `category` để xác định **số cột chính xác** của câu SELECT gốc, bằng cách dùng `UNION SELECT NULL,NULL,...` cho tới khi không còn lỗi. Đây là **bước nền tảng đầu tiên**, dùng lại ở mọi lab UNION-based tiếp theo (7, 8, 9, 10 đã làm, và 4-6 sắp làm).

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab khác — `category` bị nối chuỗi trực tiếp vào câu SQL, không qua parameterized query.

**Vì sao cần xác định số cột trước tiên — ràng buộc cứng của UNION:**
Theo chuẩn SQL, `UNION` chỉ ghép được 2 câu SELECT nếu **số cột của cả 2 câu bằng nhau tuyệt đối** (không hơn không kém). Đây là yêu cầu ở tầng cú pháp SQL của mọi DBMS, không phải đặc thù riêng của lab hay ứng dụng web. Nếu chưa biết số cột thật của câu SELECT gốc (`SELECT * FROM products WHERE category = '...'`), mọi câu `UNION SELECT` tiếp theo (đọc bảng khác, đọc version...) đều sẽ thất bại ngay từ bước đầu — vì vậy đây luôn là bước bắt buộc đầu tiên trong mọi UNION attack.

---

## 2. Kỹ thuật dò cột — 2 cách, lab này dùng cách `UNION SELECT NULL`

### Cách 1 (dùng ở lab này): Tăng dần số `NULL` trong `UNION SELECT`

**Payload thử lần lượt:**
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```

**Vì sao dùng `NULL` thay vì 1 giá trị cụ thể (VD `'a'`):**
`NULL` tương thích với **mọi kiểu dữ liệu cột** (text, số, ngày tháng...) trong hầu hết DBMS — nên nếu UNION vẫn báo lỗi dù đã dùng `NULL`, chắc chắn nguyên nhân là **sai số cột**, chứ không thể là lỗi do sai kiểu dữ liệu (loại trừ được 1 biến số gây nhiễu). Nếu dùng `'a'` ngay từ đầu mà bị lỗi, sẽ không biết chắc là do sai số cột hay do cột đó không nhận kiểu text.

**Đọc kết quả:**
- Còn sai số cột → lỗi kiểu `The used SELECT statements have a different number of columns` (MySQL) hoặc tương đương tùy DBMS
- Đúng số cột → **không lỗi**, và quan trọng hơn: response phải xuất hiện **thêm 1 dòng mới chứa toàn giá trị null/rỗng** trong danh sách sản phẩm — đây là bằng chứng UNION đã thực sự chạy thành công, không chỉ là "không lỗi 500" (đôi khi không lỗi 500 nhưng dòng UNION không hiện ra do lỗi khác ở tầng hiển thị).

### Cách 2 (thay thế, đã dùng ở các lab trước — Lab 7, 9, 10): `ORDER BY`

```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--   -- lỗi tại đây → số cột thật = giá trị trước đó
```

**So sánh 2 cách:**
| | `UNION SELECT NULL,...` | `ORDER BY N` |
|---|---|---|
| Cách xác nhận | Tăng dần tới khi **hết lỗi** | Tăng dần tới khi **bắt đầu lỗi** |
| Số lần thử trung bình | Nhiều hơn nếu số cột lớn (phải thử đúng số NULL) | Ít hơn — chỉ cần binary search trên 1 số nguyên |
| Bằng chứng thành công | Phải quan sát thêm dòng dữ liệu mới trong response | Chỉ cần quan sát hết lỗi 500, không cần dòng mới hiện ra |
| Rủi ro nhầm lẫn | Thấp — nếu không lỗi mà cũng không thấy dòng mới, biết ngay có vấn đề khác | Cao hơn nếu ứng dụng suppress lỗi (không phân biệt được đâu là ranh giới) |

→ Cả 2 cách đều hợp lệ, `ORDER BY` thường nhanh hơn (đặc biệt hiệu quả khi kết hợp binary search cho bảng có nhiều cột), nhưng `UNION SELECT NULL` trực quan hơn cho người mới vì thấy ngay bằng chứng UNION hoạt động (dòng dữ liệu mới xuất hiện).

---

## 3. Quy trình khai thác (Burp Suite)

1. Bật Intercept, chọn 1 category → bắt request có tham số `category`.
2. Gửi sang Repeater.
3. Sửa `category` thành:
   ```
   ' UNION SELECT NULL--
   ```
   Ctrl+U (encode 1 lần) → Send.
4. Quan sát: nếu lỗi (VD 500, hoặc thông báo lỗi số cột) → tăng thêm 1 `NULL`:
   ```
   ' UNION SELECT NULL,NULL--
   ```
   Lặp lại tăng dần.
5. Khi hết lỗi **và** response chứa thêm 1 dòng sản phẩm mới với giá trị trống/null → xác nhận đã tìm đúng số cột.
6. Lab solved khi tìm ra đúng số cột này (không cần đọc thêm dữ liệu gì khác — đây chỉ là bài tập xác định số cột).

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Vẫn lỗi dù tăng số `NULL` khá nhiều | Đếm nhầm số dấu phẩy, thiếu/thừa 1 `NULL` so với dự định | Đếm lại chính xác số lượng `NULL` trong payload trước khi gửi |
| Không lỗi (200 OK) nhưng không thấy dòng mới trong response | Đúng số cột về mặt cú pháp, nhưng vị trí UI không hiển thị dòng có toàn giá trị NULL (VD ảnh sản phẩm bị thiếu khiến dòng đó bị ẩn) | Kiểm tra kỹ toàn bộ response (View response → Render/Raw), không chỉ nhìn lướt qua giao diện |
| Double-encode dấu phẩy hoặc khoảng trắng | Bấm Ctrl+U 2 lần | Chỉ bấm đúng 1 lần trên payload plain text |
| Nhầm lẫn giữa lỗi do sai số cột và lỗi do sai kiểu dữ liệu | Dùng giá trị cụ thể (`'a'`) thay vì `NULL` ngay từ bước dò cột | Luôn dùng `NULL` ở bước dò số cột, chỉ đổi sang giá trị cụ thể sau khi đã xác nhận đúng số cột |

---

## 5. Vì sao đây là bước nền tảng, không phải bài tập độc lập

Kết quả của lab này (số cột) **không có giá trị khai thác riêng lẻ** — nó là **điều kiện tiên quyết bắt buộc** cho mọi UNION attack tiếp theo (đọc version, liệt kê bảng, đọc dữ liệu credential). Đây chính là Giai đoạn 1 đã lặp lại xuyên suốt trong toàn bộ các lab UNION đã note trước đó (Lab 7, 9, 10) — lab này tách riêng kỹ năng đó ra để luyện tập độc lập trước khi ghép vào bài toán lớn hơn.

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** loại bỏ khả năng `category` bị hiểu thành cú pháp `UNION SELECT` — bất kể số cột bao nhiêu, input luôn được xử lý như 1 chuỗi dữ liệu thuần.

**Bổ sung:** Không có biện pháp "chặn riêng UNION" nào thực sự hiệu quả ở tầng ứng dụng (VD chặn từ khóa `UNION` dễ bị bypass qua encoding/case) — parameterization vẫn là giải pháp duy nhất triệt để.

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao `UNION` bắt buộc 2 câu SELECT phải có số cột bằng nhau — đây là giới hạn ở tầng nào (cú pháp SQL chuẩn, hay đặc thù riêng của từng DBMS)?
2. Vì sao dùng `NULL` ở bước dò cột lại loại trừ được khả năng nhầm lẫn giữa "sai số cột" và "sai kiểu dữ liệu"?
3. So với `ORDER BY N`, vì sao `UNION SELECT NULL,...` cần thêm bước "quan sát dòng dữ liệu mới xuất hiện" để xác nhận chắc chắn, thay vì chỉ dựa vào việc hết lỗi 500?
4. Nếu ứng dụng suppress toàn bộ lỗi SQL (luôn trả về 200 dù query lỗi), kỹ thuật `ORDER BY` để dò cột có còn dùng được không? Kỹ thuật `UNION SELECT NULL` có bị ảnh hưởng theo cách tương tự không?

---

## 8. Payload cuối cùng (cheat-sheet)

```sql
-- Tăng dần cho tới khi hết lỗi và thấy dòng mới trong response
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
-- ... tiếp tục tới khi tìm ra đúng số cột
```

**Kết quả:** Xác định đúng số cột của câu SELECT gốc → lab solved (không cần khai thác thêm gì khác ở lab này).
