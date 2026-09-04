# Tổng kết Lab: Blind SQL Injection with Conditional Errors

## 1. Bản chất lỗ hổng đã khai thác

**Root cause:** Cookie `TrackingId` bị nối chuỗi trực tiếp vào câu SQL phía backend (dạng `WHERE trackingId = '<cookie>'`), không qua parameterized query. Input (cookie) — vốn đáng lẽ chỉ là 1 chuỗi định danh vô hại — bị DB parser hiểu nhầm thành cú pháp SQL.

**Điểm khác biệt cốt lõi so với Lab 11:** Ứng dụng **không phản hồi khác biệt gì** dù query trả về bao nhiêu dòng (không có tín hiệu tự nhiên như `Welcome back`). Bạn buộc phải **tự tạo ra tín hiệu** bằng cách ép DB throw lỗi có điều kiện.

## 2. Toàn bộ quy trình bạn đã thực hiện (5 giai đoạn)

| Giai đoạn                            | Việc làm                                                                        | Payload cốt lõi                                                                 | Kết quả                                                                 |
| ------------------------------------ | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| **0. Xây cơ chế tín hiệu**           | Dùng `CASE WHEN` + phép chia `1/0` để biến "đúng/sai" thành "chạy được/lỗi 500" | `AND (CASE WHEN (<đk>) THEN 1 ELSE 1/0 END) = 1`                                | Confirm: true→200/216 dòng, false→500/56 dòng                           |
| **1. Bảng `users` tồn tại?**         | Lồng subquery kiểm tra bảng vào `WHEN (...)`                                    | `(SELECT 'x' FROM users WHERE ROWNUM=1) = 'x'`                                  | 200 → bảng tồn tại                                                      |
| **2. User `administrator` tồn tại?** | Lồng subquery kiểm tra username                                                 | `(SELECT username FROM users WHERE username='administrator') = 'administrator'` | 200 → user tồn tại (test chéo `notarealuser` → 500, củng cố độ tin cậy) |
| **3. Độ dài password**               | Test tay theo kiểu binary search (35→25→20→19) thay vì chạy Intruder            | `LENGTH(password) > N`                                                          | N=19 true, N=20 false → **độ dài = 20**                                 |
| **4. Từng ký tự password**           | Dùng Intruder **Cluster bomb**, 2 payload position                              | `SUBSTR(password,i,1)='x'`                                                      | Đang chạy — chờ kết quả                                                 |

## 3. Bug/lỗi kỹ thuật đã gặp và cách sửa (rất quan trọng để nhớ)

| Lỗi gặp phải                                              | Nguyên nhân                                                          | Cách sửa                                                                |
| --------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Response giống hệt dù `1=1`/`1=0`                         | Ứng dụng không phản hồi theo số row (đặc thù bài Conditional Errors) | Đổi sang kỹ thuật ép lỗi bằng `CASE WHEN`                               |
| `(SELECT 'x' FROM users LIMIT 1)` → lỗi 500 dù true/false | **Oracle không có `LIMIT`**                                          | Thay bằng `WHERE ROWNUM=1` (pseudo-column riêng của Oracle)             |
| `FROM users FROM DUAL` → lỗi cú pháp                      | Viết 2 lần `FROM` trong 1 câu                                        | Chỉ cần `FROM users`, không cần thêm `DUAL` khi đã có bảng thật         |
| Burp báo "Stream failed to close correctly"               | Lỗi kết nối HTTP/2 giữa Burp và server                               | Tắt "Default to HTTP/2" trong Settings → Network → HTTP, ưu tiên HTTP/1 |

## 4. Cập nhật Mind Map tổng (6 nhánh)

**NHÁNH 2 — Phân loại:** Bổ sung ví dụ thực chiến cho **Conditional Errors**: dùng `CASE WHEN ... ELSE <phép_toán_luôn_lỗi> END` (ví dụ `1/0`) làm oracle, khi ứng dụng không phân biệt response theo số row trả về.

**NHÁNH 3 — Quy trình khai thác:** Bổ sung kỹ thuật tạo tín hiệu nhân tạo khi không có tín hiệu tự nhiên: `AND (CASE WHEN (<điều_kiện>) THEN <giá_trị_an_toàn> ELSE <biểu_thức_luôn_lỗi> END) = <giá_trị_an_toàn>` — biến mọi bài toán boolean thành bài toán "lỗi/không lỗi".

**NHÁNH 5 — Tooling:** Bổ sung: khi tín hiệu là status code (200 vs 500) thay vì chuỗi text, Burp Intruder có thể đọc trực tiếp cột **Status code** để lọc kết quả, không cần Grep-Match như Lab 11.

**NHÁNH 6 — Câu hỏi tự kiểm tra:** Bổ sung câu hỏi mới — _"Vì sao kỹ thuật `CASE WHEN + phép toán gây lỗi` lại tổng quát hơn `AND 1=1/1=0` — nó giải quyết được vấn đề gì mà kỹ thuật kia không giải quyết được?"_
