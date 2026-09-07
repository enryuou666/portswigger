# Lab — SQL Injection with Filter Bypass via XML Encoding

## Mục tiêu
Khai thác lỗ hổng SQLi trong chức năng stock check (gửi `productId`/`storeId` dạng XML), vượt qua WAF bằng cách encode payload thành XML entity, sau đó dùng UNION attack đọc username/password của `administrator`.

---

## 1. Bản chất lỗ hổng — có 2 lớp chồng lên nhau

**Lớp 1 — SQLi gốc:** Tham số `storeId` bị nối chuỗi trực tiếp vào câu SQL backend (dạng `SELECT stock FROM stock WHERE productId = ... AND storeId = <storeId>`), không qua parameterized query. Giống mọi lab khác về root cause.

**Lớp 2 — WAF chặn payload thô:** Khác các lab trước, ở đây có thêm **1 lớp phòng thủ bổ sung (WAF)** đứng giữa request và ứng dụng, quét nội dung XML tìm các pattern nghi ngờ (`'`, `UNION`, `SELECT`...) và chặn request nếu khớp — **đây chính là lý do lab này cần thêm bước "Bypass the WAF" mà các lab UNION khác không cần**.

**Vì sao input được gửi dạng XML lại là chìa khóa để bypass:** Vì `storeId` được đóng gói trong body XML (`<storeId>...</storeId>`), có thể tận dụng cơ chế **XML entity encoding** để mã hóa lại các ký tự nguy hiểm — WAF (quét theo pattern chuỗi thô) sẽ không nhận diện được payload đã bị encode, nhưng **XML parser ở tầng ứng dụng lại tự động decode entity về ký tự gốc trước khi query được xây dựng** → SQL injection vẫn xảy ra bình thường sau khi vượt qua WAF.

---

## 2. Quy trình khai thác — 3 giai đoạn (đúng theo solution)

### Giai đoạn 1 — Xác nhận injectable, chưa bypass WAF

**Bước 1: Quan sát format request**
```xml
POST /product/stock
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
  <productId>1</productId>
  <storeId>1</storeId>
</stockCheck>
```

**Bước 2: Test `storeId` bằng biểu thức toán học** (không phải payload SQL syntax rõ ràng, để tránh WAF chặn ngay từ bước thăm dò ban đầu):
```xml
<storeId>1+1</storeId>
```
✅ Nếu response trả về đúng stock của storeId=2 (thay vì storeId=1) → xác nhận: giá trị `storeId` **được evaluate bởi DB** (không phải chỉ so sánh chuỗi tĩnh) → injectable.

**Bước 3: Thử `UNION SELECT` để dò số cột**
```xml
<storeId>1 UNION SELECT NULL</storeId>
```
❌ Request bị chặn — "flagged as a potential attack" → xác nhận có **WAF** đứng chặn giữa request và ứng dụng, phát hiện theo pattern (`UNION`, `SELECT`).

### Giai đoạn 2 — Bypass WAF bằng XML entity encoding

**Công cụ:** Burp extension **Hackvertor** (cài qua BApp Store).

**Cách dùng:** Bôi đen phần payload cần encode → chuột phải → **Extensions → Hackvertor → Encode → dec_entities** (hoặc `hex_entities`).

**Cơ chế encode:** Mỗi ký tự trong payload được chuyển thành dạng XML character entity, ví dụ:
- `'` (dấu nháy đơn) → `&#39;` (dec) hoặc `&#x27;` (hex)
- `U` → `&#85;` hoặc `&#x55;`

**Vì sao cách này qua mặt được WAF nhưng vẫn hoạt động đúng ở tầng SQL:**

| Tầng xử lý | Nhìn thấy gì | Kết quả |
|---|---|---|
| **WAF** (quét raw bytes của request) | Chuỗi `&#x55;&#x4e;&#x49;...` — không khớp pattern `UNION`/`'` | Cho qua, không chặn |
| **XML parser của ứng dụng** (decode entity theo chuẩn XML trước khi lấy giá trị text node) | Tự động giải mã `&#x55;...` trở lại thành `UNION...` | Giá trị `storeId` thực nhận được là chuỗi SQL injection nguyên vẹn |
| **SQL engine** | Nhận đúng chuỗi injection đã decode | Query bị injection thành công |

→ **Bài học cốt lõi:** WAF và XML parser xử lý request ở **2 thời điểm khác nhau, nhìn thấy 2 dạng dữ liệu khác nhau của cùng 1 input** — WAF kiểm tra dữ liệu **trước khi decode**, còn logic nghiệp vụ (và SQL engine) chỉ nhận dữ liệu **sau khi decode**. Đây chính là dạng tổng quát của lỗ hổng **"parser differential" / "encoding mismatch bypass"** — không riêng gì SQLi, áp dụng được cho nhiều loại filter bypass khác (XSS filter, path traversal filter...).

### Giai đoạn 3 — Craft exploit hoàn chỉnh sau khi đã bypass được WAF

**Xác nhận số cột:** Sau khi bypass, thử tăng dần cột như thường lệ → phát hiện: query gốc chỉ trả về **1 cột** (thử >1 cột → ứng dụng trả `0 units`, ngầm báo lỗi).

**Vì chỉ có 1 cột khả dụng, phải gộp username + password bằng nối chuỗi** (kỹ thuật giống hệt Lab 6 đã note trước đó):
```xml
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```

**Giải thích cú pháp `<@hex_entities>...</@hex_entities>`:** Đây là **cú pháp riêng của Hackvertor** (không phải XML entity thật) — cặp tag `<@hex_entities>` / `</@hex_entities>` báo cho Hackvertor biết: "hãy tự động encode toàn bộ nội dung nằm giữa 2 tag này thành hex XML entity ngay trước khi gửi request". Đây là cách dùng Hackvertor tiện lợi hơn so với việc bôi đen từng đoạn rồi chuột phải encode mỗi lần sửa payload.

**Kết quả:** Response trả về các dòng dạng `administrator~<password>`, tách theo `~` lấy password → đăng nhập → lab solved.

---

## 3. Trả lời câu hỏi: vì sao encode trong `storeId` bypass được, còn test `'` ở cả `productId` lẫn `storeId` (chưa encode) đều bị flag như nhau?

**Về việc cả 2 field đều bị WAF flag khi test `'` thô (chưa encode):** Đây là hành vi đúng như kỳ vọng — **WAF quét toàn bộ nội dung XML body theo pattern**, không phân biệt field nào đang chứa ký tự nghi ngờ. Bất kỳ field nào (dù có phải điểm inject thật hay không) chứa `'`, `UNION`, `SELECT` ở dạng thô đều bị chặn như nhau, vì WAF hoạt động ở tầng **kiểm tra chuỗi request**, chưa biết field nào thực sự được dùng trong câu SQL.

**Về việc encode chỉ áp dụng thành công ở `storeId`, không phải `productId` — nhiều khả năng do 2 nguyên nhân kết hợp:**

1. **`storeId` mới là injection point thật sự trong câu query backend.** Từ bước thăm dò ở Giai đoạn 1 (`1+1` cho kết quả đúng stock của ID khác), bạn đã **xác nhận `storeId` được evaluate bởi DB**. Không có bước tương đương xác nhận `productId` cũng vậy — rất có thể `productId` được ứng dụng **validate/ép kiểu int nghiêm ngặt ở tầng code** (VD parse `int(productId)`) trước khi đưa vào query, hoặc dùng trong 1 câu query khác không liên quan tới injection — nên dù có bypass được WAF bằng encode, giá trị injection trong `productId` cũng **không bao giờ chạm tới được SQL engine dưới dạng cú pháp SQL**, mà bị chặn/ép kiểu ở 1 lớp hoàn toàn khác (validation code, không phải WAF).

2. **Bypass bằng encode chỉ giải quyết được lớp WAF — không tự động biến 1 field không injectable thành injectable.** Encode chỉ giúp *payload đi qua được WAF nguyên vẹn tới tầng ứng dụng*; việc field đó có thực sự là injection point hay không là **thuộc tính của chính code backend**, độc lập hoàn toàn với việc WAF có chặn hay không. Vì vậy nếu bạn thử encode cả `productId`, nhiều khả năng request vẫn "đi qua" được WAF (không bị flag) — nhưng **không tạo ra được injection thật**, vì bản thân `productId` chưa từng được chứng minh là injectable ngay từ bước thăm dò ban đầu.

**Kết luận thực chiến:** Luôn **xác nhận injection point bằng phép thử an toàn (`1+1`) trước**, cho từng field riêng biệt, thay vì giả định mọi field trong cùng 1 request đều injectable như nhau. WAF flag cả 2 field không có nghĩa cả 2 đều là lỗ hổng thật — WAF chỉ phản ánh "trông giống tấn công", không phản ánh "có tác dụng khai thác được hay không".

---

## 4. Bug/lỗi thường gặp

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| `1+1` không trả về stock khác | Chưa chắc `storeId` injectable, hoặc dùng nhầm field | Thử lại đúng field `storeId`, không phải `productId` |
| Vẫn bị WAF chặn dù đã dùng Hackvertor | Chỉ encode 1 phần payload, còn sót ký tự thô (VD `'` chưa nằm trong vùng bôi đen) | Bôi đen **toàn bộ** đoạn cần encode, hoặc dùng cú pháp `<@hex_entities>...</@hex_entities>` bao trọn cả payload |
| Encode xong nhưng SQL vẫn không chạy đúng | XML parser ở ứng dụng không tự decode entity (hiếm, tùy implementation) | Xác nhận lại bằng response — nếu vẫn thấy lỗi cú pháp gốc (chưa decode), thử `dec_entities` thay vì `hex_entities` hoặc ngược lại |
| Chỉ trả về `0 units` dù cú pháp đúng | Query gốc chỉ có 1 cột, đang thử UNION SELECT nhiều hơn 1 cột | Quay lại dùng kỹ thuật nối chuỗi (`\|\|`) để gộp dữ liệu vào đúng 1 cột |

---

## 5. So sánh với các lab UNION/filter khác đã học

| | Lab UNION thường (3-10) | Lab này (filter bypass XML) |
|---|---|---|
| Cản trở chính | Chỉ cần đúng cú pháp SQL | Cú pháp SQL đúng **chưa đủ** — còn phải qua được WAF |
| Kỹ thuật thêm | Không có | XML entity encoding để né pattern-matching |
| Vị trí input | Query string/cookie (text thường) | XML body (tận dụng được cơ chế encode riêng của XML) |
| Bài học chính | Cách dùng UNION | Chênh lệch xử lý dữ liệu giữa các lớp (WAF vs parser vs SQL engine) |

---

## 6. Cách phòng chống

**Gốc rễ — Parameterized query:** vẫn là giải pháp duy nhất triệt để — nếu `storeId` được đưa vào query qua parameterized binding, việc bypass WAF bằng encode **vô nghĩa**, vì dù giá trị decode ra là gì, nó vẫn luôn được driver xử lý như dữ liệu thuần, không bao giờ diễn giải thành cú pháp SQL.

**Bổ sung — nhưng cần lưu ý về giới hạn của WAF:**
- WAF là lớp phòng thủ **dựa trên pattern-matching** — bản chất dễ bị bypass bằng bất kỳ kỹ thuật encoding/obfuscation nào mà WAF chưa biết tới (không chỉ XML entity, còn có thể là URL encoding kép, Unicode normalization, case variation...).
- **Bài học quan trọng nhất của lab này:** WAF **không thay thế** được việc sửa lỗ hổng gốc — nó chỉ làm tăng độ khó cho attacker ở 1 số kỹ thuật cụ thể mà nó nhận diện được, nhưng không loại bỏ injection point.
- Nếu bắt buộc dùng WAF, nên **normalize/decode toàn bộ input về dạng chuẩn trước khi áp dụng rule quét**, thay vì quét trên raw bytes chưa decode — giảm thiểu (không loại bỏ hoàn toàn) khả năng bypass qua encoding mismatch.

---

## 7. Câu hỏi tự kiểm tra

1. Vì sao WAF quét theo pattern lại có thể bị qua mặt hoàn toàn chỉ bằng cách đổi encoding của input, mà không cần đổi bản chất logic của payload?
2. Vì sao XML parser tự động decode entity lại là "con dao 2 lưỡi" — vừa là tính năng cần thiết cho XML hoạt động đúng chuẩn, vừa là nguồn gốc của filter bypass ở đây?
3. Vì sao WAF flag cả `productId` lẫn `storeId` khi test `'` thô, nhưng chỉ `storeId` mới thực sự khai thác được sau khi bypass — điều này nói lên gì về sự khác biệt giữa "nhìn giống tấn công" và "thực sự injectable"?
4. Vì sao việc chỉ có 1 cột khả dụng trong query gốc lại bắt buộc phải quay lại đúng kỹ thuật nối chuỗi đã học ở Lab 6, dù ngữ cảnh khai thác (có WAF) hoàn toàn khác?
5. Nếu WAF được cấu hình để tự decode entity trước khi quét pattern (thay vì quét raw), kỹ thuật bypass ở lab này còn hoạt động không? Vì sao?

---

## 8. Payload cuối cùng (cheat-sheet)

```xml
<!-- Bước 1: xác nhận storeId injectable -->
<storeId>1+1</storeId>

<!-- Bước 2: thử UNION (bị WAF chặn, chưa encode) -->
<storeId>1 UNION SELECT NULL</storeId>

<!-- Bước 3: bypass WAF bằng Hackvertor hex_entities, gộp dữ liệu vào 1 cột -->
<storeId><@hex_entities>1 UNION SELECT username || '~' || password FROM users</@hex_entities></storeId>
```

**Kết quả:** Response trả về danh sách `username~password`, tìm dòng `administrator` → đăng nhập → lab solved.
