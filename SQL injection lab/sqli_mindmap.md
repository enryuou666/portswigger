# MIND MAP — SQL INJECTION (SQLi)
*(Tổng hợp từ 17 lab đã hoàn thành trên PortSwigger Web Security Academy)*

---

## NHÁNH 1 — BẢN CHẤT & ROOT CAUSE

### Định nghĩa
SQL Injection là lỗ hổng cho phép attacker chèn hoặc sửa đổi câu lệnh SQL mà ứng dụng gửi tới database, thông qua việc kiểm soát một phần nội dung của câu lệnh đó qua input (tham số URL, cookie, header, body...). Hệ quả: đọc/sửa/xóa dữ liệu ngoài phạm vi cho phép, bypass authentication, và trong trường hợp xấu nhất là RCE (qua stacked queries + hàm hệ thống của DBMS).

### Root cause
- Input của user bị **nối chuỗi trực tiếp (string concatenation)** vào câu lệnh SQL, thay vì được truyền qua **parameterized query / prepared statement**.
- Input **không được tách biệt giữa "data" và "code"** → khi input chứa ký tự đặc biệt (`'`, `"`, `;`, `--`, `#`, `/* */`), nó phá vỡ ranh giới string literal và bị **diễn giải lại thành cú pháp SQL mới** (operator `OR`/`AND`, statement terminator `;`, comment `--`/`#`...).
- Input bị coi là "an toàn ngầm" chỉ vì nguồn gốc của nó (VD: cookie do chính server sinh ra ban đầu — Lab 11) — nhưng thực tế **mọi input từ client đều nằm trong tầm kiểm soát của attacker** (query param, body, header, cookie đều có thể sửa qua Burp), không phân biệt "trusted" hay "untrusted" theo nguồn.

### Component bị đánh lừa
- **SQL parser / query engine của DBMS** — không phải web server, không phải application layer. Đây là điểm mấu chốt: dù ứng dụng có validate input ở tầng code, nếu chuỗi cuối cùng đưa tới DBMS vẫn được ghép bằng string concatenation, injection point vẫn tồn tại.
- Parser không phân biệt được "chuỗi cú pháp do dev viết sẵn" vs "chuỗi dữ liệu do input tạo ra" — vì cả hai đến cùng một kênh văn bản thuần (câu SQL hoàn chỉnh dạng string) tại thời điểm parser nhận được nó.
- Ở Lab 17 (filter bypass qua XML encoding), có thêm 1 lớp bị đánh lừa khác: **WAF (pattern matcher ở tầng network)** — WAF quét dữ liệu *trước khi* XML parser decode entity, trong khi SQL engine chỉ nhận dữ liệu *sau khi* decode → 2 tầng nhìn thấy 2 dạng khác nhau của cùng 1 input (parser differential).

---

## NHÁNH 2 — PHÂN LOẠI CÁC BIẾN THỂ

### In-band — Retrieve hidden data *(Lab 1)*
- **Dấu hiệu:** sửa logic `WHERE` (thêm `OR 1=1--`) để vô hiệu hóa điều kiện lọc ẩn (`AND released=1`), trả về dữ liệu vốn không hiển thị.
- **Điều kiện khai thác:** kết quả injection hiển thị **trực tiếp** trên response — không cần side-channel gián tiếp nào.

### In-band — Login bypass *(Lab 2)*
- **Dấu hiệu:** sửa logic điều kiện xác thực (`administrator'--`) để cắt bỏ hẳn điều kiện `AND password='...'` bằng comment, thay vì cố "thắng" nó bằng `OR`.
- **Điều kiện khai thác:** injection point nằm ngay trong câu query dùng cho luồng authentication, và ứng dụng coi "query trả về ≥1 dòng" = "đăng nhập thành công".

### In-band — UNION attack *(Lab 3, 4, 5, 6, 7, 8, 9, 10)*
- **Dấu hiệu:** dùng `UNION SELECT` để ghép thêm 1 câu SELECT hoàn toàn mới vào kết quả trả về, đọc dữ liệu không thuộc bảng gốc.
- **Điều kiện khai thác:** (1) số cột của 2 câu SELECT phải khớp tuyệt đối (Lab 3), (2) kiểu dữ liệu từng vị trí cột phải tương thích (Lab 4), (3) kết quả UNION phải hiển thị ra response.
- **Biến thể phụ:**
  - Đọc dữ liệu từ bảng biết trước tên (Lab 5) vs bảng có tên ngẫu nhiên phải tự dò qua `information_schema`/`all_tables` (Lab 9, 10).
  - Gộp nhiều giá trị vào 1 cột bằng string concatenation khi số cột nhận text bị giới hạn (Lab 6).
  - Fingerprint DBMS type & version qua UNION (Lab 7 Oracle, Lab 8 MySQL/MSSQL) — cú pháp khác biệt hoàn toàn giữa các DBMS dù cùng kỹ thuật.

### Error-based — Visible error-based *(Lab 18)*
- **Dấu hiệu:** ép DB throw lỗi convert kiểu có chủ đích (`CAST(text AS int)`), và DBMS **in kèm chính giá trị gây lỗi** vào error message → đọc được nguyên 1 giá trị/request, không cần brute-force.
- **Điều kiện khai thác:** ứng dụng không suppress verbose error, DBMS có hành vi in giá trị lỗi vào message (PostgreSQL: `invalid input syntax for type integer: "administrator"`).

### SQLi filter bypass (WAF/input validation evasion) *(Lab 17)*
- **Dấu hiệu:** input bị WAF chặn theo pattern (`'`, `UNION`, `SELECT`), nhưng bypass được bằng cách encode payload thành XML character entity (`&#x55;...`) — WAF quét raw bytes trước decode, còn XML parser + SQL engine chỉ nhận dữ liệu sau decode.
- **Điều kiện khai thác:** input đi qua 1 tầng có cơ chế encode/decode riêng (ở đây là XML), và WAF hoạt động dạng blocklist theo pattern thay vì decode-rồi-mới-quét.

### Blind — Conditional responses (Boolean-based) *(Lab 11)*
- **Dấu hiệu:** response khác biệt về nội dung (`Welcome back` có/không) giữa điều kiện TRUE/FALSE, không có error, không có data trực tiếp.
- **Điều kiện khai thác:** có thể inject điều kiện boolean (`AND (subquery)='x'`) vào query ảnh hưởng tới việc có/không có dòng trả về, từ đó ảnh hưởng luồng hiển thị.

### Blind — Conditional errors *(Lab 12)*
- **Dấu hiệu:** không có khác biệt nội dung, nhưng TRUE/FALSE tạo ra HTTP status khác nhau (200 vs 500) do query lỗi có chủ đích.
- **Điều kiện khai thác:** có thể trigger lỗi DB có điều kiện (`CASE WHEN (đk) THEN 1 ELSE 1/0 END`) — biến bài toán boolean thành bài toán "lỗi/không lỗi".

### Blind — Time delays *(Lab 13)*
- **Dấu hiệu:** response time khác biệt dựa trên điều kiện (`pg_sleep()`, `WAITFOR DELAY`, `dbms_pipe.receive_message()`).
- **Điều kiện khai thác:** không có bất kỳ side-channel nào khác (không error, không content diff) — đây là oracle tổng quát nhất vì DB thực thi query đồng bộ (server phải chờ xong mới render trang).

### Blind — Time delays + information retrieval *(Lab 14)*
- **Dấu hiệu:** dùng time-based làm oracle để leak từng ký tự dữ liệu thật (không chỉ chứng minh injectable).
- **Điều kiện khai thác:** cần điều kiện hóa delay theo giá trị ký tự đang test (`CASE WHEN (SUBSTRING(password,i,1)='x') THEN pg_sleep(N) ELSE pg_sleep(0) END`), qua stacked query (`;`).

### Blind — Out-of-band interaction (OAST) *(Lab 15)*
- **Dấu hiệu:** trigger DNS/HTTP lookup ra ngoài (Burp Collaborator) khi query chạy, chỉ để **chứng minh injectable** — chưa đọc dữ liệu thật.
- **Điều kiện khai thác:** query chạy **bất đồng bộ (async)**, khiến mọi in-band channel (content/status/error/time) đều vô hiệu; DB không có network function đơn giản (Oracle) → phải mượn cơ chế XXE (`EXTRACTVALUE(xmltype(...), '/l')` + external DTD entity).

### Blind — Out-of-band data exfiltration *(Lab 16)*
- **Dấu hiệu:** nhúng dữ liệu leak thật vào chính request OAST (subdomain) bằng string concatenation (`||`).
- **Điều kiện khai thác:** giống Lab 15 (query async, không side-channel in-band nào khả dụng) + có thể nối kết quả subquery vào chuỗi URL bị gọi ra ngoài — đọc được nguyên 1 giá trị/request qua Collaborator thay vì dò từng ký tự.

### Second-order SQL injection *(chưa thực hành)*
- **Dấu hiệu:** payload lưu vào DB ở request A (vô hại tại thời điểm lưu), kích hoạt injection ở request B khi giá trị đó được dùng lại trong 1 câu query khác.
- **Điều kiện khai thác:** có 2 điểm tách biệt — điểm lưu dữ liệu và điểm sử dụng lại dữ liệu đó trong query, và điểm sử dụng lại không parameterize.

---

## NHÁNH 3 — QUY TRÌNH KHAI THÁC (từng bước)

### Bước 1 — Xác định điểm inject
- Test tất cả input surface: URL param (`category` — Lab 1, 3-10), cookie (`TrackingId` — Lab 11, 12, 14, 15, 16, 18), body XML (`storeId` — Lab 17), form field (`username`/`password` — Lab 2).
- Payload dò an toàn: dấu nháy đơn `'`, phép toán học không rõ ràng SQL (`1+1` — Lab 17, tránh WAF chặn ngay từ bước thăm dò), khoảng trắng bất thường → quan sát lỗi/thay đổi hành vi.
- **Nguyên tắc quan trọng (rút từ Lab 17):** phải xác nhận injectable **riêng từng field**, không giả định mọi field trong cùng 1 request đều injectable như nhau — 1 field bị flag bởi WAF không có nghĩa nó thực sự injectable.

### Bước 2 — Xác định loại/context
- String context (trong `'...'`) vs Numeric context (không quote) vs Identifier context (tên cột/bảng).
- Ứng dụng có phản hồi trực tiếp (in-band) hay không phản hồi gì khác biệt (blind) → quyết định nhánh kỹ thuật tiếp theo (Nhánh 2).
- Kiểm tra khả năng stacked queries (`;` có chạy được statement thứ 2 không — Lab 14 dùng được trên PostgreSQL qua HTTP body, nhưng cần lưu ý tầng Cookie header cũng dùng `;` làm delimiter riêng, phải encode `%3B` trước khi tới được SQL layer).
- Nếu có WAF/filter chặn cú pháp SQL rõ ràng (Lab 17): xác định filter hoạt động theo blocklist pattern, từ đó tìm cơ chế encode/decode mismatch giữa lớp filter và lớp xử lý thật (XML entity, URL encoding kép, Unicode...).

### Bước 3 — Fingerprint môi trường
- **DBMS type** dựa vào:
  - Error message signature (Oracle `ORA-xxxxx`, PostgreSQL `ERROR: ... Position: N`, MySQL "You have an error in your SQL syntax", MSSQL "Incorrect syntax near...").
  - Comment syntax: `--` (Oracle/MSSQL/Postgres, MySQL cần dấu cách theo sau) vs `#` (chỉ MySQL).
  - Có bắt buộc `FROM` khi SELECT hằng số hay không: Oracle bắt buộc `FROM dual`, MySQL/MSSQL/Postgres không cần.
  - String concat operator: `||` (Oracle/Postgres) vs `CONCAT()` (MySQL) vs `+` (MSSQL).
- **Version:** `SELECT BANNER FROM v$version` (Oracle) / `SELECT @@version` (MySQL, MSSQL) / `SELECT version()` (PostgreSQL) — đọc qua UNION nếu in-band.
- **Đặc thù DBMS khác:** Oracle cần `ROWNUM=1` thay cho `LIMIT 1` (Postgres/MySQL) khi ép subquery về đúng 1 dòng; Oracle dùng `all_tables`/`all_tab_columns` thay cho `information_schema.tables`/`information_schema.columns` (chuẩn ANSI, dùng cho non-Oracle).

### Bước 4 — Khai thác chính (leo thang từ detect → extract → full impact)
1. **Detect:** xác nhận injectable qua boolean oracle (`AND 1=1` vs `AND 1=0`), error oracle (`CASE WHEN...1/0`), hoặc time oracle (`pg_sleep`) — chọn oracle theo thứ tự ưu tiên: content diff > status diff > error message chứa data > time delay > OOB (chỉ dùng khi mọi kênh khác đều vô hiệu, VD query async).
2. **Confirm & enumerate schema (nếu chưa biết tên bảng/cột):** liệt kê bảng (`information_schema.tables`/`all_tables`), liệt kê cột của bảng nghi ngờ (`information_schema.columns WHERE table_name=...`/`all_tab_columns WHERE table_name=...`).
3. **Extract data:**
   - In-band: đọc trực tiếp qua UNION, hoặc qua error message (visible error-based).
   - Blind: brute-force nhị phân/tuần tự từng ký tự (`SUBSTRING(col,i,1)='x'`) bằng Intruder Sniper (1 vị trí, VD dò độ dài) hoặc Cluster bomb (2 vị trí, VD dò offset × ký tự).
   - OOB: nối dữ liệu vào chuỗi gọi ra ngoài (`||`) để đọc nguyên giá trị/request qua Collaborator, không cần dò ký tự.
4. **Full impact / escalate (chưa thực hành trong chuỗi lab này nhưng cần biết):** stacked queries → `xp_cmdshell` (MSSQL), `INTO OUTFILE` (MySQL), đọc/ghi file hệ thống → RCE nếu quyền DB account cho phép.

---

## NHÁNH 4 — PHÒNG CHỐNG (theo độ ưu tiên)

### Giải pháp gốc rễ — Parameterized queries / Prepared statements (bind variables)

```php
// ❌ SAI — string concatenation
$query = "SELECT * FROM users WHERE username = '" . $u . "' AND password = '" . $p . "'";

// ✅ ĐÚNG — parameterized query
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$u, $p]);
```

**Tại sao hiệu quả về mặt cơ chế (không chỉ "lọc ký tự"):**
- DB driver gửi **câu lệnh SQL (query plan) và dữ liệu qua 2 kênh tách biệt ở tầng giao thức** — query được compile/parse trước với các placeholder (`?`), dữ liệu thật chỉ được "bind" vào sau khi cấu trúc câu lệnh đã cố định.
- Vì vậy, input — dù chứa `'`, `;`, `--`, `UNION`, `OR 1=1`, hay bất kỳ cú pháp SQL nào — **không bao giờ được SQL parser đọc lại như cú pháp**, nó chỉ được xử lý như 1 giá trị dữ liệu thuần túy được gán vào đúng vị trí đã định sẵn.
- Đây là loại bỏ **injection channel tận gốc** (không có "biến thể payload" nào bypass được, vì input không đi qua bước parse cú pháp nữa), khác hẳn với việc "chặn" hay "lọc" các payload đã biết — vốn luôn có nguy cơ bị bypass bằng payload biến thể chưa được liệt kê.
- **Bằng chứng thực chiến (Lab 15/16):** dù attacker dùng kỹ thuật tinh vi tới đâu (XXE lồng trong SQLi, OOB qua DNS), gốc rễ vẫn luôn là injection point chưa parameterize — mọi biện pháp khác (suppress error, disable time delay, chặn network egress) chỉ chặn được **1 kênh lộ dữ liệu cụ thể**, không triệt tiêu được injection point.

### Giải pháp bổ sung (defense in depth — không thay thế được giải pháp gốc rễ)

| Biện pháp | Tác dụng | Giới hạn |
|---|---|---|
| **Least privilege cho DB account** | Hạn chế thiệt hại nếu injection vẫn xảy ra (không cấp quyền DDL, `xp_cmdshell`, đọc `information_schema`/`v$version` nếu không cần) | Không vá được injection point, chỉ giảm blast radius |
| **Suppress verbose error message** | Ngăn được Error-based SQLi (Lab 18) | Injection point vẫn tồn tại, attacker chuyển sang blind/time/OOB (Lab 11-16) |
| **Input validation / whitelist** | Chặn sớm ở tầng trước khi chạm SQL (VD `category` chỉ nhận 1 trong tập giá trị cố định) | Chỉ hiệu quả với input có định dạng cố định; không áp dụng được cho input tự do (VD nội dung bài viết) |
| **WAF (Web Application Firewall)** | Chặn payload SQLi phổ biến theo pattern ở tầng network | Bản chất là blocklist — luôn có thể bypass bằng encoding/obfuscation mới (Lab 17 minh chứng: chỉ cần đổi encoding, không cần đổi logic payload) |
| **ORM sử dụng đúng cách** | Mặc định dùng parameterized query phía dưới, giảm rủi ro tự nối chuỗi SQL thủ công | Vẫn có thể bị injection nếu dùng raw query/string building trong ORM |
| **Hash password (bcrypt/argon2)** | Dù bị leak qua SQLi, giá trị leak ra là hash chứ không phải plaintext | Không ngăn được injection, chỉ giảm impact của riêng dữ liệu password |
| **Vô hiệu hóa external entity resolution trong XML parser** | Chặn vector XXE cụ thể dùng trong OOB (Lab 15/16) | Không vá injection point gốc, chỉ chặn 1 kỹ thuật tạo network call cụ thể |

### So sánh cơ chế các lớp phòng thủ
- **WAF / input validation (blocklist)** = kiểm tra theo pattern → luôn có nguy cơ bị bypass bằng biến thể payload chưa biết (encoding, case, comment trick).
- **Suppress error** = chặn đúng 1 side-channel (error-based) → injection point vẫn tồn tại nguyên vẹn, chỉ đổi kỹ thuật khai thác sang blind/time/OOB.
- **Parameterized query** = loại bỏ khả năng parser hiểu nhầm data thành code **ngay từ gốc** → không có "biến thể payload" nào bypass được, vì input không còn đi qua bước parse cú pháp SQL nữa.

---

## NHÁNH 5 — TOOLING & TỐI ƯU THỜI GIAN

### sqlmap
- `--technique=U` → UNION-based (Lab 3-10)
- `--technique=E` → error-based (khi có verbose error như Lab 18)
- `--technique=B` → boolean blind (Lab 11)
- `--technique=T` → time-based blind (Lab 13, 14)
- `--technique=S` → stacked queries (Lab 14 dùng thủ công qua Repeater/Intruder, nhưng về nguyên lý tương ứng kỹ thuật này)
- `--dbms=oracle`/`--dbms=postgresql`/... → skip bước fingerprint, dùng đúng cú pháp đặc thù DBMS ngay từ đầu (VD `FROM dual`, `ROWNUM` cho Oracle), giảm số request thừa
- `--risk`, `--level` → tăng độ sâu test (thêm payload, thêm vị trí thử ở header/cookie — hữu ích khi injection point nằm ở cookie như phần lớn lab blind trong chuỗi này)
- `-r <request_file>` → nạp trực tiếp request đã bắt từ Burp (Repeater) vào sqlmap, giữ nguyên toàn bộ header/cookie thay vì gõ lại tay
- `--os-shell` → escalate lên RCE nếu quyền DB account cho phép (full impact, bước 4 của Nhánh 3)

### Khi nào nên tự viết script Python thay vì dùng tool có sẵn
- Cần **binary search** thay vì linear brute-force mặc định của Intruder/sqlmap → giảm số request từ O(n) xuống O(log n) mỗi ký tự (áp dụng được cho cả dò độ dài password lẫn dò từng ký tự ở Lab 11, 12, 14).
- Payload dạng `CASE WHEN` tùy biến sâu (VD Oracle conditional error ở Lab 12 dùng `ROWNUM` thay `LIMIT`) không khớp pattern chuẩn mà sqlmap tự sinh.
- Cần custom side-channel mà tool không hỗ trợ sẵn — điển hình là OOB exfiltration ghép dữ liệu vào subdomain qua `||` (Lab 16), cần tự parse kết quả từ Collaborator (Host header) thay vì đọc response HTTP thông thường.
- Cần tốc độ cao qua request bất đồng bộ/song song có kiểm soát (khác với time-based, nơi *phải* single-thread — xem mục Resource pool bên dưới), hoặc cần filter/sắp xếp lại kết quả theo logic riêng (VD Cluster bomb trả kết quả không theo thứ tự offset số học, cần tự sort lại).

### Burp Repeater
- Dùng để **confirm thủ công từng bước** trước khi đưa vào Intruder: test true/false, trigger error, đo baseline response time — tránh brute-force hàng loạt với payload sai cú pháp (bài học từ mọi lab blind: luôn xác nhận oracle hoạt động đúng cả 2 chiều ở Repeater trước).
- Luôn kiểm tra tab **Raw** (không phải Pretty) trước khi Send — phát hiện lỗi encode (`;` chưa thành `%3B` — Lab 14), double single-quote (`''` thay vì `'` — Lab 18), hoặc double-encode do bấm Ctrl+U 2 lần.

### Burp Intruder
- **Sniper**: 1 payload position — dò độ dài dữ liệu (`LENGTH(password) > N`, Numbers sequential).
- **Cluster bomb**: ≥2 payload position độc lập, chạy hết mọi tổ hợp — dò từng ký tự (offset × ký tự thử, VD 20 × 36 = 720 request ở Lab 11/14).
- Filter kết quả theo:
  - **Status code** — Conditional errors (Lab 12).
  - **Response length / Grep-Match keyword** — Conditional responses (Lab 11).
  - **Response received (thời gian)** — Time-based (Lab 13, 14), cần sort cột này để tìm ranh giới.

### Resource pool — bắt buộc cho time-based Intruder
- **Vì sao cần:** oracle dạng nội dung/status (Lab 11/12) không bị ảnh hưởng khi chạy đa luồng vì mỗi response tự chứa đúng tín hiệu riêng. Nhưng oracle dạng **thời gian** phụ thuộc tài nguyên dùng chung (CPU, connection pool DB) — nhiều request "true" (đang sleep) chạy song song sẽ tranh chấp, khiến các lệnh sleep xếp hàng chồng lên nhau, làm sai lệch phép đo (thực tế Lab 14: dùng `pg_sleep(5)` mặc định đa luồng ra tới 7 dòng ~10.300-10.600ms nhiễu, thay vì 1 ranh giới rõ ràng).
- **Cách sửa:** tab Resource pool → Create new resource pool → "Maximum concurrent requests" = **1** → gán attack vào pool này.
- **Đánh đổi tốc độ:** sleep càng lớn càng dễ phân biệt khỏi baseline nhưng attack càng chậm; sau khi đã single-thread, có thể giảm sleep (VD từ 10s xuống 5s) mà kết quả vẫn sạch, miễn khoảng cách với baseline mạng đủ rộng.

### So sánh tốc độ extract dữ liệu giữa các kỹ thuật
| Kỹ thuật | Tốc độ | Lab minh họa |
|---|---|---|
| Boolean-based / Conditional errors | 1 bit/request (cần Intruder dò từng ký tự) | Lab 11, 12 |
| Time-based | 1 bit/request, tốn thêm N giây sleep mỗi request | Lab 13, 14 |
| Visible error-based | Nguyên 1 giá trị/request | Lab 18 |
| OOB data exfiltration | Nguyên 1 giá trị/request (qua Collaborator) | Lab 16 |
| UNION-based | Toàn bộ dữ liệu trong 1 response | Lab 5, 6, 9, 10 |

### Burp Collaborator (bắt buộc Professional)
- Dùng cho mọi kỹ thuật OOB (Lab 15, 16) — Copy to clipboard lấy subdomain, Insert Collaborator payload để gắn đúng vị trí, Poll now để đọc interaction.
- **Bẫy cần nhớ:** chỉ bôi đen đúng placeholder text (không lấy kèm `http://` hay `/` xung quanh) trước khi Insert Collaborator payload — bôi sai vùng sẽ làm mất phần cấu trúc quan trọng (scheme, hoặc đoạn subquery nối chuỗi để exfiltrate).

### Hackvertor (extension, dùng ở Lab 17)
- Encode payload thành XML character entity (`dec_entities`/`hex_entities`) để bypass WAF pattern-matching mà không đổi bản chất logic payload.
- Cú pháp tiện lợi `<@hex_entities>...</@hex_entities>` để tự động encode toàn bộ nội dung bên trong ngay trước khi gửi, không cần bôi đen thủ công mỗi lần sửa payload.
