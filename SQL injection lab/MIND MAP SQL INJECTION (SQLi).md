# MIND MAP: SQL INJECTION (SQLi) — PortSwigger Web Security Academy

## NHÁNH 1 — BẢN CHẤT & ROOT CAUSE

- Định nghĩa
  - Lỗ hổng cho phép attacker can thiệp vào câu truy vấn SQL mà ứng dụng gửi tới database
- Root cause
  - Input của user bị **nối chuỗi trực tiếp (string concatenation)** vào câu SQL
  - Dữ liệu (data) bị hiểu nhầm thành **cú pháp/lệnh (code)**
  - Ranh giới data/code bị phá vỡ do thiếu tách biệt ngữ cảnh
- Component bị đánh lừa
  - SQL parser/interpreter của DBMS (MySQL/PostgreSQL/Oracle/MSSQL)
  - Không phải web server, không phải browser — là tầng thực thi truy vấn

## NHÁNH 2 — PHÂN LOẠI CÁC BIẾN THỂ

- In-band SQLi
  - UNION-based
    - Dấu hiệu: kết quả query hiển thị trực tiếp trên response
    - Điều kiện: số cột + kiểu dữ liệu tương thích giữa query gốc và UNION SELECT
  - Error-based (visible)
    - Dấu hiệu: thông báo lỗi DB trả về nguyên văn trong response
    - Điều kiện: ứng dụng không suppress lỗi DB
- Blind SQLi
  - Boolean-based (conditional responses)
    - Dấu hiệu: response thay đổi (nội dung/HTTP status) theo điều kiện TRUE/FALSE, không có dữ liệu/lỗi lộ ra
  - Conditional errors
    - Dấu hiệu: query không trả kết quả nhưng gây lỗi có điều kiện (vd chia cho 0) → phát hiện qua HTTP 500 vs 200
  - Time-based blind
    - Dấu hiệu: không có khác biệt response ngoài **thời gian trả lời** (SLEEP/WAITFOR DELAY)
    - Điều kiện: dùng khi không có bất kỳ tín hiệu nào khác (không lỗi, không khác biệt nội dung)
- Out-of-band (OAST)
  - Dấu hiệu: không có tín hiệu nào qua kênh HTTP response — phải dùng kênh phụ (DNS/HTTP callback)
  - Điều kiện: dùng khi in-band và blind đều bị chặn (WAF, network egress bị hạn chế phía app nhưng DB có thể resolve DNS)
- Second-order (stored) SQLi
  - Dấu hiệu: input được lưu an toàn ở bước 1, nhưng bị dùng lại không an toàn ở bước 2 (chức năng khác)

## NHÁNH 3 — QUY TRÌNH KHAI THÁC

- Bước 1: Xác định điểm inject
  - Test từng entry point: query param, cookie, header, JSON/XML body, path
  - Payload dò: `'` , `''`, `" `, logic test `OR 1=1` / `OR 1=2`
- Bước 2: Xác định loại/context
  - Query trả dữ liệu trực tiếp? → in-band
  - Không trả gì nhưng response đổi theo điều kiện? → blind boolean
  - Không có tín hiệu gì cả? → time-based / OOB
  - Context cú pháp: trong string literal, trong số, trong ORDER BY, trong table/column name
- Bước 3: Fingerprint môi trường
  - Xác định DBMS: cú pháp comment (`--`, `#`, `/* */`), string concat (`||`, `+`, `CONCAT`), banner query (`@@version`, `v$version`)
  - Xác định số cột (UNION: `ORDER BY n` hoặc `UNION SELECT NULL,...`)
  - Xác định cột chấp nhận kiểu text
- Bước 4: Khai thác leo thang
  - Detect → confirm injectable
  - Extract metadata: `information_schema.tables` / `columns`
  - Extract data: username/password, dữ liệu nhạy cảm
  - Leo thang impact: bypass auth, stacked queries (INSERT/UPDATE/DELETE), đọc file (`LOAD_FILE`), RCE (`xp_cmdshell` trên MSSQL, `INTO OUTFILE` trên MySQL nếu có quyền)

## NHÁNH 4 — PHÒNG CHỐNG (theo ưu tiên)

- Ưu tiên 1 — Parameterized queries / Prepared statements
  - Cơ chế: tách data và code ngay từ tầng driver DB — input được gửi như **giá trị**, không bao giờ được parser DB diễn giải lại thành cú pháp
  - Vì sao hiệu quả gốc rễ: loại bỏ hoàn toàn bước "nối chuỗi", nên input dù chứa `'`, `--`, `UNION` vẫn không có khả năng thay đổi cấu trúc câu lệnh
- Ưu tiên 2 — Whitelist cho phần không parameterize được
  - Áp dụng cho table name/column name/ORDER BY (không thể bind bằng placeholder)
  - Cơ chế: giới hạn input về một tập giá trị hợp lệ đã biết trước, loại input ngoài whitelist trước khi build query
- Defense in depth (bổ sung, không thay thế gốc rễ)
  - Least privilege cho DB account (giảm impact nếu bypass được)
  - Input validation/escaping (chỉ là lớp phụ, dễ bị bypass bằng encoding)
  - WAF (chặn theo pattern, có thể bypass qua obfuscation/encoding)
  - Error handling: không lộ chi tiết lỗi DB ra response
- Vì sao whitelist/escaping/WAF không phải gốc rễ
  - Chúng cố "lọc" dữ liệu nguy hiểm sau khi đã trộn data+code → luôn có khả năng sót pattern
  - Parameterized query loại bỏ luôn khả năng trộn lẫn, nên không phụ thuộc vào việc liệt kê hết pattern nguy hiểm

## NHÁNH 5 — TOOLING & TỐI ƯU THỜI GIAN

- sqlmap
  - Dùng khi: đã xác nhận có injection, cần tự động hoá extract nhanh
  - Flag quan trọng
    - `-r request.txt` : import raw request từ Burp (giữ nguyên cookie/header)
    - `--level` / `--risk` : tăng độ sâu test (nhiều payload hơn, kể cả nguy hiểm)
    - `--technique=B/E/U/T/O` : giới hạn kỹ thuật (Boolean/Error/UNION/Time/OOB) để tăng tốc, tránh noise
    - `--dbms=mysql` : bỏ qua bước fingerprint nếu đã biết DB, tiết kiệm request
    - `--batch` : chạy non-interactive, phù hợp script
    - `--dump -T <table>` : trích xuất dữ liệu có mục tiêu thay vì dump toàn bộ
- Khi nào tự viết script Python thay vì dùng tool có sẵn
  - Blind/time-based cần logic đặc thù (binary search ký tự, xử lý rate-limit riêng của lab)
  - OOB payload cần custom domain/interaction (Burp Collaborator client)
  - Ứng dụng có CSRF token/step xác thực phức tạp mà sqlmap khó tái tạo tự động
  - Cần kiểm soát chính xác timing/threading để tránh false positive trên time-based
- Dùng Burp hiệu quả
  - Repeater: test tay từng payload, quan sát response length/status/time — bước bắt buộc trước khi tự động hoá
  - Intruder:
    - Sniper cho fuzzing 1 điểm inject (dò column count, dò ký tự trong blind)
    - Cluster bomb khi cần kết hợp nhiều tham số
    - Dùng Grep - Match/Extract để tự động phân loại response TRUE/FALSE trong boolean-blind
    - Dùng response time trong Intruder để tự động hoá time-based (so sánh baseline vs delay)

## NHÁNH 6 — CÂU HỎI TỰ KIỂM TRA

- Vì sao UNION attack yêu cầu số cột và kiểu dữ liệu khớp với query gốc, thay vì chỉ cần inject được là đủ?
- Vì sao time-based blind lại là kỹ thuật "cuối cùng" — vì sao không dùng ngay từ đầu dù nó luôn hoạt động được?
- Vì sao parameterized query chặn được SQLi ở mọi context (WHERE, INSERT, UPDATE) nhưng lại bất lực với ORDER BY hay table/column name?
- Vì sao second-order SQLi vẫn xảy ra dù input đã được xử lý "an toàn" ở lần lưu đầu tiên?
- Vì sao OOB (out-of-band) là kỹ thuật mạnh nhất trong các trường hợp blind, nhưng không phải lúc nào cũng khả thi?

---

# DANH SÁCH LAB TƯƠNG ỨNG (tăng dần độ khó)

**UNION-based / In-band:**

1. SQL injection vulnerability allowing login bypass
2. SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
3. SQL injection UNION attack, determining the number of columns returned by the query
4. SQL injection UNION attack, finding a column containing text
5. SQL injection UNION attack, retrieving data from other tables
6. SQL injection UNION attack, retrieving multiple values in a single column

**Examining database (fingerprint):** 7. SQL injection attack, querying the database type and version on Oracle 8. SQL injection attack, querying the database type and version on MySQL and Microsoft 9. SQL injection attack, listing the database contents on non-Oracle databases 10. SQL injection attack, listing the database contents on Oracle

**Blind SQLi:** 11. Blind SQL injection with conditional responses 12. Blind SQL injection with conditional errors 13. Visible error-based SQL injection 14. Blind SQL injection with time delays 15. Blind SQL injection with time delays and information retrieval 16. Blind SQL injection with out-of-band interaction 17. Blind SQL injection with out-of-band data exfiltration

**Nâng cao / bypass filter:** 18. SQL injection with filter bypass via XML encoding

_Lưu ý:_ danh sách tên lab có thể thay đổi nhẹ theo cập nhật của PortSwigger — nên đối chiếu lại với trang [portswigger.net/web-security/all-labs#sql-injection](https://portswigger.net/web-security/all-labs#sql-injection) trước khi lập kế hoạch học chi tiết, vì trang này render động và mình không lấy được danh sách real-time chính xác 100% qua fetch.
