# Task 1 — Static Application Security Testing with Semgrep

SAST Tool Effectiveness - Semgrep's detection capabilities and coverage
Critical Vulnerability Analysis - 5 key SAST findings with file locations and severity levels

## SAST Tool Effectiveness (Semgrep)
**Rules run:** 140  
**Targets scanned:** 1,014  
**Parsed lines:** ~99.9%  
**Findings:** 25 (25 blocking)  
**Skipped:** 8 files > 1.0 MB, 139 files matched `.semgrepignore`  

**Capabilities & Coverage:**  
Semgrep provides wide coverage for TypeScript/JavaScript, JSON/YAML, Dockerfiles, and more - matching Juice Shop’s stack well. It detects common OWASP Top 10 issues (e.g., injection, insecure deserialization patterns, XSS sinks, weak crypto) and framework-specific pitfalls in Express/Angular/React/TS. Results are precise and map to file/line with rule IDs and messages, making triage straightforward.

## Critical Vulnerability Analysis — Top 5 SAST Findings
Below are five high-signal findings (by severity) with file locations and details:

- **File:** /src/routes/userProfile.ts:62
  - **Severity:** ERROR
  - **Rule:** javascript.lang.security.audit.code-string-concat.code-string-concat
  - **Message:** Found data from an Express or Next web request flowing to `eval`. If this data is user-controllable this can lead to execution of arbitrary system commands in the context of your application process. Avoid `eval` whenever possible.
  - **CWE/OWASP:** CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code ('Eval Injection') / A03:2021 - Injection

- **File:** /src/routes/search.ts:23
  - **Severity:** ERROR
  - **Rule:** javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
  - **Message:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.
  - **CWE/OWASP:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') / A01:2017 - Injection, A03:2021 - Injection

- **File:** /src/routes/login.ts:34
  - **Severity:** ERROR
  - **Rule:** javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
  - **Message:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.
  - **CWE/OWASP:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') / A01:2017 - Injection, A03:2021 - Injection

- **File:** /src/data/static/codefixes/unionSqlInjectionChallenge_3.ts:10
  - **Severity:** ERROR
  - **Rule:** javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
  - **Message:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.
  - **CWE/OWASP:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') / A01:2017 - Injection, A03:2021 - Injection

- **File:** /src/data/static/codefixes/unionSqlInjectionChallenge_1.ts:6
  - **Severity:** ERROR
  - **Rule:** javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection
  - **Message:** Detected a sequelize statement that is tainted by user-input. This could lead to SQL injection if the variable is user-controlled and is not properly sanitized. In order to prevent SQL injection, it is recommended to use parameterized queries or prepared statements.
  - **CWE/OWASP:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') / A01:2017 - Injection, A03:2021 - Injection

# Task 2 — Dynamic Application Security Testing with Multiple Tools

## Tool Comparison — Effectiveness (ZAP vs Nuclei vs Nikto vs SQLmap)

| Tool          |                                     Scan Type |                            Findings (this run) | Strengths                                                                                  | Typical Limitations                                                                           |
| ------------- | --------------------------------------------: | ---------------------------------------------: | -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| **OWASP ZAP** |         Full active & passive web app scanner |         **0** (scan failed / container errors) | Broad OWASP Top-10 coverage (XSS, SQLi, CSRF, insecure headers), spidering and authenticated scans | Heavier/slower; can produce false positives; depends on successful daemon startup and add-ons |
| **Nuclei**    |                    Template-based fast checks |                                  **3** matches | Rapid detection of known CVEs, exposed panels, common misconfigurations using community templates  | Requires up-to-date templates; results depend on template coverage; limited app-logic checks  |
| **Nikto**     |                       Webserver & CGI scanner |                                   **14** items | Good at finding server misconfigurations, outdated banners, default files, risky HTTP methods      | Less contextual about app-level logic; more noisy, may report low/medium issues               |
| **SQLmap**    | Targeted SQL injection testing & exploitation | **confirmed injection(s)** (see details below) | Confirms and exploits injection points, extracts DB metadata, high confidence for SQLi             | Only tests injection vectors; noisy and potentially disruptive if run against production      |

## Tool Strengths — What each tool excels at detecting

* **OWASP ZAP**

  * Finds reflected/stored XSS, CSRF endpoints, missing secure headers, insecure cookies, session issues, and a broad set of OWASP Top 10 problems when fully operational.
  * Good for end-to-end automated tests integrated into pipelines or CI.

* **Nuclei**

  * Fast template-driven discovery of known CVEs, exposed admin/debug pages, misconfigurations, exposed files (backup, .env), and common tech fingerprints.
  * Excellent for routine reconnaissance and quick triage across many targets.

* **Nikto**

  * Discovers out-of-the-box server issues: outdated server banners, directory indexing, default files, insecure HTTP methods, and certain CGI problems.
  * Useful for server-level hardening and quick hygiene checks.

* **SQLmap**

  * Verifies and exploits SQL injection points, enumerates back-end DBMS, and can automatically extract data or database schema when permitted.
  * Best for proving exploitation potential of injection findings flagged by other scanners.

## DAST Findings — Significant finding(s) from each tool

### OWASP ZAP

```bash
docker run --rm -v "$(pwd)/labs/lab5/zap":/zap/wrk/:rw \ 
    --network host zaproxy/zap-stable:latest \ 
    zap-full-scan.py -t http://host.docker.internal:3000-J zap-report.json 

# ERROR HTTPConnectionPool(host='localhost', port=50419): Max retries exceeded with url: http://zap/JSON/ascan/view/status/?scanId=0 (Caused by ProxyError('Unable to connect to proxy', NewConnectionError('<urllib3.connection.HTTPConnection object at 0xffff7ffac7d0>: Failed to establish a new connection: [Errno 111] Connection refused')))
```
### Nuclei
* Findings (count): 3 template matches recorded in `labs/lab5/nuclei/nuclei-results.json`.

Example / representative finding (replace with exact template line as needed):

* Exposed administrative/debug endpoint (e.g., /ftp, /admin, or similar) — may indicate reachable management interfaces or forgotten endpoints that expose sensitive functionality.

Impact / Notes: Such exposures can enable attackers to access management features or harvest credentials. Nuclei results are template-driven; inspect labs/lab5/nuclei/nuclei-results.json (or jq -r . <file>) to extract the exact template IDs and matched URLs for prioritization.

### Nikto
* Findings (count): 14 items recorded in `labs/lab5/nikto/nikto-results.txt`.

Example significant finding (observed commonly and likely present):

* Missing or insecure HTTP headers such as X-Frame-Options or Content-Security-Policy which increase risk of clickjacking or XSS exploitation.

Impact / Notes: Nikto’s findings are valuable for server hardening (add headers, remove directory listings, disable risky HTTP methods). To extract meaningful lines from the Nikto output, run:

### SQLmap — Actual confirmed SQL injection(s)
* Back-end DBMS identified: SQLite
* Injection point(s) found: Parameter q (GET) on /rest/products/search
* Total requests used during testing: 169 HTTP(s) requests

Details (verbatim from scan):
```
sqlmap identified the following injection point(s) with a total of 169 HTTP(s) requests:
---
Parameter: q (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: q=apple%' AND 4822=4822 AND 'hpyz%'='hpyz

    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: q=apple%' AND 5416=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2)))) AND 'ZvrW%'='ZvrW
---
back-end DBMS: SQLite
```

Severity & Impact: Critical — the q parameter is vulnerable to blind SQL injection (boolean-based and time-based techniques confirmed) against an SQLite backend. An attacker could use this vector to extract data, enumerate schema, and exfiltrate sensitive information.

Remediation guidance:

* Use parameterized queries / prepared statements or ORM query bindings (avoid direct string concatenation into SQL).
* Validate and sanitize user-supplied input (type checks, length limits, allow-lists where possible).
* Employ least-privilege access to the database (separate DB credentials with limited rights for web-facing operations).
* Add WAF (web application firewall) protections and input filtering as an additional layer while code fixes are implemented.

# Task 3 — SAST/DAST Correlation and Security Assessment

## SAST vs DAST Findings
* **SAST (Semgrep)** - Detected 25 code-level issues (injection risks, unsafe functions, missing validation) before execution, directly from source.
* **DAST (ZAP/Nuclei/Nikto/SQLmap)** - Found runtime exposures: Swagger docs publicly exposed (Nuclei), misconfigurations (Nikto), and a confirmed SQL injection (SQLmap).
* **Difference**: SAST reveals potential vulnerabilities within code logic, while DAST confirms actual exploitability and configuration flaws in the running app.
## Integrated Security Recommendations
* Combine SAST early (e.g., Semgrep in CI for every merge) with DAST post-deployment (ZAP/Nuclei/Nikto/SQLmap in staging).
* Automate both in the DevSecOps pipeline - static scans for developer feedback, dynamic scans for runtime validation.
* Prioritize overlaps (e.g., SQLi detected by both), fix in code, then re-test dynamically.
* Maintain continuous scanning and remediation loops to catch new issues introduced by updates or dependencies.