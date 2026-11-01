# Phase 1: Detection Gaps Closure Report
## Autonomous Cybersecurity Analyst AI

### 1. Executive Summary & Rule Counts

This report details the implementation, validation, and metrics for Phase 1 ("Close the Detection Gaps").
All 6 previously unimplemented rules in `rules.yaml` (`not_implemented`) and 5 new JavaScript/TypeScript ported rules have been implemented, registered, and verified across four fixture applications.

- **Rule Count Before Phase 1**: 17 implemented rules, 6 not implemented
- **Rule Count After Phase 1**: **28 implemented rules**, 0 not implemented (+11 implemented rules, +64.7% coverage increase)
- **Languages Supported**: Python, JavaScript, TypeScript
- **Recall Across All 4 Test Apps**: **100.0% (43 / 43 ground truth findings detected)**
- **False Positive Rate**: **0.0% (0 false positives on safe code / tricky negatives)**
- **Secret Redaction Integrity**: **100% verified** (zero raw secret strings leaked in snippets, JSON, or reports)

---

### 2. New Detection Rules & CWE Mappings

| Rule ID | Vulnerability Class | Match Type | Languages | CWE Mapping | Module | Description & Scope |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`XSS-004`** | Cross-Site Scripting | AST | Python | **CWE-79** | `rules_extra.py` | Flask `render_template_string()` called with user input concatenated into template |
| **`AUTH-003`** | Broken Authentication | AST | Python, JS/TS | **CWE-307** | `rules_extra.py` | Login/auth route missing rate-limiting decorator (`@limiter.limit`) or middleware |
| **`AUTH-004`** | Broken Authentication | AST | Python, JS/TS | **CWE-614 / CWE-1004** | `rules_extra.py` | Session cookie set without `HttpOnly=True` and `Secure=True` flags |
| **`SSRF-001`** | Server-Side Request Forgery | AST | Python, JS/TS | **CWE-918** | `rules_extra.py` | HTTP client (`requests`, `urllib`, `httpx`, `fetch`, `axios`) with user URL & no allowlist |
| **`SECRET-004`** | Hardcoded Secrets | Regex | All | **CWE-798** | `rules_extra.py` | Hardcoded JWT literal (`eyJ...`); redacted immediately at detection time |
| **`SECRET-008`** | Hardcoded Secrets | File-Pattern | All | **CWE-540** | `rules_extra.py` | Tracked `.env` configuration file present in git repository (not in `.gitignore`) |
| **`CMDINJ-002`** | Command Injection | AST | JS/TS | **CWE-78** | `rules_extra.py` | `child_process.exec`/`execSync`/`spawn` (shell: true) with non-literal/concatenated input |
| **`PATHTRAV-002`**| Path Traversal | AST | JS/TS | **CWE-22** | `rules_extra.py` | `fs.readFile`/`writeFile`/`res.sendFile` with tainted input without base dir check |
| **`DESER-003`** | Unsafe Deserialization | AST | JS/TS | **CWE-502** | `rules_extra.py` | `node-serialize` `unserialize()`, `yaml.load()` without safe schema, `vm.runInContext` |
| **`AUTH-005`** | Broken Authentication | AST | JS/TS | **CWE-287** | `rules_extra.py` | Password compared with `==` / `===` / `!=` / `!==` directly instead of bcrypt/argon2 |
| **`AUTH-006`** | Broken Authentication | AST | JS/TS | **CWE-327** | `rules_extra.py` | `crypto.createHash('md5'|'sha1')` applied directly to a password value |

---

### 3. Fixtures Added & Ground Truth Details

Existing fixture applications (`demo_app/` and `demo_app_jsts/`) were left completely untouched (retaining their 14/14 ground truth findings and line numbering).

Two new dedicated fixture applications were added:

#### 3.1 `demo_app_phase1/` (Python)
- **`app.py`** & **`.env`**
- Ground Truth: **6 findings**
  1. `GT-P1-SECRET-008` (`.env:1`): Tracked `.env` file present in git repository.
  2. `GT-P1-SECRET-004` (`app.py:11`): Hardcoded JWT secret literal in source file.
  3. `GT-P1-XSS-004` (`app.py:23`): Flask `render_template_string(f"<h1>Hello, {user_name}!</h1>")`.
  4. `GT-P1-AUTH-003` (`app.py:33`): Authentication route `@app.route("/auth/login")` without rate limiting.
  5. `GT-P1-AUTH-004` (`app.py:39`): `resp.set_cookie("session", ...)` missing `httponly=True` and `secure=True`.
  6. `GT-P1-SSRF-001` (`app.py:74`): `requests.get(target)` without allowlist validation.
- Safe counterparts and tricky negatives tested with 0 false positives:
  - `TEST_JWT_PLACEHOLDER`: Placeholder format `eyJ...example...dummy` ignored.
  - `render_safe()`: Parameterized template rendering `render_template_string("<h1>Hello, {{ name }}</h1>", name=...)`.
  - `auth_login_safe()`: Protected by `@limiter.limit("5/minute")`.
  - `dashboard()`: Non-auth route without rate limiter.
  - `resp.set_cookie(..., httponly=True, secure=True, samesite="Lax")`: Hardened cookie.
  - `fetch_user_url_safe()`: Guarded by `target in ALLOWED_DOMAINS` allowlist check.
  - `health_check()`: Constant URL `requests.get("https://api.internal.service/health")`.

#### 3.2 `demo_app_phase1_jsts/` (JavaScript/TypeScript)
- **`server.js`**
- Ground Truth: **9 findings**
  1. `GT-P1-JS-SECRET-004` (`server.js:17`): Hardcoded JWT secret literal.
  2. `GT-P1-JS-AUTH-003` (`server.js:26`): Express auth endpoint without rate limiter middleware.
  3. `GT-P1-JS-AUTH-005` (`server.js:31`): Plaintext password comparison `password === user.passwordHash`.
  4. `GT-P1-JS-AUTH-006` (`server.js:33`): `crypto.createHash('md5')` on password.
  5. `GT-P1-JS-AUTH-004` (`server.js:36`): `res.cookie('session', ...)` missing `httpOnly` and `secure`.
  6. `GT-P1-JS-CMDINJ-002` (`server.js:74`): `child_process.exec(\`ping -c 1 ${host}\`)`.
  7. `GT-P1-JS-PATHTRAV-002` (`server.js:96`): `fs.readFile(userFile, ...)` with unvalidated path.
  8. `GT-P1-JS-DESER-003` (`server.js:124`): `serialize.unserialize(payload)` using `node-serialize`.
  9. `GT-P1-JS-SSRF-001` (`server.js:139`): `fetch(targetUrl)` with unvalidated user URL.
- Safe counterparts and tricky negatives tested with 0 false positives:
  - `testJwtPlaceholder`: Dummy token ignored.
  - `auth_login_safe`: Wrapped in `rateLimiter` middleware.
  - `bcrypt.compare(password, user.passwordHash)`: Safe hash verification.
  - `res.cookie(..., { httpOnly: true, secure: true, sameSite: 'strict' })`: Safe cookie.
  - `crypto.createHash('sha256').update(content)`: Non-password file checksum.
  - `child_process.spawn("ping", ["-c", "1", host])`: Safe argv array without `shell: true`.
  - `child_process.execSync("git rev-parse HEAD")`: Constant command.
  - `safePath.startsWith(SAFE_BASE_DIR)`: Safe base directory enforcement.
  - `fs.readFileSync(path.join(__dirname, 'package.json'))`: Constant path.
  - `yaml.load(yamlData, { schema: yaml.FAILSAFE_SCHEMA })` and `JSON.parse()`: Safe parsing.
  - `ALLOWED_URLS.includes(targetUrl)`: Safe allowlist check.
  - `fetch("https://api.internal.service/health")`: Constant URL.

---

### 4. Evaluation Metrics Across All Four Applications

| Application | Ground Truth Count | Recall (Before Reason) | Recall (After Reason) | FP Rate (Before Reason) | FP Rate (After Reason) | Patch Validity (Offline) | Run Time |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`demo_app`** | 14 | **100.0%** | **100.0%** | **0.0%** | **0.0%** | 100.0% (2/2 accepted) | 0.242s |
| **`demo_app_jsts`** | 14 | **100.0%** | **100.0%** | **0.0%** | **0.0%** | n/a (0/0) | 0.104s |
| **`demo_app_phase1`** | 6 | **100.0%** | **100.0%** | **0.0%** | **0.0%** | n/a (0/0) | 0.087s |
| **`demo_app_phase1_jsts`** | 9 | **100.0%** | **100.0%** | **0.0%** | **0.0%** | n/a (0/0) | 0.138s |
| **TOTAL** | **43** | **100.0%** | **100.0%** | **0.0%** | **0.0%** | — | **0.571s** |

---

### 5. Architectural & Design Decisions

1. **Deduplication via `_SUPERSEDED_BY`**:
   - `SQLI-001` is superseded by `SQLI-002` on `%`-formatting / `.format()` calls.
   - `XSS-002` (generic HTML return) is superseded by `XSS-004` (Flask `render_template_string()`).
   - `SECRET-005` (generic credential assignment) is superseded by `SECRET-001`, `SECRET-002`, `SECRET-003`, `SECRET-004` (JWT), and `SECRET-006`.
   - Result: Exactly one finding per defect, keeping defect counts mathematically precise.
2. **Conservative Scope Heuristics for Zero False Positives**:
   - `AUTH-003`: Only flags authentication endpoints (`/login`, `/signin`, `/auth`, `/token`) that actually contain credential-checking or session-setting logic in their handler body, avoiding false positives on mock endpoints in test suites or non-auth routes.
   - `SSRF-001`: Inspects the enclosing scope for validation guards (`ALLOWED_HOSTS`, `ALLOWED_DOMAINS`, `ALLOWED_URLS`, `whitelist`, `urlparse`, `startsWith`) and bypasses constant URLs.
3. **Mandatory Secret Redaction**:
   - Redaction is strictly enforced at detection time. In `rules_extra.py` and `analyst/common/redact.py`, raw JWTs are matched by `JWT_RE` and scrubbed to `<first_2_chars>****<len>****<last_2_chars>`, and tracked `.env` files produce a static informational snippet without file contents.
