# Detection Rules Catalog
## Autonomous Cybersecurity Analyst AI

This document defines the concrete rule set used by the Static Vulnerability Scanner and Secrets & Credential Scanner. Every finding surfaced by the tool must trace back to a rule ID in this catalog — this is what keeps the pipeline auditable (see `architecture.md §7`).

Rule ID format: `<CLASS>-<NNN>` e.g. `SQLI-001`.

---

## 1. Rule Schema

Every rule is defined with the following fields:

```yaml
id: SQLI-001
class: SQL Injection
severity_base: CRITICAL          # starting point; LLM may adjust ±1 bucket with justification
languages: [python, javascript, typescript]
match_type: ast | regex
pattern: <AST query or regex>
description: <human-readable, shown in report>
confidence: high | medium | low  # rule engine's own confidence, prior to LLM confirmation
llm_confirmation_required: true  # false only for near-zero-FP rules (e.g. exact secret format match)
```

---

## 2. SQL Injection (SQLI)

| ID | Match Type | Pattern (conceptual) | Languages | Confidence |
|---|---|---|---|---|
| SQLI-001 | AST | String concatenation (`+`, f-string, template literal) used directly as argument to `execute()`, `query()`, `raw()` | Python, JS/TS | High |
| SQLI-002 | AST | Cursor/ORM `.raw()` or `.execute()` call where argument is built via `%`-formatting or `.format()` with a variable | Python | High |
| SQLI-003 | Regex | `f"...{var}..."` or template literal passed to any function named `*query*`, `*execute*`, `*sql*` | Python, JS/TS | Medium |
| SQLI-004 | AST | ORM query built with unvalidated request input inserted into `.filter()`/`.where()` string clause (as opposed to parameterized kwargs) | Python (Django/SQLAlchemy) | Medium |

**Confirmation prompt focus:** LLM checks whether the variable is genuinely tainted (traceable to request input: query params, form data, headers, path params) vs. a constant/internal value. Untainted matches are rejected as false positives.

**Non-vulnerable pattern (should NOT fire):** parameterized queries (`cursor.execute("SELECT * FROM x WHERE id=%s", (id,))`), ORM methods using kwargs (`User.objects.filter(id=user_id)`).

---

## 3. Hardcoded Secrets (SECRET)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| SECRET-001 | Regex | AWS Access Key ID format `AKIA[0-9A-Z]{16}` | High |
| SECRET-002 | Regex | AWS Secret Key assignment context (`aws_secret_access_key\s*=\s*['"][A-Za-z0-9/+=]{40}['"]`) | High |
| SECRET-003 | Regex | GitHub token formats (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` + 36 alphanumeric) | High |
| SECRET-004 | Regex | JWT structure (`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`) hardcoded as a literal (not read from env/config) | Medium |
| SECRET-005 | Regex | Generic assignment `(api[_-]?key|secret|password|token)\s*=\s*['"][^'"]{8,}['"]` where RHS is a literal, not `os.environ`/`process.env` | Medium |
| SECRET-006 | Entropy | String literal ≥ 20 chars with Shannon entropy ≥ 4.0 bits/char, appearing in an assignment or config value context | Low–Medium |
| SECRET-007 | Regex | Private key block headers (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`) present in a tracked file | High |
| SECRET-008 | File-pattern | `.env` file present and tracked in git (not `.gitignore`d) | Medium |

**Redaction rule (mandatory, applies to all SECRET-* findings):** the detected value is immediately reduced to `<first_2_chars>****<len>****<last_2_chars>` before being written to any artifact, prompt, or report. The raw value is held only in-memory for the duration of the single detection call and is never logged.

**LLM confirmation:** SECRET-001, 002, 003, 007 (`llm_confirmation_required: false`) — format is unambiguous. SECRET-004, 005, 006, 008 go through confirmation to filter placeholders/examples/test fixtures (e.g., `"password": "changeme"` or docs examples).

---

## 4. Cross-Site Scripting (XSS)

| ID | Match Type | Pattern (conceptual) | Languages | Confidence |
|---|---|---|---|---|
| XSS-001 | AST | React `dangerouslySetInnerHTML` with a value derived from props/state not passed through a sanitizer | JS/TS (React) | High |
| XSS-002 | AST | Direct DOM write (`innerHTML =`, `document.write()`) with a non-literal (variable) right-hand side | JavaScript | High |
| XSS-003 | AST | Server-rendered template with autoescaping explicitly disabled (`{{ var|safe }}` in Jinja2, `<%- var %>` in EJS) | Python (Flask/Jinja2), Node (EJS) | High |
| XSS-004 | Regex | Flask `render_template_string()` called with request data concatenated into the template string itself | Python | High |

**Confirmation prompt focus:** trace whether the rendered value originates from user-controllable input (query/body/header) and whether any sanitization function appears between source and sink.

**Non-vulnerable pattern:** default-escaped template rendering (`{{ var }}` in Jinja2 without `|safe`), use of a sanitizer library (`DOMPurify`, `bleach.clean()`) before render.

---

## 5. Broken Authentication (AUTH)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| AUTH-001 | AST | Password compared with `==` / stored directly instead of via a hashing library call (`bcrypt`, `argon2`, `werkzeug.security`) | High |
| AUTH-002 | AST | Password hashed with a known-weak algorithm (`md5`, `sha1` used directly on a password field) | High |
| AUTH-003 | AST/Regex | Login/auth route with no rate-limiting decorator/middleware detected in the route's call chain | Medium |
| AUTH-004 | AST | Session cookie set without `HttpOnly` and/or `Secure` flags in a login/session-creation function | Medium |
| AUTH-005 | Regex | JWT signed with `alg: none` or a hardcoded/weak symmetric secret under 16 chars | High |
| AUTH-006 | AST | Session/auth token generated via non-cryptographic RNG (`random.random()`, `Math.random()`) instead of `secrets`/`crypto.randomBytes` | High |

**Confirmation prompt focus:** confirm the flagged function is genuinely part of the authentication surface (uses the ingestion module's auth surface map as a hint) rather than an unrelated password-like field (e.g., a "password strength checker" utility with no storage/comparison implication).

---

## 6. Insecure Deserialization / SSRF (DESER / SSRF)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| DESER-001 | AST | `pickle.loads()` / `yaml.load()` (without `SafeLoader`) called on data from an external source (request body, file upload) | High |
| DESER-002 | AST | JS `eval()` or `Function()` constructor called with any non-literal input | High |
| SSRF-001 | AST | HTTP client call (`requests.get`, `fetch`, `axios.get`) where the URL/host portion is built from unvalidated user input, with no allowlist check preceding it | Medium |
| SSRF-002 | Regex | Webhook/callback URL fields accepted from request body and used directly in a server-side outbound request | Medium |

**Confirmation prompt focus:** for SSRF, check whether any allowlist/domain-validation logic exists between input and the outbound call.

---

## 7. Misconfigurations (CONFIG)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| CONFIG-001 | Regex | `DEBUG = True` (Django/Flask) or `NODE_ENV` not set to `production` in a deployment-facing config | High |
| CONFIG-002 | AST/Regex | CORS configured with `Access-Control-Allow-Origin: *` alongside `Allow-Credentials: true` | High |
| CONFIG-003 | Regex | Missing common security headers in middleware setup (`Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`) — flagged only if no security-headers middleware (e.g., `helmet`, `flask-talisman`) is detected anywhere in the app | Medium |
| CONFIG-004 | Regex | `.env` / config values for DB connection strings with no SSL/TLS enforcement flag | Low |

---

## 8. Log & Traffic Analyzer Rules (EXT)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| LOG-001 | Rule (windowed count) | ≥ 5 failed login responses (401/403 on auth endpoint) from the same IP within 60s | High |
| LOG-002 | Rule (windowed count) | ≥ 3 different usernames attempted from the same IP within 5 minutes (credential stuffing pattern) | Medium |
| LOG-003 | Rate baseline | Request rate from a single IP exceeding 5× the rolling median for that path | Medium |
| LOG-004 | Rule | Access to known-sensitive paths (`/admin`, `/.env`, `/.git`, `/wp-admin`) returning non-404 | High |

---

## 9. Cloud Config Auditor Rules (EXT)

| ID | Match Type | Pattern (conceptual) | Confidence |
|---|---|---|---|
| CLOUD-001 | JSON/YAML rule | S3-style bucket policy with `"Principal": "*"` and an `Allow` effect | High |
| CLOUD-002 | JSON rule | IAM policy statement with `"Action": "*"` and `"Resource": "*"` combined | High |
| CLOUD-003 | Config rule | Storage resource block with no `encryption` / `server_side_encryption` field set | Medium |
| CLOUD-004 | File-pattern | `.env` referencing production credentials committed alongside IaC files in the same repo | Medium |

---

## 10. Rule Engine Behavior Notes

- **Deduplication:** if two rules fire on the exact same `(file, line_start, line_end)` span, only the highest-confidence rule's finding is kept; the other is logged as a suppressed duplicate in the appendix.
- **Confidence → LLM routing:** `high` confidence findings still go through LLM confirmation (per FR2.3) but with a lighter-weight prompt (verify, don't re-derive); `low`/`medium` confidence findings get the full reasoning prompt with taint-tracing.
- **Extensibility:** new rules are added as YAML entries following the schema in §1; the rule engine loader does not require code changes to add a pattern-only rule (AST rules requiring new query logic do require a small Python matcher function).
- **False positive suppression list:** a project-level `.security-ignore` file (analogous to `.gitignore`) allows maintainers to suppress specific `(file, line, rule_id)` tuples with a required justification comment — suppressions are listed in the report appendix, never silently dropped.
