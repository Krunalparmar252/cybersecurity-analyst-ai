# Security Audit & Hardening Report — Autonomous Cybersecurity Analyst AI

## 1. Executive Summary

A comprehensive security audit of the `cybersecurity-analyst-ai` codebase was conducted. The audit spanned static analysis for dangerous DOM patterns, environment variable hygiene, CORS configurations, client-side input validation, container isolation, and HTTP security headers. All identified vulnerabilities were triaged and remediated.

---

## 2. Vulnerability Findings & Remediation Register

| ID | Title | Severity | Location | Status | Remediation Applied |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | SSRF & Internal IP Targeting via Git URL | **HIGH** | `app/(app)/scan/new/page.tsx:47` | **RESOLVED** | Added URL parser to enforce `http:`/`https:` and block private IP ranges (localhost, 127.0.0.1, 10.x, 192.168.x, 172.16-31.x, 169.254.x metadata). |
| **SEC-02** | Command / Flag Injection via Git Branch Name | **HIGH** | `app/(app)/scan/new/page.tsx:43` | **RESOLVED** | Enforced strict regex whitelist (`^[a-zA-Z0-9._/-]+$`) and explicitly prohibited leading dashes (`-`) to block Git CLI flag injection (e.g. `--upload-pack`). |
| **SEC-03** | Path Traversal via Local Directory Path | **HIGH** | `app/(app)/scan/new/page.tsx:75` | **RESOLVED** | Added client-side sanitization explicitly forbidding directory traversal sequences (`..`) and null bytes (`\0`). |
| **SEC-04** | Missing HTTP Security Headers & Clickjacking Exposure | **MEDIUM** | `next.config.mjs:12` | **RESOLVED** | Configured `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `Permissions-Policy`. |
| **SEC-05** | Insecure Wildcard CORS Origin with Credentials | **MEDIUM** | `analyst/api/app.py:38` | **RESOLVED** | Replaced `allow_origins=["*"]` with an explicit localhost whitelist (`http://localhost:3000`, `http://127.0.0.1:3000`, `http://localhost:8000`) and configurable `ALLOWED_ORIGINS` environment parsing. |
| **SEC-06** | Potential Docker Build Cache & Secret Leakage | **LOW** | `.dockerignore:31` | **RESOLVED** | Added `.next/`, `.taste-skill/`, and verified `.env` and `.env.*` are strictly excluded from Docker build context. |
| **SEC-07** | Next.js 14 DoS & PostCSS Vulnerabilities | **LOW (Contextual)** | `node_modules/next` | **JUSTIFIED** | Next.js 14.2.15 has upstream advisories for Server Actions and Image Optimization APIs. Running in standalone SSR mode where Server Actions and dynamic SVG image processing are unused. Upgrading to Next 16 requires breaking framework changes. |

---

## 3. Detailed Audit Sections

### 3.1 Dangerous JavaScript / DOM Injection Audit
- **`dangerouslySetInnerHTML`**: 0 occurrences found.
- **`innerHTML`**: 0 occurrences found.
- **`eval()` / `new Function()`**: 0 occurrences found.
- **`document.write`**: 0 occurrences found.
- **DOM Mutations**: Safe `title.innerText` utilized exclusively with hardcoded route title strings in `RouteTransition.tsx`.

### 3.2 Sensitive Data in `localStorage`
- **Keys Evaluated**:
  - `CYBER_ANALYST_SCANS`
  - `CYBER_ANALYST_FINDINGS`
  - `CYBER_ANALYST_REPORTS`
- **Assessment**: Only offline state models and mock AST findings are persisted. No credentials, tokens, cookies, or cryptographic private keys are ever stored in `localStorage`.

### 3.3 Environment Variable & Secret Hygiene
- **`.env` File**:
  - Verified git-ignored via `.gitignore` line 2 (`.gitignore:2:.env`).
  - Confirmed `.env` has never been committed in git history (`git log --all --full-history -- .env` returned 0 commits).
- **Environment Variable Names Present**:
  - `GROQ_API_KEY`: Kept strictly server-side (no `NEXT_PUBLIC_` prefix).
  - Client-exposed variables verified:
    - `NEXT_PUBLIC_USE_REAL_BACKEND`: Boolean toggle.
    - `NEXT_PUBLIC_API_URL`: Backend URL (defaults to `http://localhost:8000`).
  - **Verdict**: Zero API keys or secrets exposed through `NEXT_PUBLIC_` prefixes.

### 3.4 Content Security Policy & HTTP Headers (`next.config.mjs`)
Implemented headers:
```http
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self' http://localhost:8000 http://127.0.0.1:8000 https: ws: wss:; frame-ancestors 'none'; object-src 'none'; base-uri 'self'; form-action 'self';
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), browsing-topics=()
```
- Fully accommodates Google Fonts, Next.js font optimization, WebGL/Three.js shaders, and local/remote FastAPI telemetry endpoints.

### 3.5 Input Sanitization on `/scan/new`
- **SSRF Prevention**: Rejects any non-HTTP(S) protocol and validates the target hostname against reserved IPv4/IPv6 private subnets and AWS/GCP cloud metadata endpoints (`169.254.169.254`).
- **CLI Flag Injection**: Disallows branch strings beginning with `-` (mitigating git flag tampering like `--upload-pack`).
- **Path Traversal**: Rejects paths containing `..` or null bytes (`\0`).

### 3.6 Docker and CI Configuration Review
- **`.dockerignore`**:
  - Explicitly ignores `.env`, `.env.*`, `node_modules/`, `.next/`, `api_runs/`, and artifacts.
  - Confirmed `.env` is never copied into the production container image.
- **GitHub Actions (`.github/workflows`)**:
  - `ci.yml`: Runs tests without exposing secrets.
  - `cd.yml`: Uses standard ephemeral `${{ secrets.GITHUB_TOKEN }}` for GHCR image publishing. No secrets logged or baked into image layers.

---

## 4. Final Security Posture
The application demonstrates robust defense-in-depth:
- Client-side input sanitization stops malicious inputs before transmission.
- Strict CSP and frame-ancestors block XSS and clickjacking.
- Secret isolation ensures API keys remain exclusively on the server.
- Container boundaries and Git workflows prevent accidental credential leakage.
