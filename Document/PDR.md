# Product Design Requirements (PDR)
## Autonomous Cybersecurity Analyst AI

**Team:** Krunal Parmar (23CP044) · Sumit Trapasiya (23CP070) · Rushi Divecha (23CP201)
**Type:** Final Year Project — Cybersecurity / AI
**Doc status:** v1.0

---

## 1. Problem Statement

AI coding assistants and "vibe coding" workflows let individuals and small teams ship functional web applications in hours. The step that gets skipped is security review. Common, recurring failure patterns:

- Login/auth pages shipped with default or weak validation
- Raw SQL built via string concatenation → SQL injection
- Unsanitized input rendered directly to the DOM → XSS
- API keys and DB passwords hardcoded and pushed to public repos
- Cloud storage/configs left with public or overly permissive access

**Why it matters:**
- Broken Access Control is the #1-ranked OWASP risk category, closely tied to weak login/auth flows
- 94% of tested applications show some form of broken access control (OWASP)
- Thousands of solo/student-built apps reach production with zero security review

**Core insight:** The gap isn't awareness of best practices — it's that *no one reviews the code before it ships*. This is fundamentally a bandwidth problem, not a knowledge problem, and it is well suited to automation.

---

## 2. Product Vision

> A security review that never sleeps — and never skips the login page.

An AI-driven security analyst that ingests a codebase (and optionally logs / cloud configs), detects vulnerabilities using a combination of static analysis and LLM reasoning, and produces developer-ready fixes and severity-ranked reports — without a human security engineer in the loop.

---

## 3. Goals & Non-Goals

### 3.1 Goals
| # | Goal |
|---|------|
| G1 | Ingest a source code repository and build a structural understanding of it (AST, routes, DB call sites) |
| G2 | Detect the six target vulnerability classes with acceptable precision/recall for a static+LLM hybrid pipeline |
| G3 | Rank findings by severity using a CVSS-inspired scoring scheme |
| G4 | Generate a plain-English explanation and a proposed code patch (diff) per finding |
| G5 | Produce a single exportable report (Markdown/PDF/HTML) developers can act on directly |
| G6 | Extend coverage to runtime logs (brute-force/anomaly detection) and cloud config auditing as secondary modules |
| G7 | Run end-to-end on a real, non-trivial demo repo for the jury presentation with reproducible results |

### 3.2 Non-Goals (explicitly out of scope for this project)
- Automated exploitation / active penetration testing of live systems
- Auto-committing or auto-merging patches without human review
- Full dynamic application security testing (DAST) with live traffic fuzzing
- Coverage of every OWASP Top 10 category — the six listed classes are the committed scope
- Multi-tenant SaaS product hardening (auth, billing, RBAC for the tool itself) — this is a research/demo-grade system
- Support for compiled/binary-only artifacts (source access is assumed)

---

## 4. Target Users & Use Cases

| User | Use Case |
|---|---|
| Student / solo developer | Run the tool against their own repo before pushing to production; get a report before deploying a "vibe-coded" app |
| Small dev team without dedicated AppSec | Use as a pre-merge / pre-release gate to catch the most common, highest-impact issues |
| Academic jury / evaluators | Demo the pipeline end-to-end against a deliberately vulnerable sample app and inspect the generated report + patches |

**Primary demo scenario:** Point the tool at a small deliberately-vulnerable web app (e.g., a Flask/Express CRUD app with seeded SQLi, XSS, hardcoded secrets, and weak auth), run the full pipeline, and present the generated report + patch diffs live.

---

## 5. Scope Definition

### 5.1 Core modules (must-have, demo-critical)
1. **Code Ingestion & Parsing** — clone repo, build AST via tree-sitter, map files/routes/DB calls
2. **Static Vulnerability Scanner** — rule + pattern engine for SQLi, XSS, SSRF, insecure auth, weak crypto
3. **Secrets & Credential Scanner** — entropy + regex detection of API keys, tokens, hardcoded passwords
4. **LLM Reasoning & Patch Engine** — contextualizes findings, ranks severity (CVSS-style), drafts fixes

### 5.2 Extension modules (stretch, time-permitting)
5. **Log & Traffic Analyzer** — flags brute-force attempts, anomalous request patterns in app/server logs
6. **Cloud Config Auditor** — checks IAM policies, storage buckets, env files against baseline rules

### 5.3 Vulnerability class coverage (committed)

| Severity | Class | Description |
|---|---|---|
| Critical | SQL Injection | Unparameterized queries, string-concatenated SQL in ORM/raw calls |
| Critical | Hardcoded Secrets | API keys, DB credentials, JWT secrets committed in source or `.env` |
| High | Cross-Site Scripting (XSS) | Unescaped user input rendered into HTML/JS without sanitization |
| High | Broken Authentication | Weak session handling, missing rate limits, plaintext password storage |
| Medium | Insecure Deserialization / SSRF | Untrusted input passed to deserializers or outbound request builders |
| Medium | Misconfigurations | Debug mode in production, permissive CORS, missing security headers |

---

## 6. Functional Requirements

**FR1 — Ingestion**
- FR1.1: Accept a Git URL or local path as input
- FR1.2: Clone/copy repo into an isolated sandbox directory
- FR1.3: Detect language/framework (initially: Python/Flask/Django, JS/TS/Express/Next.js)
- FR1.4: Parse source files into ASTs via tree-sitter
- FR1.5: Build a symbol/route/DB-call map (which files define HTTP routes, which functions touch the DB, which touch auth)

**FR2 — Detection**
- FR2.1: Run rule-based SAST checks against parsed AST + raw source (regex fallback)
- FR2.2: Run entropy-based + regex-based secret scanning across all text files, respecting `.gitignore`-style excludes plus a scanner-specific ignore list
- FR2.3: For each rule-based candidate finding, pass surrounding code context to the LLM for confirmation/rejection (reduce false positives)
- FR2.4: Deduplicate findings across scanners (same file+line+class)

**FR3 — Reasoning & Patch Generation**
- FR3.1: For each confirmed finding, generate: severity score (CVSS-inspired 0–10), a plain-English root-cause explanation, and a proposed patch as a unified diff
- FR3.2: Patch generation must preserve surrounding code style/formatting where feasible
- FR3.3: Flag any finding the LLM cannot confidently patch as "manual review required" rather than emitting a low-confidence patch

**FR4 — Reporting**
- FR4.1: Generate a single report (Markdown, exportable to PDF/HTML) with: executive summary, findings sorted by severity, per-finding detail (file, line, explanation, patch diff), and appendix of scanned files/rules applied
- FR4.2: Report must be reproducible — same repo + same commit → same findings (LLM non-determinism handled via low temperature + confirmation step)

**FR5 — Extension: Log Analysis**
- FR5.1: Accept app/server log files (common formats: Apache/Nginx access logs, JSON app logs)
- FR5.2: Flag repeated failed-auth patterns (brute force), anomalous request rate/paths

**FR6 — Extension: Cloud Config Audit**
- FR6.1: Parse common IaC/config formats (`.env`, basic Terraform/JSON IAM policy snippets, S3-style bucket configs)
- FR6.2: Check against a baseline ruleset (public bucket ACLs, wildcard IAM `*:*`, missing encryption flags)

---

## 7. Non-Functional Requirements

| Category | Requirement |
|---|---|
| Performance | Full pipeline run on a demo repo (~5–20k LOC) completes in under 10 minutes on standard dev hardware |
| Reliability | A single unparseable file or scanner failure must not crash the pipeline — degrade gracefully and report as "skipped" |
| Safety | No code from the ingested repo is ever executed; ingestion is static-only (parsing, not running) |
| Reproducibility | Deterministic ordering of findings; LLM calls use temperature ≤ 0.2 for detection/scoring |
| Cost control | LLM calls are batched/context-limited per finding, not per full file, to keep token spend bounded |
| Transparency | Every LLM-generated finding must cite the rule or heuristic that triggered the initial candidate |
| Data handling | No ingested source code, secrets, or logs are sent to third parties beyond the configured LLM API; secrets found are redacted/truncated before being included in any LLM prompt or report |

---

## 8. Success Metrics (for jury evaluation)

| Metric | Target |
|---|---|
| Detection recall on seeded vulnerable demo repo | ≥ 90% of seeded issues across the 6 classes found |
| False positive rate after LLM confirmation step | Demonstrable reduction vs. rule-engine-only output (report both numbers) |
| Patch usability | ≥ 70% of generated patches apply cleanly (valid diff, compiles/lints) on demo repo |
| End-to-end run time | < 10 min on demo repo |
| Report clarity | Jury can read one finding end-to-end (issue → why → fix) without needing verbal explanation |

---

## 9. Risks & Mitigations

| Risk | Mitigation |
|---|---|
| LLM hallucinates vulnerabilities that don't exist | Rule/pattern engine gates candidates first; LLM only confirms/explains/patches, never originates findings from scratch |
| LLM-generated patches break the app | Patches are diffs for human review only; never auto-applied; syntax-validated before inclusion in report |
| Secrets scanner leaks real secrets into LLM prompts or reports | Redact/hash secret values before they leave the local sandbox; only pass file/line/context, not the raw secret |
| Tree-sitter/parsing fails on unusual codebases | Regex-based fallback detectors for core vulnerability classes when AST parsing fails |
| Scope creep into full DAST / exploitation | Explicit non-goals section (§3.2); static-only ingestion enforced at the architecture level |
| Demo repo not representative | Curate a deliberately vulnerable demo app covering all 6 classes; validate detection before presentation day |

---

## 10. Deliverables for Jury Presentation

1. Working pipeline (CLI or minimal web UI) run live against a seeded demo repository
2. Generated report (PDF/HTML) with findings, severities, and patches
3. Architecture diagram + explanation of static+LLM hybrid design decision
4. Metrics table (detection recall, FP reduction, patch applicability, run time)
5. Discussion of extension modules (log analyzer, cloud config auditor) even if partially implemented
