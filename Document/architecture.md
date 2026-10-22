# Architecture Document
## Autonomous Cybersecurity Analyst AI

---

## 1. High-Level Architecture

```
                        ┌─────────────────────────────────────────────────────────┐
                        │                     ORCHESTRATOR                        │
                        │        (pipeline controller / state machine)            │
                        └─────────────────────────────────────────────────────────┘
                                │            │             │            │
                ┌───────────────┘            │             │            └───────────────┐
                ▼                             ▼             ▼                            ▼
     ┌─────────────────────┐   ┌─────────────────────┐   ┌──────────────────┐   ┌──────────────────┐
     │  1. INGESTION        │   │ 2. DETECTION LAYER  │   │ 3. REASONING &   │   │ 4. REPORTING      │
     │     MODULE           │──▶│  (SAST + Secrets)   │──▶│    PATCH ENGINE  │──▶│    MODULE         │
     └─────────────────────┘   └─────────────────────┘   └──────────────────┘   └──────────────────┘
                │                        │                          │                     │
                ▼                        ▼                          ▼                     ▼
        Repo Sandbox /            Findings Store              LLM API (Groq)        Markdown/PDF/HTML
        AST + Symbol Map          (SQLite/JSON)                + Prompt Templates    report artifact

     ┌─────────────────────┐   ┌─────────────────────┐
     │ EXT. Log & Traffic   │   │ EXT. Cloud Config    │
     │      Analyzer        │   │      Auditor         │
     └─────────────────────┘   └─────────────────────┘
                │                          │
                └───────────► Findings Store ◄───────────┘
```

The system is a **linear pipeline with a shared findings store**, not a fully agentic/autonomous loop. This is a deliberate design choice (see §7 — Design Rationale): each stage has a bounded, auditable responsibility, and the LLM is scoped to reasoning/generation tasks rather than open-ended tool use over the target repo. This keeps the system safe (no arbitrary code execution), debuggable, and demoable within project constraints.

---

## 2. Module Breakdown

### 2.1 Ingestion Module (CORE)

**Responsibility:** Turn an arbitrary repo into a structured, queryable representation.

**Components:**
- `RepoFetcher` — clones a Git URL (shallow clone) or accepts a local path; copies into an isolated sandbox dir under `/sandbox/<run_id>/`
- `LanguageDetector` — inspects file extensions + manifest files (`package.json`, `requirements.txt`, `pyproject.toml`) to determine stack
- `ASTBuilder` — wraps `tree-sitter` grammars (Python, JS/TS at minimum) to parse each source file into an AST
- `SymbolMapper` — walks ASTs to build:
  - **Route map**: HTTP route definitions → handler functions (Flask `@app.route`, Express `app.get/post`, Django `urls.py`)
  - **DB call map**: functions that construct/execute SQL or ORM queries
  - **Auth surface map**: login/session/password-handling functions
- `FileIndex` — flat index of all files with metadata (path, language, size, hash) for the secrets scanner and reporting

**Output artifact:** `ingestion_manifest.json` — file list, detected stack, route map, DB call map, auth surface map. This is the shared context object passed to downstream stages.

**Failure handling:** Per-file parse failures are logged and the file falls back to regex-based scanning only; the pipeline does not halt.

---

### 2.2 Detection Layer (CORE)

Two parallel sub-scanners, both consuming the ingestion manifest + raw source.

**A. Static Vulnerability Scanner**
- Rule + pattern engine (see `rules.md` for the full rule catalog)
- For each rule, runs either:
  - an **AST-based matcher** (preferred — e.g., "call to `db.execute()` where argument is a `BinaryExpression` with `+` on a string literal and a variable" → SQLi candidate)
  - a **regex-based matcher** (fallback for unparsed files or simple patterns)
- Targets: SQL Injection, XSS, SSRF, Insecure Auth, Weak Crypto, Misconfigurations
- Emits **candidate findings** (unconfirmed) — file, line range, rule ID, matched snippet

**B. Secrets & Credential Scanner**
- Runs independently over the full file index (not just source files — also `.env`, config files, YAML)
- Two detectors combined:
  - **Regex detector**: known key formats (AWS `AKIA...`, GitHub tokens, JWT structure, generic `API_KEY=` assignments)
  - **Entropy detector**: Shannon entropy over candidate string literals/assignment values above a threshold, to catch unlabeled high-entropy secrets
- Emits candidate findings with the secret **value redacted** (only first/last 2 chars + length retained) before it ever leaves this module

**Output artifact:** `candidate_findings.json` — deduplicated list of candidate findings tagged by source scanner and rule ID.

---

### 2.3 Reasoning & Patch Engine (CORE)

**Responsibility:** Turn candidate findings into confirmed, explained, patchable findings. This is the only module that calls the LLM.

**Pipeline per candidate finding:**
1. **Context assembly** — pull the minimal code window (function containing the finding + immediate callers if resolvable from the symbol map), capped at a token budget
2. **Confirmation call** — LLM is prompted with the rule that fired + code context, asked to confirm/reject as a true positive, with brief reasoning (structured JSON output)
3. **If confirmed:**
   - **Severity scoring call** — CVSS-inspired scoring (Attack Vector, Complexity, Privileges Required, Impact) reduced to a practical 0–10 scale + Critical/High/Medium/Low bucket
   - **Patch generation call** — LLM proposes a unified diff fixing the specific issue, plus a plain-English explanation (root cause + why the fix works)
   - **Patch validation** — generated diff is checked for: valid diff syntax, applies cleanly against the sandboxed file, passes a language-appropriate syntax check (`ast.parse` for Python, a JS parser for JS/TS). If validation fails, the finding is kept but marked `manual_review_required` with no patch attached
4. **If rejected:** finding is dropped from the confirmed set but retained in an `fp_log.json` for false-positive-rate reporting

**Batching/cost control:** confirmation calls are batched (multiple small findings per call where they share file context) to control token spend; patch generation calls remain 1:1 with confirmed findings since patches need focused context.

**Output artifact:** `confirmed_findings.json` — severity, explanation, patch diff (or `manual_review_required` flag), citation of triggering rule.

---

### 2.4 Reporting Module (CORE)

**Responsibility:** Deterministic rendering of `confirmed_findings.json` into a human-readable artifact.

- Sorts findings by severity (Critical → Low), then by file path
- Renders: executive summary (counts by severity/class), per-finding sections (description, location, explanation, diff block), appendix (files scanned, rules applied, scan duration, FP count)
- Output formats: Markdown (canonical) → converted to HTML and PDF via a render step (e.g., Pandoc or a headless-browser print for HTML→PDF)

---

### 2.5 Extension: Log & Traffic Analyzer (EXT)

- `LogParser` — normalizes common formats (Apache/Nginx combined log format, JSON app logs) into a common event schema (`timestamp, ip, path, method, status, user_id?`)
- `AnomalyDetector`:
  - Rule-based: N failed logins from same IP/user within window → brute-force candidate
  - Rate-based: request rate per IP/path exceeding a rolling baseline → anomalous traffic candidate
- Findings feed into the same `candidate_findings.json` schema (tagged `source: log_analyzer`) so they flow through the same reasoning/reporting stages

### 2.6 Extension: Cloud Config Auditor (EXT)

- `ConfigParser` — parses `.env` files, JSON/YAML IAM policy documents, basic Terraform resource blocks
- `BaselineRuleset` — checks: public bucket ACL/policy, wildcard (`"*"`) IAM actions/resources, missing encryption-at-rest flags, debug/permissive CORS settings in app configs
- Findings feed into the same shared pipeline as above

---

## 3. Data Flow & Storage

| Artifact | Produced by | Consumed by | Format |
|---|---|---|---|
| `ingestion_manifest.json` | Ingestion | Detection, Reasoning | JSON |
| `candidate_findings.json` | Detection, Log Analyzer, Cloud Auditor | Reasoning | JSON |
| `confirmed_findings.json` | Reasoning | Reporting | JSON |
| `fp_log.json` | Reasoning | Metrics/reporting appendix | JSON |
| Final report | Reporting | End user / jury | Markdown, HTML, PDF |

**Persistence:** SQLite for run history (multiple scans over time, useful for a "trend" view if time permits) with JSON blobs for the artifacts above. No persistent storage of raw secret values — only redacted representations.

---

## 4. Orchestrator / Control Flow

The orchestrator is a simple **linear state machine**, not an agent with free tool access:

```
INGEST → DETECT → REASON → REPORT
   │        │         │        │
   ▼        ▼         ▼        ▼
 [fail]  [fail]    [fail]   [fail]
   │        │         │        │
   └────────┴─────────┴────────┴──▶ run marked PARTIAL, best-effort output still produced
```

Each stage writes its artifact to disk before the next stage begins, so the pipeline is resumable and each stage is independently testable/debuggable — important given the phased development approach (see `phases.md`).

**Why not a fully autonomous agent loop (e.g., LangGraph ReAct-style with repo-editing tools)?**
- Predictability: a jury needs to see *why* something was flagged; a bounded pipeline is auditable, an open-ended agent loop is not
- Safety: no arbitrary code execution against the ingested repo is ever required
- Cost/time: bounded LLM calls per finding vs. unbounded exploration
- This can be noted explicitly as a design decision during the jury Q&A (see `design.md §6`)

---

## 5. Technology Stack

| Layer | Technology | Rationale |
|---|---|---|
| Language (pipeline) | Python 3.11+ | Rich ecosystem for AST tooling, LLM SDKs, entropy calc |
| AST parsing | `tree-sitter` + language grammars (Python, JavaScript, TypeScript) | Language-agnostic, fast, well-supported |
| Regex fallback | Python `re` | Simple, no dependency overhead |
| LLM | Groq (openai/gpt-oss-120b) | Structured output support, high throughput, free tier |
| Findings store | SQLite | Zero-ops, sufficient for single-machine demo |
| Report rendering | Markdown → Pandoc (PDF) / simple HTML template | Lightweight, no heavy report-engine dependency |
| CLI / entrypoint | `click` or `argparse` | Simple CLI for `scan <repo>` commands |
| Optional UI | Minimal Next.js or Streamlit dashboard | Only if time permits post-core-pipeline; not required for MVP |
| Secrets detection | Regex rules + custom entropy calculator | No need for a heavyweight third-party secret-scanning dependency, keeps it explainable |

---

## 6. Security & Safety Boundaries of the Tool Itself

Since this tool ingests third-party/user source code, the tool's own architecture must not become an attack surface:

- **No execution of ingested code** — ingestion is parse-only (tree-sitter parsing does not execute code)
- **Sandboxed filesystem access** — all cloned/copied repo content lives under a dedicated `sandbox/<run_id>/` directory with no write access back to the tool's own source
- **Secret redaction boundary** — raw secret values never cross into LLM prompts or the final report; only redacted forms (`AKIA****...**34`, length, detection rule) do
- **LLM prompt injection awareness** — since file contents (potentially attacker-controlled, e.g., a malicious README or code comment) are placed into LLM prompts, prompts are structured to clearly delimit "untrusted repo content" from "system instructions," and the LLM's output is only ever used as structured data (JSON findings, diff text) — never as new instructions to the orchestrator

---

## 7. Design Rationale (Static+LLM Hybrid vs. Alternatives)

| Approach | Why not chosen as the sole approach |
|---|---|
| Pure rule-based SAST (like Semgrep alone) | High false-positive rate on real code; no plain-English explanation or patch generation |
| Pure LLM (feed whole repo, ask "find vulnerabilities") | No structural guarantees on recall; expensive; findings not traceable to a concrete rule; hallucination risk with nothing to gate against |
| **Hybrid (chosen)** | Rule/pattern engine provides recall + auditability (every finding traces to a rule); LLM provides precision improvement (confirmation step), explanation quality, and patch generation — the parts LLMs are genuinely good at |

This hybrid design is the central technical narrative for the jury presentation: **static analysis proposes, LLM reasons and disposes.**
