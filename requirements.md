# Requirements — Autonomous Cybersecurity Analyst AI
  
## 1. Project Purpose
A final-year multi-agent system that scans a code repository for vulnerabilities,
proposes and validates patches, and (new) proves a patch actually closes the hole
by attempting to exploit the code before and after the fix.

## 2. Core Functional Requirements (already built — do not re-implement)

### 2.1 Ingestion
- Read a target repo/folder, produce a signed manifest of files scanned.
- Each file gets a salted digest; manifest has its own aggregate digest.
- Fails closed (status INSUFFICIENT) if manifest verification fails.

### 2.2 Detection
- SQL injection (SQLI-001): AST/taint analysis via tree-sitter.
- XSS (XSS-002): regex, keys on f-string + HTML tag shape.
- Hardcoded secrets (SECRET-005): regex.
- Additional rule IDs exist: CMDINJ-001, DESER-001, PATHTRAV-001.
- Falls back to regex-only scanning if a file fails to parse with tree-sitter.
- Every finding is tagged with `source_scanner`.
- Serves `rule.recheck` capability: re-run a single rule against a (possibly
  patched) file and report whether it still fires.

### 2.3 Reasoning / Patching
- LLM (Groq via langchain-groq) proposes a patch for a confirmed finding.
- Patch applied to a sandboxed copy, DETECT re-checks via `rule.recheck`.
- Loop up to MAX_ATTEMPTS = 2.
- Confidence tiers: verified_full / verified_narrow / unverified
  (via diff-scope check against the finding's location; import lines exempted).
- Tiered fallback on LLM/tooling failure (see fallback.py):
  - T0: normal LLM call
  - T1: retry with exponential backoff + full jitter, max 3 attempts,
    transient errors only (429 / timeout / connectivity / 5xx)
  - T2: circuit breaker (opens after 3 failures, or 1 for AUTH/QUOTA errors)
  - T3: deterministic local analysis — static severity table + fixed patch
    templates, Python-only, for SQLI-001 / XSS-002 / SECRET-005
  - T4: MANUAL_REVIEW_REQUIRED — no patch applied, safe remediation advice
    returned instead
  - System fails CLOSED on anything unverifiable (never silently accepts
    an unverified patch as safe).

### 2.4 A2A Protocol (agent-to-agent communication)
- Agents never call each other's functions directly — all communication goes
  through a capability-routed in-process message bus (`analyst/protocol/bus.py`).
- Every message is a signed, salted Pydantic envelope (`AgentMessage` in
  `analyst/protocol/envelope.py`): sender, receiver, message_type, payload,
  correlation_id, integrity block (algorithm, salt_fingerprint, payload_digest,
  signature, sealed_at).
- Bus admission gates: run_id match, TTL, replay protection (message_id
  single-use), payload digest check, signature check. Failed messages go to
  dead letters.
- 9 existing payload schemas, all `extra="forbid"`.
- Legacy projection (`to_legacy_dict()`) kept for backward compatibility:
  `{agent, decision, reason, timestamp}`.

### 2.5 Cryptographic integrity
- `SaltContext`: per-run salt = `sha256(v1 | pepper | run_id | nonce | epoch)[:32]`.
- Tagged digests: `v1:mode:epoch:hex`.
- Two hash modes: `sha256-salt-prefix` (default) and `hmac-sha256`
  (length-extension-safe), switchable via `ANALYST_HASH_MODE`.
- Ephemeral pepper unless `ANALYST_HASH_PEPPER` is set in the environment.
- Hash-chained audit log (`AuditLog`).
- Report gets a signed `.integrity.json` sidecar.

### 2.6 Reporting
- Renders markdown report with per-finding status, confidence tier, fallback
  tier used.
- Shows a degraded-run banner if any manual-review or fallback occurred.
- Counts MANUAL_REVIEW_REQUIRED findings separately.

### 2.7 Orchestration
- LangGraph graph: nodes `ingest`, `detect`, `negotiate`, `reason`, `report`,
  `skip_to_report`.
- LOW_SIGNAL findings can trigger a negotiation step (REASON may decline).
- `--offline` CLI flag for fully local/deterministic runs (no live LLM calls).

## 3. New Requirement — Exploit Verification Agent (in progress)

### 3.1 Problem being solved
"Patch verified" currently only means the detection rule stopped firing on the
patched code. That is a weak proof — e.g. the XSS-002 regex matches a specific
f-string shape, so a differently-shaped but still-unsafe rewrite could pass the
rule check while remaining exploitable.

### 3.2 Goal
Add a new agent that actually attempts to exploit the vulnerable code, black-box
style, before and after the patch, to produce real evidence the fix works —
not just that a rule stopped matching.

### 3.3 Scope (v1)
- Vulnerability classes: SQLI-001 and XSS-002 only.
- Target: `demo_app` only.
- Opt-in only, via `--dynamic` CLI flag (it executes code, must never run by
  default).
- Secrets (SECRET-005) are explicitly excluded — nothing to "exploit" there.

### 3.4 Functional requirements
- Black-box only: the agent gets payload-in / response-out. No source code
  access (no `read_snippet` tool in v1).
- Exactly 2 tools exposed to the LLM agent:
  1. `run_payload(payload: str) -> {status, response_body, error}` — executes
     against a sandboxed subprocess copy of the target code.
  2. `report_result(success: bool, payload_used: str, evidence: str) -> None`
     — ends the agent's loop.
- Timeout enforcement — THREE separate, independent timeouts are required.
  The 60-second budget below CANNOT enforce itself if a single blocking call
  inside the loop has no timeout of its own — this is the actual deadlock
  risk (LLM call hangs waiting on the network, loop never gets back to
  checking its own budget). All three must be implemented, not just the
  outer one:
  1. Per-LLM-call timeout: every call to Groq inside the agent loop must
     have a hard request timeout (e.g. 15-20 seconds). On timeout, treat it
     as a transient failure and route through the existing fallback/circuit
     breaker pattern from `fallback.py` — do not let the call block
     indefinitely.
  2. Per-tool-call timeout: `run_payload`'s sandboxed subprocess execution
     must have its own hard timeout (reuse the existing sandbox timeout
     pattern from `patch_loop.py`), independent of the LLM timeout, so a
     payload that hangs the target code doesn't freeze the loop either.
  3. Overall loop budget: max 5 tool calls OR 60 seconds wall-clock,
     whichever comes first, as the outer ceiling. On exceeding budget,
     auto-stop with verdict INCONCLUSIVE. This only works correctly once 1
     and 2 are in place — it is not a substitute for them.
- Three runs per finding:
  a. Against the ORIGINAL (pre-patch) code — expected success = True.
     If no working exploit is found here, flag the original finding as
     suspect (the detection may have been a false positive).
  b. Against the PATCHED code — expected success = False after exhausting
     budget.
  c. One benign/normal-input call against the patched code — must behave
     correctly (regression check: patch must not have broken functionality).
- Verdict enum: `CONFIRMED_VULNERABLE_THEN_FIXED` | `BYPASS_FOUND` |
  `INCONCLUSIVE` | `STATIC_CHECK_ONLY`.
- Fallback tier (same pattern as `fallback.py`): if the LLM/tooling is
  unavailable, use a fixed payload library instead of the agent loop, and
  always tag the result `STATIC_CHECK_ONLY`.
  - SQLI-001 payloads: `' OR '1'='1' --`, `1; DROP TABLE users--`,
    `' UNION SELECT NULL--`
  - XSS-002 payloads: `<script>alert(1)</script>`,
    `<img src=x onerror=alert(1)>`, `"><svg onload=alert(1)>`
- New Pydantic payload schemas: `ExploitVerifyRequestPayload`,
  `ExploitVerifyResultPayload`, following the existing envelope pattern
  (`extra="forbid"`), registered as valid payload types on the signed bus.
- New capability: `exploit.verify`, served by a new agent module
  `analyst/exploitation/agent.py`.
- Wiring: ORCHESTRATOR sends an `exploit.verify` request after a patch is
  accepted (same request/response pattern as the existing `rule.recheck`
  flow). Result attaches to the finding's record.
- Reporting: per-finding verdict shown, plus an aggregate line:
  "N/M findings verified by exploit vs static-only".

### 3.5 Non-functional requirements
- Sandbox isolation: subprocess execution, no network access, temp-directory
  copy only, hard timeout per call. Reuse `_make_sandbox_copy` from
  `patch_loop.py`.
- Must reuse the existing `ChatGroq`-constructed-in-module-namespace pattern
  from `patch_loop.py`, so it can be mocked the same way in tests.
- Must reuse the existing fallback-tier pattern from `fallback.py` rather
  than inventing a new one.
- No new LLM provider/API — stay on Groq, for consistency with the rest of
  the project.
- No new dependencies unless unavoidable (state why if one is added).
- Must never break existing tests. Full suite must stay green after every
  change (baseline: 126 passed, 0 failed, 29 harmless FutureWarnings from
  tree_sitter).

## 4. Out of scope (explicitly not doing)
- Command injection / path traversal / deserialization exploitation (future
  work, not v1).
- White-box exploitation (source-aware payload generation) — v1 is black-box
  only.
- A second LLM provider/API as a fallback.
- Training a custom ML model for exploit generation.
- Any live/network-facing execution — everything stays local and sandboxed.
