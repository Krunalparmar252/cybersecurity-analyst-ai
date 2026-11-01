# Design / Architecture — Autonomous Cybersecurity Analyst AI

This file describes HOW the system is built. Treat it as ground truth for
existing code — if something in the repo contradicts this file, trust the
repo and flag the mismatch in log.md rather than guessing.

## 1. High-level pipeline

```
INGEST -> DETECT -> REASON -> REPORT
              ^         |
              |         v
          (rule.recheck)  (exploit.verify, new)
```

All coordinated by an ORCHESTRATOR (LangGraph graph in
`analyst/orchestrator/graph.py` + `analyst/orchestrator/pipeline.py`).

Agents do not call each other's Python functions directly. They communicate
only through the message bus described below. This is the project's "A2A"
(agent-to-agent) layer — a custom protocol, not an external standard.

## 2. Package layout

```
analyst/
  api/            FastAPI surface
  common/         shared types (growing — see implementation-plan.md task A2)
  detection/      DETECT agent (AST + regex rules, rule.recheck)
  exploitation/   NEW — exploit verification agent (this is what we're building)
  ingestion/      INGEST agent, manifest + salted digests
  orchestrator/   pipeline.py, graph.py — wires everything together
  protocol/       bus.py, envelope.py, crypto.py — the A2A + integrity layer
  reasoning/      REASON agent: engine.py, patch_loop.py, fallback.py,
                  confidence.py
  reporting/      REPORT agent — renders markdown + integrity sidecar
  triage/         triage logic
```

## 3. Protocol layer (`analyst/protocol/`)

- `envelope.py` — `AgentMessage` Pydantic model: protocol_version, message_id,
  correlation_id, causation_id, run_id, sender, receiver, message_type,
  payload_type, payload, created_at, ttl_seconds, integrity block. All
  payload schemas use `extra="forbid"`. `to_legacy_dict()` gives
  `{agent, decision, reason, timestamp}` for backward compatibility.
- `bus.py` — capability-routed, in-process, synchronous message bus. Agents
  register capabilities (e.g. `rule.scan`, `rule.recheck`, `patch.reasoning`,
  `report.render`, and soon `exploit.verify`). Admission gates on every
  message: run_id match, TTL check, replay protection (message_id is
  single-use), payload digest check, signature check. Failures go to dead
  letters, not silently dropped. Capability announcements are transcript-only
  (not pushed to `on_message`, to avoid flooding subscribers).
- `crypto.py` — `SaltContext` (per-run salt derivation), tagged digest format
  `v1:mode:epoch:hex`, two hash modes (`sha256-salt-prefix` default,
  `hmac-sha256` via `ANALYST_HASH_MODE` env var), hash-chained `AuditLog`.

## 4. Detection (`analyst/detection/agent.py`)

- SQLi: AST-based taint analysis via tree-sitter.
- XSS / secrets: regex-based.
- Regex fallback when a file fails AST parsing.
- `recheck_rule(sandbox_root, rel_file, rule_id)` — used by the patch loop to
  verify whether a rule still fires after a patch.
- `handle_message` — serves `rule.recheck` over the bus. Fails CLOSED:
  if recheck can't run cleanly, returns INDETERMINATE with `still_fires=True`
  (never silently assumes a patch worked).

## 5. Reasoning / patching (`analyst/reasoning/`)

- `engine.py` — `analyze_finding(finding, source, client, breaker, on_fallback,
  sleep_fn)`, tiered `_invoke_with_retry`. `ConfirmedFinding` carries
  `analysis_tier` and `fallback_trigger`.
- `fallback.py` — `FailureClass`, `classify_llm_error`, `CircuitBreaker`,
  `backoff_delay` (exponential + full jitter), `local_confirm`,
  `deterministic_patch` templates, `manual_review_advice`,
  `deterministic_analysis`, `manual_review_finding`, `FallbackOutcome`.
  THIS is the pattern the new exploit module's own fallback tier should
  follow — do not invent a parallel mechanism.
- `patch_loop.py` — propose -> act (sandbox copy) -> observe (rule.recheck
  over bus) -> decide. `MAX_ATTEMPTS = 2`. `ChatGroq` is constructed INSIDE
  this module's own namespace (not imported from a shared client factory) —
  this is intentional, it's the test mock seam
  (`analyst.reasoning.patch_loop.ChatGroq`). Do not refactor this away.
  Also contains `_make_sandbox_copy` (reusable for the exploit module's
  sandboxing), `apply_patch_to_text`, `handle_message` (negotiation
  endpoint), `STATUS_*` constants, `HUMAN_ATTENTION_STATUSES`,
  `PeerValidationUnavailable` (raised when verification is attempted with
  `bus=None` — peer validation is bus-only, by design).
- `confidence.py` — `diff_scope_check` with an import-line exemption regex
  (`_IMPORT_LINE`) so patches that add an import aren't automatically scored
  "unverified".

## 6. Reporting (`analyst/reporting/`)

- Counts `MANUAL_REVIEW_REQUIRED` findings.
- Shows a degraded-run banner/note when any fallback tier fired.
- Shows per-finding analysis tier.
- Default safe remediation advice text when no patch was produced.

## 7. Orchestrator (`analyst/orchestrator/`)

- `pipeline.py` / `graph.py` — bus-based. Builds a `SaltContext` and
  `AuditLog` per run. `_build_bus()` wires up all agents' capabilities.
  `PipelineResult` carries run_id, integrity info, fallback list,
  manual_review_count, protocol_messages. `offline` param disables live LLM
  calls. Verifies the full message transcript at the end of a run. Writes a
  report integrity sidecar and `audit_log.json`.

## 8. Exploit verification agent — design (NEW, being built now)

Full requirements in requirements.md section 3. Architectural decisions:

- Lives in `analyst/exploitation/agent.py`, new package, mirrors the shape
  of `analyst/detection/agent.py` (a `handle_message` entrypoint serving one
  capability).
- Capability: `exploit.verify`. Request/response pattern mirrors the
  existing `rule.recheck` flow (ORCHESTRATOR sends request after patch
  acceptance, waits for response, attaches result to the finding).
- Agent loop implementation: LangGraph ReAct-style tool-calling loop (same
  library already used for the orchestrator graph — no new dependency).
- Tool-calling, NOT direct code execution by the LLM. The LLM only ever says
  "call tool X with input Y" — actual execution happens in plain Python,
  inside the sandbox. This is the core safety boundary of the whole module.
- Exactly 2 tools (see requirements.md 3.4) — deliberately minimal, no
  filesystem/network/shell access given to the agent.
- Sandbox: subprocess, copy of target code only (via `_make_sandbox_copy`,
  reused from `patch_loop.py`), no network, hard timeout.
- `ChatGroq` constructed in `analyst/exploitation/agent.py`'s own module
  namespace, same pattern as `patch_loop.py`, so it has its own test mock
  seam (`analyst.exploitation.agent.ChatGroq`).
- Fallback tier: reuses `fallback.py`'s circuit breaker / retry pattern for
  the LLM call; if unavailable, falls through to the fixed payload library
  and tags the result `STATIC_CHECK_ONLY` — this mirrors T3 in the existing
  fallback design, not a new concept.
- Deadlock prevention: three independent timeouts, not one (see
  requirements.md 3.4). A per-LLM-call timeout (~15-20s, via the Groq
  client's own request-timeout setting) is what actually prevents the loop
  from hanging — the LLM waiting on the agent and the agent waiting on the
  LLM is only possible if the underlying network call has no timeout of its
  own. The per-tool sandbox timeout and the overall 5-call/60s budget are
  both necessary but NOT sufficient on their own.
- New Pydantic schemas added to `analyst/protocol/envelope.py` alongside the
  existing 9 payload types, same conventions (`extra="forbid"`).

## 9. Known constraints / do-not-change list

- Do not remove or weaken `PeerValidationUnavailable` / bus-only patch
  verification (task A1, already completed and tested).
- Do not change the `ChatGroq`-in-module-namespace pattern in
  `patch_loop.py` — tests depend on mocking it at that exact path.
- Do not alter the legacy `to_legacy_dict()` projection format.
- Do not commit `.venv/` — confirm `.gitignore` covers it (fixed once
  already, re-check if venv issues recur).
- Never log, print, or commit secrets/API keys. `.env` must stay out of git.

### 9. Incremental scanning — design (Track C, new)

- New module: `analyst/ingestion/scan_cache.py` — handles reading/writing
  `.analyst_cache/last_scan.json`, schema validation, and the
  changed-files-via-git-diff logic. Keep this separate from the manifest
  code (`analyst/ingestion/manifest.py`) — the manifest is about integrity
  of THIS run, the scan cache is about comparing TO a PREVIOUS run. Don't
  merge the two concepts.
- `get_changed_files(repo_root, last_commit) -> ChangedFileSet` — a plain
  function wrapping `git diff --name-only` + `git status --porcelain`
  subprocess calls. Returns three sets: added, modified, deleted. If
  `last_commit` is None, or the subprocess call fails (not a git repo,
  git not installed), return a sentinel meaning "do a full scan" — the
  caller decides what to do with that, this function never decides to
  silently do nothing.
- Orchestrator (`pipeline.py`/`graph.py`) gains an `incremental: bool` param
  (mirrors the existing `offline` and `dynamic` params). When true, it reads
  the cache (if present), computes the changed set, and passes it down to
  DETECT so DETECT only runs its rule scan on that subset. Findings for
  files outside that set are pulled from the cache and merged into the
  result with `scan_mode="carried_forward"`.
- REASON/EXPLOIT check `scan_mode` + whether a finding was already resolved
  in the cache before deciding whether to re-run — this is where the actual
  LLM-call savings come from.
- At the end of a run, write the updated cache (current HEAD commit +
  merged findings) — same place regardless of whether the run was
  incremental or full, so a full run also refreshes the baseline for next
  time.
- CLI: new `--incremental` flag in `analyst/__main__.py`, off by default,
  same pattern as `--offline`/`--dynamic`.

---