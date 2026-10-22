# Implementation Plan — Autonomous Cybersecurity Analyst AI

## How to use this file
Work one numbered step at a time, in order, inside a step follow:
PLAN (3-5 lines) -> IMPLEMENT -> VERIFY (run full test suite +
`python -m analyst scan demo_app --offline -o /tmp/r.md --artifacts /tmp/a`)
-> REPORT -> write an entry in log.md -> STOP and ask
"continue to next step?". Never skip ahead or batch multiple steps into one
change without explicit confirmation.

## Status snapshot (update this line whenever a step completes)
Last confirmed state: B-4 complete — 155 passed, 0 failed,
33 harmless warnings. Exploit module: step 4 of 5 complete (bus wiring in orchestrator/pipeline.py and orchestrator/graph.py).
Next: B-5 (Reporting and CLI flag).

---

## Track A — original 17-task improvement plan (pre-existing, partially done)

Status: A1 complete. A2-E4 not started. (If repo state disagrees with this,
trust the repo — check for evidence of completed work, e.g. existing files
matching a task's description, before assuming "not started".)

- [x] A1 — Bus-only patch validation cleanup. Removed direct
      `detection.agent.recheck_rule` import from `patch_loop.py`. Added
      `PeerValidationUnavailable` raised when `bus is None`. Added
      `tests/test_peer_validation_bus_only.py`.
- [ ] A2 — Move `ConfirmedFinding` + `HUMAN_ATTENTION_STATUSES` into a
      neutral module (e.g. `analyst/common/types.py`) with re-exports, so
      `reporting` no longer imports from `reasoning` directly.
- [ ] A3 — (Originally: parallel INGEST/DETECT.) SUPERSEDED by Track B
      (exploit verification agent) — do not implement the original A3 unless
      explicitly told to revisit it.
- [ ] A4 — Optional TRIAGE agent (lower priority, discuss before starting).
- [ ] B1-B3 — Detection coverage improvements (additional rules/classes).
- [ ] C1-C2 — Metrics.
- [ ] D1-D2 — Reporting: HTML + PDF output.
- [ ] E1-E4 — Packaging.

## Track B — Exploit Verification Agent (current priority)

Full spec: requirements.md section 3, design.md section 8.

- [x] B-1 — Pydantic schemas: `ExploitVerifyRequestPayload`,
      `ExploitVerifyResultPayload` in `analyst/protocol/envelope.py`,
      registered as valid payload types. Also added `AgentID.EXPLOIT` and
      two `MessageType` entries. Test suite stays at 126 passed, 0 failed.
- [x] B-2 — Sandbox tools: `run_payload`, `report_result` as plain Python
      functions in `analyst/exploitation/agent.py`. Reuses
      `_make_sandbox_copy` from `patch_loop.py`. No LLM/agent loop wired up
      yet. 24 new tests in `tests/test_exploit_tools.py`. 150 passed, 0 failed.
- [x] B-3 — Agent loop: LangGraph ReAct-style tool-calling loop using the 2
      tools from B-2. `ChatGroq` constructed in this module's own
      namespace, WITH an explicit per-call request timeout (~15-20s) set on
      the client — this is required, not optional, see requirements.md 3.4
      and design.md section 8 ("Deadlock prevention"). Per-tool sandbox
      timeout enforced independently. Overall budget enforcement (max 5
      calls / 60s) on top of both. Verdict enum implemented. Fallback to
      fixed payload library (`STATIC_CHECK_ONLY`) when LLM unavailable or
      times out, reusing `fallback.py`'s circuit breaker pattern. 155 passed, 0 failed.
- [x] B-4 — Bus wiring: register `exploit.verify` capability, ORCHESTRATOR
      sends request after patch acceptance (mirrors existing `rule.recheck`
      flow), result attached to the finding's record.
- [x] B-5 — Reporting: per-finding verdict shown in the markdown report,
      plus aggregate line "N/M findings verified by exploit vs
      static-only". `--dynamic` CLI flag gates the whole exploit flow
      (off by default).

Each B-step must independently pass the full test suite before moving to
the next. Do not combine steps.

---

## Decision log (why things are the way they are — read before proposing
## a different approach)

- Exploit module is BLACK-BOX only in v1 (no source-code-reading tool) —
  decided deliberately, not a limitation to "fix". White-box is future work.
- One LLM provider only (Groq) — a second provider was considered and
  explicitly rejected (adds credential/config surface without improving the
  exploit agent's actual capability — payload selection doesn't need a
  stronger/different model).
- No custom-trained ML model for exploitation — no labeled dataset exists,
  and a black-box model would be unexplainable in a viva. Deterministic
  payload library + agentic loop was chosen instead.
- Scope limited to SQLi + XSS on demo_app for v1 — command injection, path
  traversal, deserialization intentionally deferred.
