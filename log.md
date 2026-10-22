# Change Log

Append-only. Every change made to the repo gets one entry here, newest at
the BOTTOM. Never edit or delete a past entry — if something turns out to
be wrong, add a NEW entry correcting it.

## Entry format
```
## [YYYY-MM-DD HH:MM] <one-line summary>
- Step: <task id from tasks.md/implementation-plan.md, e.g. B-1>
- Files changed: <list>
- What changed: <2-4 lines, plain language>
- Tests: <pass count> passed, <fail count> failed (before -> after if counts changed)
- Notes: <anything unusual, any deviation from the plan and why>
```

---

## [2026-10-08 21:41] Rebuilt broken virtual environment
- Step: (infra, not in tasks.md)
- Files changed: .venv/ (rebuilt, not tracked in git), .gitignore (confirmed/updated)
- What changed: Existing .venv had a hardcoded Python interpreter path from a
  different machine/user (kruna), causing "No Python at ..." errors. Deleted
  and recreated with `python -m venv .venv` + `pip install -r requirements.txt`.
  Confirmed .venv/ is in .gitignore and not tracked by git.
- Tests: 126 passed, 0 failed, 29 warnings (harmless FutureWarning from
  tree_sitter Language(path, name) deprecation).
- Notes: This is the confirmed baseline going forward. Any test count other
  than 126/0 from here should be treated as a regression, not the new normal,
  unless a log entry explains an intentional change in test count.

---

## [2026-10-08 21:42] B-1: Added exploit verify Pydantic schemas to envelope.py
- Step: B-1
- Files changed: analyst/protocol/envelope.py
- What changed: Added `ExploitVerifyRequestPayload` (schema_name:
  "exploitation.verify.request.v1", fields: finding_id, rule_id, file,
  sandbox_root, patched_source_digest, attempt) and
  `ExploitVerifyResultPayload` (schema_name: "exploitation.verify.result.v1",
  fields: finding_id, rule_id, file, verdict Literal, payload_used, evidence,
  tool_calls_used, elapsed_seconds). Both inherit BasePayload (extra="forbid")
  and auto-register via __init_subclass__. Also added AgentID.EXPLOIT,
  MessageType.EXPLOIT_VERIFY_REQUEST, MessageType.EXPLOIT_VERIFY_RESPONSE.
- Tests: 126 passed, 0 failed (unchanged from baseline)
- Notes: Work was done in the previous session (2026-10-08) but log entry was
  not written at the time. This entry is backdated to the actual change time.
  tasks.md and implementation-plan.md updated to reflect completion.

---

## [2026-10-09 12:39] Session resume: read design/requirements/plan/tasks/log
- Step: (session setup, not a task step)
- Files changed: tasks.md, implementation-plan.md (housekeeping only)
- What changed: Re-read all five source-of-truth files. Confirmed B-1 was
  complete but unlogged. Updated tasks.md to show B-2 as active step and
  implementation-plan.md to check off B-1 and update status snapshot.
  Re-ran test suite to confirm current state.
- Tests: 126 passed, 0 failed, 29 warnings (unchanged)
- Notes: Next work item is B-2. Awaiting user go-ahead before proceeding.

---

## [2026-10-09 12:49] B-2: Sandbox tool functions + static payload library
- Step: B-2
- Files changed: analyst/exploitation/__init__.py (new),
  analyst/exploitation/agent.py (new),
  analyst/protocol/__init__.py (added ExploitVerifyRequestPayload,
  ExploitVerifyResultPayload, CAP_EXPLOIT_VERIFY to public surface),
  tests/test_exploit_tools.py (new, 24 tests)
- What changed: Created analyst/exploitation/ package. agent.py contains:
  run_payload() — starts sandboxed Flask subprocess, sends HTTP request,
  returns {status, response_body, triggered, error}; report_result() —
  writes completion signal into _VerifyState; _static_check() — runs
  STATIC_PAYLOADS list without LLM (STATIC_CHECK_ONLY fallback tier);
  make_exploit_sandbox() — thin wrapper around _make_sandbox_copy().
  Also added CAP_EXPLOIT_VERIFY constant and the two new payload schema
  classes to the protocol package public surface.
- Tests: 126 -> 150 passed, 0 failed, 29 warnings (unchanged)
- Notes: All 24 new tests run offline (subprocess.Popen mocked). Flask is
  NOT imported into agent.py — the subprocess runs it directly, which keeps
  flask out of the module's import chain and avoids adding a dependency.

---

## [2026-10-09 12:57] User updated design/requirements/implementation-plan for timeout requirements
- Step: (design review, not a code step)
- Files changed: requirements.md, design.md, implementation-plan.md (user edits)
- What changed: Requirements §3.4 now mandates three independent timeouts:
  (1) per-LLM-call timeout ~15-20s on ChatGroq client, (2) per-tool sandbox
  subprocess timeout, (3) overall 5-call/60s budget as outer ceiling. design.md
  §8 added a "Deadlock prevention" bullet. implementation-plan.md B-3 description
  expanded with explicit timeout requirements. Also: B-1/B-2 checkmarks and
  status snapshot were accidentally cleared; restored them.
- Tests: 150 passed, 0 failed (no code change)
- Notes: B-2's run_payload already satisfies timeout #2 (SUBPROCESS_TIMEOUT=10s).
  Timeout #1 (per-LLM-call) must be set via ChatGroq(..., request_timeout=15)
  in B-3. Timeout #3 already planned in B-3. No rework needed on B-1 or B-2.

---

## [2026-10-09 13:15] B-3: Agent loop with timeout enforcement
- Step: B-3
- Files changed: analyst/exploitation/agent.py (appended run_verify_loop),
  tests/test_exploit_agent.py (new)
- What changed: Implemented the ReAct agent loop for B-3 in agent.py using
  LangGraph prebuilt create_react_agent. Enforces 3 timeouts: (1) `ChatGroq`
  created with `request_timeout=15`, (2) sandbox subprocess uses 10s timeout,
  (3) loop stream manually checks against a 60s wallclock budget. LLM
  exceptions (transient or timeouts) are caught, recorded to CircuitBreaker,
  and fallback cleanly to `_static_check` as required.
- Tests: 150 -> 155 passed, 0 failed.
- Notes: A minor mocking quirk arose in tests: `langgraph.prebuilt.create_react_agent`
  must be patched at its source, as patching the local import fails.
  Next step is B-4 (bus wiring).

---

## [2026-10-09 13:31] B-4: Bus wiring
- Step: B-4
- Files changed: `analyst/exploitation/agent.py` (added `handle_message`), `analyst/orchestrator/pipeline.py` (registered `EXPLOIT` capability on bus), `analyst/orchestrator/graph.py` (added logic to send `EXPLOIT_VERIFY_REQUEST` after `run_patch_verify_loop`), `analyst/reasoning/patch_loop.py` (added `exploit_result` to `PatchVerificationResult`).
- What changed: Wired up the EXPLOIT agent. The `handle_message` inside `analyst/exploitation/agent.py` runs the verify loop using the payload parameters. After the patch is successfully applied and verified statically, the Orchestrator (in `graph.py`) makes a request over the message bus to the EXPLOIT capability to confirm the exploit, and populates `PatchVerificationResult.exploit_result` with the response.
- Tests: 155 passed, 0 failed.
- Notes: Next step is B-5 (Reporting and CLI flag).

---

## [2026-10-09 13:49] B-5: Reporting and CLI flag
- Step: B-5
- Files changed: analyst/__main__.py, analyst/orchestrator/pipeline.py, analyst/orchestrator/graph.py, analyst/reporting/renderer.py, analyst/exploitation/agent.py, tasks.md, implementation-plan.md
- What changed: Added `--dynamic` CLI flag to trigger exploit verification. Passed it through `run_pipeline` and `run_pipeline_graph` into the Orchestrator, where it conditionally fires the `EXPLOIT_VERIFY_REQUEST`. Updated `renderer.py` to display the exploit verdict per-finding, as well as an aggregate summary line of findings verified by exploit vs static-only. Fixed `_VerifyState` to properly set `static_only` and correctly map the verdict to `CONFIRMED_VULNERABLE_THEN_FIXED` when the patch breaks the exploit successfully.
- Tests: 155 passed, 0 failed.
- Notes: B-5 is complete and the dynamic analysis reporting flow behaves as expected. The test suite passes. Next steps are final wrap-up.
