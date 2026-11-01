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

---

## [2026-10-22 13:27] C-1: Scan cache file (read/write/schema)
- Step: C-1
- Files changed: analyst/ingestion/scan_cache.py (new), tests/test_scan_cache.py (new)
- What changed: Created `analyst/ingestion/scan_cache.py` — pure file I/O and schema
  validation for the incremental scan baseline. Implements `load_cache()` (returns None
  on every failure mode: missing file, invalid JSON, wrong schema_version, non-dict top
  level — never raises) and `save_cache()` (writes `.analyst_cache/last_scan.json`,
  creates directory if needed, accepts both dataclasses and plain dicts in
  findings_by_file). Schema version 1 with fields: schema_version, repo_path,
  last_commit, scanned_at, findings_by_file. Deliberately separate from manifest.py
  per design.md §9 — different concerns (integrity of THIS run vs comparison to a
  PREVIOUS run). No git logic (that is C-2).
- Tests: 155 passed, 0 failed → 173 passed, 0 failed (18 new tests in test_scan_cache.py:
  missing file, corrupted JSON, truncated JSON, empty file, wrong schema_version, missing
  schema_version, schema_version as string, list/string JSON top-level, round-trip basic,
  empty findings, multiple files, directory auto-creation, return value, dataclass
  conversion, null last_commit, overwrite idempotency, scanned_at ISO 8601 validity).
- Notes: All 18 new tests pass. 29 harmless FutureWarnings from tree_sitter unchanged.

---

## [2026-10-22 13:33] C-2: git diff/status change detection
- Step: C-2
- Files changed: analyst/ingestion/scan_cache.py (extended), tests/test_changed_files.py (new)
- What changed: Added `get_changed_files(repo_root, last_commit) -> Optional[ChangedFileSet]`
  to scan_cache.py. Returns a frozen `ChangedFileSet(added, modified, deleted)` computed
  from two git calls: `git diff --name-status <last_commit>..HEAD` (committed history) merged
  with `git status --porcelain` (uncommitted edits). Also added `ChangedFileSet` dataclass
  with a `.changed` property (added | modified) and the `FULL_SCAN = None` sentinel.
  Returns FULL_SCAN on every failure mode: last_commit=None, git not on PATH
  (FileNotFoundError), not a git repo (CalledProcessError), OSError. Never raises.
  Contradictions between diff and status resolved in favour of the working tree (file exists
  → must be scanned). Added `_run_git()` internal helper wrapping subprocess.run with
  check=True so all failures surface as CalledProcessError.
- Tests: 173 passed, 0 failed → 192 passed, 0 failed (19 new tests in test_changed_files.py:
  all sentinel paths, empty diff/status, A/M/D from diff, M/?? /D from status, rename in
  diff, rename in status, .changed property, contradictory delete+recreate, dedup of same
  file in both sources, mixed realistic scenario).
- Notes: All tests mock subprocess.run — no real git dependency in the test suite. 29
  harmless FutureWarnings from tree_sitter unchanged.

---

## [2026-10-22 13:39] C-3: Orchestrator wiring + DETECT skip logic
- Step: C-3
- Files changed: analyst/common/types.py, analyst/orchestrator/pipeline.py,
  analyst/orchestrator/graph.py, tests/test_incremental_filter.py (new)
- What changed:
  • `CandidateFinding` in types.py gains `scan_mode: str = "rescanned"` (optional,
    defaults to "rescanned" — all existing callers unaffected).
  • `_apply_incremental_filter(repo_path, candidates)` added to pipeline.py: loads
    the scan cache, calls get_changed_files(), separates candidates into fresh (from
    changed/added files) vs. carried-forward (from unchanged cached files), drops
    findings for deleted files, returns merged list + summary string. Fail-safe:
    returns (candidates, None) on any error — never raises.
  • `run_pipeline` and `_run_pipeline_on_local_path` in pipeline.py gain
    `incremental: bool = False` param. When True, _apply_incremental_filter is called
    between DETECT and REASON; summary logged to audit + on_route.
  • `PipelineResult` gains `incremental_summary: Optional[str]` field.
  • `PipelineState`, `detect_node`, `run_pipeline_graph`, `_run_graph_on_local_path`
    in graph.py gain the same `incremental` param and state field.
  • INGEST and DETECT still run in full — only the candidates list forwarded to
    REASON is filtered. Cache write-back is C-5.
- Tests: 192 passed, 0 failed → 205 passed, 0 failed (13 new tests in
  test_incremental_filter.py: no-cache full-scan, FULL_SCAN sentinel, changed file
  rescanned, unchanged carried forward, deleted dropped, uncached new file, malformed
  cached finding, unexpected exception fail-safe, summary string format, both engine
  signature checks, unchanged file fresh candidate superseded by cache).
- Notes: 29 harmless FutureWarnings from tree_sitter unchanged.

---

## [2026-10-22 14:12] C-4: REASON/EXPLOIT skip already-resolved findings
- Step: C-4
- Files changed: analyst/common/types.py, analyst/orchestrator/pipeline.py,
  analyst/orchestrator/graph.py, analyst/reasoning/patch_loop.py,
  tests/test_reason_skip_resolved.py (new)
- What changed:
  • `CandidateFinding` in types.py gains `already_resolved: bool = False` and
    `cached_patch_diff: Optional[str] = None` (defaults preserve full back-compat).
  • `_apply_incremental_filter` in pipeline.py inspects cached finding dicts: when
    `loop_status == "ACCEPTED"`, sets `already_resolved=True` and populates
    `cached_patch_diff` from the cached patch. Unaccepted findings leave
    `already_resolved=False`.
  • `run_patch_verify_loop` and `verify_and_patch` in patch_loop.py check
    `already_resolved`: when True, immediately synthesize a `PatchVerificationResult`
    with `loop_status=STATUS_ACCEPTED`, `attempts=0`, `patch_diff` from cache, and
    `analysis_tier="cached"`. No LLM calls, sandbox copies, or recheck bus messages
    are executed.
  • `VerifyLoopResult = PatchVerificationResult` alias added to patch_loop.py.
  • Orchestrator dynamic EXPLOIT loops in pipeline.py and graph.py check `attempts == 0`
    and skip calling EXPLOIT on already-resolved findings.
- Tests: 205 passed, 0 failed → 213 passed, 0 failed (8 new tests in
  test_reason_skip_resolved.py: filter sets already_resolved for ACCEPTED, filter
  preserves False for unaccepted, already_resolved skips LLM and synthesizes result,
  unresolved carried-forward undergoes REASON analysis, rescanned candidates always
  undergo REASON analysis, mixed candidate batches only analyze unresolved/rescanned,
  verify_and_patch directly handles already_resolved, and dynamic EXPLOIT is skipped
  for attempts==0 findings).
- Notes: 30 harmless FutureWarnings from tree_sitter unchanged.

---

## [2026-10-22 14:36] C-5: Reporting summary line + cache write-back at end of every run
- Step: C-5
- Files changed: analyst/ingestion/scan_cache.py, analyst/reporting/renderer.py,
  analyst/reporting/agent.py, analyst/orchestrator/pipeline.py,
  analyst/orchestrator/graph.py, analyst/__main__.py,
  tests/test_incremental_reporting_and_cache.py (new)
- What changed:
  • `get_head_commit(repo_root)` added to `scan_cache.py`: captures HEAD commit via
    `git rev-parse HEAD`, fail-safe returning None on any error.
  • `_write_scan_cache(repo_path, verify_results, scanned_files)` added to `pipeline.py`:
    serializes `verify_results` into `findings_by_file` mapping with loop statuses and
    patch diffs, captures clean scanned files, resolves HEAD commit, calls `save_cache()`,
    and catches all exceptions fail-safe.
  • In `pipeline.py`, `finish()` calls `_write_scan_cache()` whenever a scan completes
    (covering both findings-detected runs and `NONE_FOUND` clean exits).
  • In `graph.py`, `_run_graph_on_local_path()` calls `_write_scan_cache()` at run completion.
  • `render_report()` in `renderer.py` and `run_reporting_agent()` in `agent.py` gain
    `incremental_summary: Optional[str]` parameter, rendering `- **Incremental scan:** <summary>`
    under `## Executive Summary`.
  • Wired `incremental_summary` from orchestrator pipelines (`pipeline.py` and `graph.py`)
    into `run_reporting_agent()`.
  • `analyst/__main__.py` surfaces `result.incremental_summary` in the CLI console output.
- Tests: 213 passed, 0 failed → 222 passed, 0 failed (9 new tests in
  test_incremental_reporting_and_cache.py: get_head_commit success, get_head_commit
  fail-safe None, _write_scan_cache serialization, _write_scan_cache fail-safe on OSError,
  render_report with incremental summary, render_report without incremental summary,
  run_reporting_agent pass-through, end-to-end cache write-back in linear pipeline, and
  end-to-end cache write-back in graph pipeline).
- Notes: 32 harmless FutureWarnings from tree_sitter unchanged.

---

## [2026-10-22 14:55] C-6: CLI flag + fallback behavior
- Step: C-6
- Files changed: analyst/__main__.py, analyst/orchestrator/pipeline.py,
  analyst/orchestrator/graph.py, tests/test_incremental_cli.py (new)
- What changed:
  • Added `--incremental` option to the `scan` CLI command in `analyst/__main__.py`.
  • Forwarded `incremental` flag to orchestrator runners (`run_pipeline` / `run_pipeline_graph`).
  • Cleaned up summary string in `_apply_incremental_filter` and updated on_route handlers in
    `pipeline.py` and `graph.py` to ensure clean, non-duplicated console and report formatting.
  • Updated `early_exit()` in `pipeline.py` and `_write_empty_report()` in `graph.py` to forward
    `incremental_summary` to `render_report()`, ensuring clean scans report differential status.
  • Verified fail-safe fallback to full scans when cache is absent, invalid, or git fails.
- Tests: 222 passed, 0 failed → 227 passed, 0 failed (5 new tests in
  test_incremental_cli.py: CLI help documents `--incremental`, CLI forwards flag to runner,
  graceful fallback on missing cache, graceful fallback when git fails, and end-to-end
  multi-run differential scan workflow). Full Track C suite now has 72 dedicated tests.
- Notes: 35 harmless FutureWarnings from tree_sitter unchanged.



