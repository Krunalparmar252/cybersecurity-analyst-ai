# Tasks — working checklist

This is the SHORT, granular to-do list for the CURRENT step only. It gets
rewritten/trimmed as work progresses — implementation-plan.md is the
permanent record, this file is scratch for "what am I doing right now".

## Completed: B-5 — Reporting and CLI flag ✓

- [x] Add `--dynamic` CLI flag to `analyst/__main__.py`.
- [x] Update `run_pipeline` in `pipeline.py` and `run_pipeline_graph` in `graph.py` to accept the `dynamic` flag.
- [x] Condition exploit verification in Orchestrator logic on `dynamic` flag.
- [x] Update `analyst/reporting/renderer.py` to show per-finding exploit verdict.
- [x] Update `analyst/reporting/renderer.py` to show aggregate line "N/M findings verified by exploit vs static-only".
- [x] Fix `_VerifyState` and logic in `agent.py` to correctly map verdicts.
- [x] Test everything end-to-end.

## Up next (do not start until told to)
- Final wrap-up / project complete.
