# Autonomous Cybersecurity Analyst AI

[![CI](https://github.com/krunalparmar252/cybersecurity-analyst-ai/actions/workflows/ci.yml/badge.svg)](https://github.com/krunalparmar252/cybersecurity-analyst-ai/actions/workflows/ci.yml)

A multi-agent pipeline that scans a codebase for vulnerabilities, confirms them, proposes patches, **verifies each patch by re-running detection on a patched sandbox**, and writes a report (Markdown, HTML or PDF).

Five agents (INGEST, DETECT, REASON, TRIAGE, REPORT) and an orchestrator communicate only through a capability-routed, signed message bus (`analyst/protocol/`). Stack: Python 3.12, LangGraph, tree-sitter, FastAPI, Pydantic, Groq (via LangChain).

## Setup

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env                                   # optional: add GROQ_API_KEY for LLM reasoning
```

No API key is required. Without one (or with `--offline`) REASON runs its deterministic tier and the report says so.

## Run

```bash
# Scan (offline, no network, no key needed)
python -m analyst scan demo_app --offline -o report.md --artifacts artifacts/

# With LLM reasoning (needs GROQ_API_KEY in .env or the environment)
python -m analyst scan demo_app -o report.md --artifacts artifacts/

# Other report formats (Markdown is always written too; the integrity checksum covers it)
python -m analyst scan demo_app --offline -o report.md --format html    # -> report.html
python -m analyst scan demo_app --offline -o report.md --format pdf     # -> report.pdf

# LangGraph orchestrator instead of the linear one (same agents, same output)
python -m analyst scan demo_app --offline --engine graph -o report.md

# Git URLs work too (shallow clone to a temp dir)
python -m analyst scan https://github.com/<org>/<repo> -o report.md

# Web dashboard + REST/WebSocket API
uvicorn analyst.api.app:app --port 8000                 # then open http://localhost:8000

# Evaluation metrics (recall, FP rate before/after REASON, patch validity, run time)
python scripts/compute_metrics.py                       # writes metrics.md and metrics.json
```

Artifacts written to `--artifacts`: `ingestion_manifest.json`, `candidate_findings.json` (before REASON), `confirmed_findings.json` (after REASON, with patch status), `audit_log.json`.

## Tests

```bash
pytest test_*.py tests/ -q
```

All tests run offline; the LLM is mocked at the `ChatGroq` seam in `reasoning/patch_loop.py`.

## Architecture

```
            ORCHESTRATOR (pipeline.py | graph.py)  ── routing decisions, never analyses code
                 │
   ┌─────────────┼───────────────────────────────────────────┐
   ▼             ▼                     ▼                     ▼
 INGEST ──▶ DETECT ────────▶ REASON ────────▶ TRIAGE ────────▶ REPORT
 repo.ingest  rule.scan,       patch.reasoning  finding.triage    report.render
              rule.recheck
                 ▲                     │
                 └─── rule.recheck ────┘   peer validation over the bus
```

| Agent | Capability | Responsibility |
|---|---|---|
| INGEST | `repo.ingest` | Walk the repo, parse with tree-sitter, hash each file |
| DETECT | `rule.scan`, `rule.recheck` | Run rules (AST, regex, entropy); redact secrets at detection time; re-check a rule on request |
| REASON | `patch.reasoning` | Confirm or reject candidates, propose a patch, then ask DETECT (`rule.recheck`) whether the rule still fires on the patched sandbox. The only LLM user. |
| TRIAGE | `finding.triage` | Rank confirmed findings P1–P4 (open critical issues before ones with a verified fix). Deterministic; no LLM. |
| REPORT | `report.render` | Render and scrub the report |

Key properties:

- **Bus only.** REASON never imports DETECT; it finds the rule-recheck provider through the bus by capability.
- **Signed transcript.** Every message is sealed with a per-run salt and chained in an audit log; the CLI prints `Integrity: VERIFIED` when the chain checks out.
- **Degrades, does not fail.** No key, rate limit, or LLM error falls through to a deterministic tier and the report is marked `DEGRADED RUN`.
- **Parallel where safe.** INGEST and DETECT split files into chunks on a thread pool; output is identical to sequential (tested).
- **Secrets never leave detection unredacted.** Snippets are redacted at detection; patch diffs, artifacts and reports are scrubbed again on the way out.

### Layout

```
analyst/
  common/      shared types (ConfirmedFinding, CandidateFinding, statuses), redaction, parallel helper
  protocol/    message bus, capabilities, signing, audit log
  ingestion/   repo fetch + tree-sitter manifest
  detection/   engine.py, rules_extra.py, rules.yaml (rule catalogue)
  reasoning/   LLM analysis, patch-verify loop, deterministic fallback
  triage/      TRIAGE agent
  reporting/   renderer, agent, HTML/PDF export
  orchestrator/ pipeline.py (linear), graph.py (LangGraph)
  api/         FastAPI + dashboard
scripts/compute_metrics.py
demo_app/, demo_app_jsts/   seeded vulnerable apps with ground_truth.json
Document/    specs: rules.md, ARCHITECTURE_A2A.md, ...
```

### Rules

Specifications are in `Document/rules.md`. Implemented rules are catalogued in `analyst/detection/rules.yaml` (a test fails if the catalogue and the code disagree), and the rules it lists as not implemented are listed explicitly.

## Known limitations

See `Document/ARCHITECTURE_A2A.md` (single process, only REASON uses an LLM, tamper-evidence only) and `metrics.md` (what the metrics do and do not show).
