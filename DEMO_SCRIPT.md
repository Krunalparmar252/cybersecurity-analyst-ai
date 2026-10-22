# Demo Script

Everything below works **offline**: no network and no API key. The LLM is the only network dependency, and the pipeline degrades to its deterministic tier without it.

## Before you go on (2 minutes)

```bash
source .venv/bin/activate
pytest test_*.py tests/ -q                      # expect: all passed
mkdir -p demo_backup
python -m analyst scan demo_app --offline -o demo_backup/report.md --artifacts demo_backup/art --format pdf
python -m analyst scan demo_app --offline -o demo_backup/report.md --format html
python scripts/compute_metrics.py               # refreshes metrics.md / metrics.json
```

`demo_backup/` is your fallback material if a live run fails (see the last section).

## 1. Multi-agent scan (about 2 min)

```bash
python -m analyst scan demo_app --offline -o /tmp/report.md --artifacts /tmp/art
```

What to point at while it runs:

- Four CLI stages appear in order: INGEST, DETECT, REASON, REPORT. Between REASON and REPORT the message log also shows the TRIAGE exchange (`ORCHESTRATOR -> TRIAGE [TRIAGE_REQUEST]`, then the response `P1: 2, P3: 12`): a fifth agent, reached by capability, with no CLI stage of its own.
- `[orchestrator decision]` lines: routing is data-dependent (e.g. DETECT reports how many rule families fired and escalates).
- REASON log lines: *"re-ran the full rule engine over the patched sandbox ... no longer fires"*. This is the peer validation: REASON asks DETECT over the bus instead of calling it.

Expected ending (durations and salt differ per run):

```
[*] 14 confirmed finding(s), 0 rejected as false positive(s), 1 escalated for human review, in 0.1s
[!] DEGRADED RUN: ... fallback event(s)        <- expected offline
[*] Integrity: VERIFIED — 37 signed message(s), salt <16 hex> (epoch 0), audit head <12 hex>
[*] Report written to /tmp/report.md
```

Then show the report: `head -40 /tmp/report.md` (14 findings listed fix-first, each with a `Fix priority` line: the two open critical findings (SQL injection, command injection) are P1; 2 patches auto-verified, 1 flagged for manual review, every secret shown redacted like `AK****...LE<len=20>`).

## 2. JS/TS and a second engine (about 1 min)

```bash
python -m analyst scan demo_app_jsts --offline --engine graph -o /tmp/report_js.md
```

Expected: `14 confirmed finding(s)`, `0 escalated`, `Integrity: VERIFIED — 29 signed message(s)`. Same agents, the LangGraph orchestrator.

## 3. Formats (about 30 s)

```bash
python -m analyst scan demo_app --offline -o /tmp/report.md --format pdf
```

Expected: `Markdown report (checksummed): /tmp/report.md` and `Report written to /tmp/report.pdf`.

## 4. Numbers (about 1 min)

```bash
python scripts/compute_metrics.py
```

Expected table (offline): both apps show 100% recall before and after REASON, 0% false-positive rate, `100.0% (2/2)` patch validity on `demo_app` and `n/a (0/0)` on `demo_app_jsts` (no auto-patch is proposed there).

Say this out loud: the demo apps were written with the rules, and they contain no benign look-alikes, so these numbers show the rules do what they were built for. They do not measure generalisation, and they do not exercise REASON's false-positive filtering (the offline tier cannot reject anything). `metrics.md` states this.

## 5. Dashboard (optional, about 1 min)

```bash
uvicorn analyst.api.app:app --port 8000
```

Open http://localhost:8000, start a job on `demo_app`, watch the live message stream.

## 6. Live LLM run (only if the network and key are confirmed beforehand)

```bash
python -m analyst scan demo_app -o /tmp/report_llm.md
```

Expected difference: no `DEGRADED RUN` banner, LLM-written explanations, and possibly different severities and patches. Findings are the same because detection is deterministic.

## Fallback plan

| Failure | What happens | What you do |
|---|---|---|
| No network | Offline scans are unaffected. Git-URL targets fail. | Use local paths (`demo_app`). Say the LLM tier needs the network and the deterministic tier does not. |
| No/invalid `GROQ_API_KEY`, or Groq down / rate-limited mid-run | The pipeline continues on the deterministic tier; report marked `DEGRADED RUN`. | Keep going. This is the fallback design. Or rerun with `--offline`. |
| Live run hangs | | Ctrl-C, rerun with `--offline`. |
| Terminal/CLI problem | | Open `demo_backup/report.pdf`, `demo_backup/report.html` and `metrics.md`, and walk through them. |
| Dashboard won't start | | Skip section 5; everything it shows is in the CLI output and artifacts. |
| A test fails before you start | | Do not demo the failing path. restore your last good copy, or demo from `demo_backup/`. |
