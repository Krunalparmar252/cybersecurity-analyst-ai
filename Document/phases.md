# Development Phases
## Autonomous Cybersecurity Analyst AI

Structured as a phased build so each phase produces a demoable increment. Core modules (Ingestion → Detection → Reasoning → Reporting) are prioritized over extension modules, in line with `PDR.md §5`.

---

## Phase 0 — Setup & Demo Repo Curation
**Goal:** Environment ready, and a ground-truth vulnerable demo app exists to measure against from day one.

- [ ] Repo scaffold: `ingestion/`, `detection/`, `reasoning/`, `reporting/`, `ext/`, `tests/`, `sandbox/`
- [ ] Python environment, `tree-sitter` + grammars (Python, JS, TS) installed and verified
- [ ] Groq API access wired up (openai/gpt-oss-120b via ChatGroq, key management via `.env`, never committed)
- [ ] **Curate the seeded demo repo**: a small Flask or Express CRUD app with intentionally planted issues covering all 6 vulnerability classes (at least 2 instances each) — this becomes the regression baseline for every later phase
- [ ] Document the seeded issues in a private `ground_truth.json` (not shown to the pipeline, used only for scoring recall/FP rate)

**Exit criteria:** Demo repo exists, builds/runs standalone, ground truth documented.

---

## Phase 1 — Ingestion Module
**Goal:** Any repo in → structured manifest out.

- [ ] `RepoFetcher`: clone/copy into sandbox
- [ ] `LanguageDetector`: stack detection via manifest files
- [ ] `ASTBuilder`: tree-sitter parsing for Python + JS/TS, with per-file failure isolation
- [ ] `SymbolMapper`: route map, DB call map, auth surface map (initially heuristic-based, refined in Phase 2 as detection needs surface gaps)
- [ ] `FileIndex` for secrets scanner consumption
- [ ] Output: `ingestion_manifest.json`
- [ ] Unit tests: run against demo repo, assert route/DB/auth maps contain expected entries

**Exit criteria:** `ingestion_manifest.json` correctly identifies all routes, DB call sites, and auth functions in the demo repo.

---

## Phase 2 — Detection Layer (Static Scanner + Secrets Scanner)
**Goal:** Candidate findings generated from the rule catalog, no LLM involved yet.

- [ ] Rule engine loader (YAML rule definitions per `rules.md`)
- [ ] AST-based matchers for SQLI-001/002, XSS-001/002/003, AUTH-001/002/006, DESER-001/002 (highest-confidence, highest-value rules first)
- [ ] Regex fallback matchers for remaining rules
- [ ] Secrets scanner: regex detectors (SECRET-001/002/003/007) + entropy detector (SECRET-006)
- [ ] Redaction enforced at the point of detection (raw secret values never written to `candidate_findings.json`)
- [ ] Deduplication logic
- [ ] Output: `candidate_findings.json`
- [ ] Run against demo repo, manually verify against `ground_truth.json` → compute raw recall/FP rate (rule-engine-only baseline, to be compared against post-LLM numbers later)

**Exit criteria:** Detection layer finds ≥ 90% of seeded issues as *candidates* (recall is the priority here; precision improves in Phase 3).

---

## Phase 3 — Reasoning & Patch Engine
**Goal:** Candidates become confirmed, explained, patchable findings.

- [ ] Context assembly (function-level code window extraction using the symbol map from Phase 1)
- [ ] Prompt templates: confirmation prompt, severity scoring prompt, patch generation prompt (structured JSON output, low temperature)
- [ ] Confirmation call implementation + batching for token efficiency
- [ ] Severity scoring implementation (CVSS-inspired reduced scale)
- [ ] Patch generation implementation
- [ ] Patch validation: diff-apply check + language syntax check (`ast.parse`, a JS parser)
- [ ] `manual_review_required` fallback path for unvalidated patches
- [ ] `fp_log.json` for rejected candidates
- [ ] Output: `confirmed_findings.json`
- [ ] Re-run demo repo end-to-end → compute post-LLM precision/recall, compare to Phase 2 baseline

**Exit criteria:** Confirmed findings show measurable FP reduction vs. Phase 2 raw output; ≥ 70% of generated patches pass validation on the demo repo.

---

## Phase 4 — Reporting Module
**Goal:** Confirmed findings become a single, presentable artifact.

- [ ] Markdown report template (executive summary, per-finding sections, appendix)
- [ ] Severity-based sorting and grouping
- [ ] Markdown → HTML render
- [ ] Markdown/HTML → PDF export (Pandoc or headless-browser print)
- [ ] Sanity pass: confirm no raw secrets, only redacted forms, appear anywhere in the rendered report

**Exit criteria:** One command produces a polished PDF/HTML report from a repo path, end to end.

---

## Phase 5 — CLI / Orchestrator Integration
**Goal:** All four core modules callable as a single pipeline.

- [ ] Orchestrator state machine (`INGEST → DETECT → REASON → REPORT`) per `architecture.md §4`
- [ ] Per-stage artifact persistence (resumability)
- [ ] Graceful degradation on stage failure (partial run marking)
- [ ] CLI entrypoint: `python -m analyst scan <repo_path_or_url> --output report.pdf`
- [ ] Full run-time measurement on demo repo (target: < 10 min)

**Exit criteria:** Single CLI command, demo repo in, report out, within time budget.

---

## Phase 6 — Extension Modules (time-permitting, parallelizable across team members)

### 6a. Log & Traffic Analyzer
- [ ] `LogParser` for Apache/Nginx combined format + JSON app logs
- [ ] `AnomalyDetector`: LOG-001 through LOG-004 rules
- [ ] Wire findings into shared `candidate_findings.json` schema → flows through existing Reasoning/Reporting stages
- [ ] Seed a sample log file with planted brute-force pattern for demo

### 6b. Cloud Config Auditor
- [ ] `ConfigParser` for `.env`, JSON/YAML IAM policies, basic Terraform blocks
- [ ] `BaselineRuleset`: CLOUD-001 through CLOUD-004 rules
- [ ] Wire findings into shared pipeline
- [ ] Seed a sample misconfigured IAM policy / bucket config for demo

**Exit criteria (either sub-phase):** at least one seeded issue per rule detected and appearing correctly in the final report, demonstrating the shared-pipeline design extends cleanly.

---

## Phase 7 — Metrics, Polish & Jury Prep
**Goal:** Package the project for presentation.

- [ ] Finalize metrics table against `PDR.md §8` targets (recall, FP reduction, patch applicability, run time)
- [ ] Architecture diagram (clean version of `architecture.md §1` for slides)
- [ ] Live-demo script: fixed sequence of commands, known-good repo state, rehearsed timing
- [ ] Fallback plan: pre-generated report/recording in case live LLM calls fail during presentation (network/API issues)
- [ ] README with setup + run instructions
- [ ] Final pass on report readability — a jury member should be able to read one finding end-to-end unaided (per PDR success metric)

**Exit criteria:** Dry-run of the full jury presentation completed successfully at least twice.

---

## Suggested Team Split (3 members)

| Member | Primary ownership | Secondary |
|---|---|---|
| Member A | Ingestion (Phase 1) + Orchestrator/CLI (Phase 5) | Metrics/demo prep (Phase 7) |
| Member B | Detection Layer (Phase 2) + Log/Traffic Analyzer (Phase 6a) | Rule catalog maintenance |
| Member C | Reasoning & Patch Engine (Phase 3) + Reporting (Phase 4) | Cloud Config Auditor (Phase 6b) |

Phases 0 and 7 are done together. Phase 6 sub-modules can run in parallel with late Phase 3/4 work once the shared findings schema (defined in Phase 2) is stable, since both extension modules only need to *produce* candidates in that schema — they don't block or get blocked by core pipeline completion.
