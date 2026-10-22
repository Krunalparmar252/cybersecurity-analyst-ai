# Evaluation metrics

Mode: **offline (deterministic fallback)**. Match key: file + line + rule_id against `ground_truth.json`.

| App | GT | Recall before | Recall after | FP rate before | FP rate after | Patch validity | Run time |
|---|---|---|---|---|---|---|---|
| demo_app | 14 | 100.0% | 100.0% | 0.0% | 0.0% | 100.0% (2/2) | 0.11s |
| demo_app_jsts | 14 | 100.0% | 100.0% | 0.0% | 0.0% | n/a (0/0) | 0.044s |

## Detail

### demo_app
- Candidates before REASON: 14 (TP 14, FP 0)
- Confirmed after REASON: 14 (TP 14, FP 0); rejected by REASON: 0
- Patches: 2 proposed, 2 accepted; 12 confirmed findings have no auto-patch; 1 routed to manual review
- Analysis tiers: {'T3_DETERMINISTIC': 13, 'T4_MANUAL_REVIEW': 1}

### demo_app_jsts
- Candidates before REASON: 14 (TP 14, FP 0)
- Confirmed after REASON: 14 (TP 14, FP 0); rejected by REASON: 0
- Patches: 0 proposed, 0 accepted; 14 confirmed findings have no auto-patch; 0 routed to manual review
- Analysis tiers: {'T3_DETERMINISTIC': 14}

## How to read these numbers

- The demo apps were written alongside the rules, and ground truth is exactly the seeded set. Recall here shows the rules detect what they were built to detect; it is **not** a measure of generalisation to unseen code.
- The demo apps contain no benign look-alikes that trigger a rule, so the false-positive rate is trivially 0% before and after REASON. REASON's false-positive filtering is therefore **not exercised** by this data.
- In offline mode REASON is the deterministic fallback, which confirms every candidate by re-running the rule. It cannot reject anything, so before/after is identical by construction. Run with `--live` (needs `GROQ_API_KEY`) for LLM-based confirmation.
- Patch validity counts only patches the pipeline actually proposed; findings with no patch are listed separately rather than counted as failures or successes.
