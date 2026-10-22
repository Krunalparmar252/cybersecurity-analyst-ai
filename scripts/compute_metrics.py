#!/usr/bin/env python
"""Compute evaluation metrics for the pipeline against ground_truth.json.

    python scripts/compute_metrics.py                      # both demo apps, offline
    python scripts/compute_metrics.py demo_app --live      # uses GROQ_API_KEY
    python scripts/compute_metrics.py -o metrics.md --json metrics.json

Definitions (match key = file + line + rule_id):
  recall            seeded bugs found / seeded bugs, before REASON (candidates)
                    and after REASON (confirmed == true)
  FP rate           findings not in ground truth / findings, before vs after REASON
  patch validity    patches ACCEPTED by the verify loop (peer-rechecked: rule no
                    longer fires on the patched sandbox) / patches proposed
  run time          wall-clock seconds for the full pipeline
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from analyst.orchestrator.pipeline import run_pipeline  # noqa: E402

DEFAULT_APPS = ["demo_app", "demo_app_jsts"]


def _key(d: dict) -> tuple:
    return (Path(d["file"]).as_posix(), int(d["line"]), d["rule_id"])


def _ratio(n: int, d: int):
    return round(n / d, 4) if d else None


def compute_app_metrics(app: str, offline: bool = True) -> dict:
    app_path = Path(app) if Path(app).is_absolute() else ROOT / app
    truth = json.loads((app_path / "ground_truth.json").read_text(encoding="utf-8"))
    truth_keys = {_key(g) for g in truth}

    with tempfile.TemporaryDirectory() as tmp:
        art = Path(tmp) / "artifacts"
        t0 = time.perf_counter()
        result = run_pipeline(str(app_path), str(Path(tmp) / "report.md"), str(art), offline=offline)
        wall = time.perf_counter() - t0
        candidates = json.loads((art / "candidate_findings.json").read_text())
        reasoned = json.loads((art / "confirmed_findings.json").read_text())

    cand_keys = [_key(c) for c in candidates]
    kept = [r for r in reasoned if r.get("confirmed")]
    kept_keys = [_key(r) for r in kept]

    def stage(keys):
        tp = len(truth_keys & set(keys))
        fp = len([k for k in keys if k not in truth_keys])
        return {"findings": len(keys), "true_positives": tp, "false_positives": fp,
                "recall": _ratio(tp, len(truth_keys)), "fp_rate": _ratio(fp, len(keys))}

    proposed = [r for r in kept if r.get("patch_diff")]
    accepted = [r for r in proposed if r.get("loop_status") == "ACCEPTED"]
    return {
        "app": app,
        "mode": "offline (deterministic fallback)" if offline else "live (LLM)",
        "ground_truth": len(truth_keys),
        "before_reason": stage(cand_keys),
        "after_reason": stage(kept_keys),
        "rejected_by_reason": len(reasoned) - len(kept),
        "patches": {"proposed": len(proposed), "accepted": len(accepted),
                    "validity": _ratio(len(accepted), len(proposed)),
                    "confirmed_without_patch": len(kept) - len(proposed)},
        "analysis_tiers": dict(Counter(r.get("analysis_tier") for r in reasoned)),
        "manual_review": result.manual_review_count,
        "run_seconds": round(wall, 3),
        "pipeline_status": result.status,
    }


def _pct(x):
    return "n/a" if x is None else f"{x * 100:.1f}%"


def render_markdown(runs: list[dict]) -> str:
    o = ["# Evaluation metrics", "",
         f"Mode: **{runs[0]['mode']}**. Match key: file + line + rule_id against `ground_truth.json`.", "",
         "| App | GT | Recall before | Recall after | FP rate before | FP rate after | Patch validity | Run time |",
         "|---|---|---|---|---|---|---|---|"]
    for r in runs:
        b, a, p = r["before_reason"], r["after_reason"], r["patches"]
        o.append(f"| {r['app']} | {r['ground_truth']} | {_pct(b['recall'])} | {_pct(a['recall'])} | "
                 f"{_pct(b['fp_rate'])} | {_pct(a['fp_rate'])} | "
                 f"{_pct(p['validity'])} ({p['accepted']}/{p['proposed']}) | {r['run_seconds']}s |")
    o += ["", "## Detail", ""]
    for r in runs:
        o += [f"### {r['app']}",
              f"- Candidates before REASON: {r['before_reason']['findings']} "
              f"(TP {r['before_reason']['true_positives']}, FP {r['before_reason']['false_positives']})",
              f"- Confirmed after REASON: {r['after_reason']['findings']} "
              f"(TP {r['after_reason']['true_positives']}, FP {r['after_reason']['false_positives']}); "
              f"rejected by REASON: {r['rejected_by_reason']}",
              f"- Patches: {r['patches']['proposed']} proposed, {r['patches']['accepted']} accepted; "
              f"{r['patches']['confirmed_without_patch']} confirmed findings have no auto-patch; "
              f"{r['manual_review']} routed to manual review",
              f"- Analysis tiers: {r['analysis_tiers']}", ""]
    o += ["## How to read these numbers", "",
          "- The demo apps were written alongside the rules, and ground truth is exactly the seeded set. "
          "Recall here shows the rules detect what they were built to detect; it is **not** a measure of "
          "generalisation to unseen code.",
          "- The demo apps contain no benign look-alikes that trigger a rule, so the false-positive rate is "
          "trivially 0% before and after REASON. REASON's false-positive filtering is therefore **not "
          "exercised** by this data.",
          "- In offline mode REASON is the deterministic fallback, which confirms every candidate by "
          "re-running the rule. It cannot reject anything, so before/after is identical by construction. "
          "Run with `--live` (needs `GROQ_API_KEY`) for LLM-based confirmation.",
          "- Patch validity counts only patches the pipeline actually proposed; findings with no patch "
          "are listed separately rather than counted as failures or successes.", ""]
    return "\n".join(o)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apps", nargs="*", default=DEFAULT_APPS)
    ap.add_argument("--live", action="store_true", help="use the LLM (needs GROQ_API_KEY); default is offline")
    ap.add_argument("-o", "--md", default=str(ROOT / "metrics.md"))
    ap.add_argument("--json", default=str(ROOT / "metrics.json"))
    args = ap.parse_args(argv)

    runs = [compute_app_metrics(a, offline=not args.live) for a in args.apps]
    Path(args.json).write_text(json.dumps({"runs": runs}, indent=2) + "\n", encoding="utf-8")
    Path(args.md).write_text(render_markdown(runs), encoding="utf-8")
    print(render_markdown(runs).split("## Detail")[0])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
