#!/usr/bin/env python3
"""
Recompute benchmark precision incorporating human-reviewed verdicts from fp_review.md.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, List

BENCHMARKS_DIR = Path(__file__).resolve().parent
ROOT_DIR = BENCHMARKS_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
RESULTS_DIR = BENCHMARKS_DIR / "results"
FP_REVIEW_PATH = RESULTS_DIR / "fp_review.md"
RESULTS_JSON_PATH = RESULTS_DIR / "results.json"
OUTPUT_PATH = RESULTS_DIR / "reviewed_summary.md"


def parse_fp_review(review_path: Path) -> Dict[str, Dict[str, int]]:
    """
    Parses verdicts from fp_review.md.
    Returns { (repo, config): {"tp": count, "fp": count, "unsure": count} }
    """
    if not review_path.exists():
        return {}

    content = review_path.read_text(encoding="utf-8", errors="ignore")
    current_repo = None
    current_cfg = None

    verdicts: Dict[str, Dict[str, int]] = {}

    for line in content.splitlines():
        # Match header: ## PYGOAT — Config: `native-only`
        header_m = re.match(r"^##\s+(\w+)\s+—\s+Config:\s+`([^`]+)`", line)
        if header_m:
            current_repo = header_m.group(1).lower()
            current_cfg = header_m.group(2)
            verdicts.setdefault(f"{current_repo}:{current_cfg}", {"tp": 0, "fp": 0, "unsure": 0})
            continue

        # Match verdict line: - **Verdict:** `[x] TP` or `verdict: TP`
        if current_repo and current_cfg and "verdict" in line.lower():
            key = f"{current_repo}:{current_cfg}"
            line_clean = line.strip().lower()
            if "[x] tp" in line_clean or "verdict: tp" in line_clean:
                verdicts[key]["tp"] += 1
            elif "[x] fp" in line_clean or "verdict: fp" in line_clean:
                verdicts[key]["fp"] += 1
            elif "[x] unsure" in line_clean or "verdict: unsure" in line_clean:
                verdicts[key]["unsure"] += 1

    return verdicts


def main() -> int:
    if not RESULTS_JSON_PATH.exists():
        print(f"Results file {RESULTS_JSON_PATH} not found. Run run_benchmarks.py first.")
        return 1

    with open(RESULTS_JSON_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    results = data.get("results", [])
    review_verdicts = parse_fp_review(FP_REVIEW_PATH)

    lines = [
        "# Recomputed Benchmark Summary with Human-Reviewed Unlabeled Findings\n\n",
        "| Config | Repository | Split | Original TP | Original FP | Reviewed TP | Reviewed FP | New Precision | Delta |\n",
        "|---|---|---|---|---|---|---|---|---|\n",
    ]

    total_orig_tp, total_orig_fp = 0, 0
    total_rev_tp, total_rev_fp = 0, 0

    print("Recomputing precision with manual review verdicts...")
    for r in results:
        if r.get("status") != "completed":
            continue
        repo = r["repo"]
        cfg = r["config"]
        key = f"{repo}:{cfg}"
        review = review_verdicts.get(key, {"tp": 0, "fp": 0, "unsure": 0})

        orig_tp = r.get("tp", 0)
        orig_fp = r.get("fp", 0)
        orig_p = r.get("precision", 0.0)

        add_tp = review["tp"]
        add_fp = review["fp"]

        new_tp = orig_tp + add_tp
        new_fp = orig_fp + add_fp
        new_p = new_tp / (new_tp + new_fp) if (new_tp + new_fp) > 0 else 0.0
        delta = new_p - orig_p

        total_orig_tp += orig_tp
        total_orig_fp += orig_fp
        total_rev_tp += new_tp
        total_rev_fp += new_fp

        lines.append(
            f"| `{cfg}` | {repo} | {r.get('split')} | {orig_tp} | {orig_fp} | "
            f"+{add_tp} | +{add_fp} | **{new_p:.1%}** | {'+' if delta >= 0 else ''}{delta:.1%} |\n"
        )

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"Recomputation complete -> {OUTPUT_PATH.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
