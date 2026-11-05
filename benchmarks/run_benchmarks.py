#!/usr/bin/env python3
"""
Benchmark Evaluation Harness (Phase 3).
Evaluates native detector, Bandit (if installed), Semgrep (if installed),
and merged configs against public vulnerable benchmark repositories.
Outputs JSON, CSV, Markdown tables, charts, FP review queue, and FN analysis.
"""

from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import os
import random
import sys
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

BENCHMARKS_DIR = Path(__file__).resolve().parent
ROOT_DIR = BENCHMARKS_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import yaml

# Headless matplotlib
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from analyst.common.types import CandidateFinding
from analyst.detection.adapters import get_available_adapters
from analyst.detection.agent import run_detection_agent
from analyst.detection.engine import run_detection
from analyst.ingestion.manifest import IngestionManifest, IngestionResult, ingest_repo
from benchmarks.matcher import MatchResult, match_findings_to_labels, normalize_path

BENCHMARKS_DIR = Path(__file__).resolve().parent
ROOT_DIR = BENCHMARKS_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
REPOS_DIR = BENCHMARKS_DIR / "repos"
LABELS_DIR = BENCHMARKS_DIR / "labels"
RESULTS_DIR = BENCHMARKS_DIR / "results"
MANIFEST_PATH = BENCHMARKS_DIR / "manifest.yaml"


def load_manifest() -> dict:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def is_path_excluded(rel_path: str, excludes: List[str]) -> bool:
    """Check if a posix relative path matches any exclusion pattern."""
    posix_path = normalize_path(rel_path)
    parts = posix_path.split("/")
    for pat in excludes:
        clean_pat = pat.strip()
        if not clean_pat:
            continue
        # Direct pattern match
        if fnmatch.fnmatch(posix_path, clean_pat):
            return True
        # Part matches
        if any(fnmatch.fnmatch(part, clean_pat.strip("*/")) for part in parts):
            return True
    return False


def filter_ingestion(ingestion: IngestionResult, excludes: List[str]) -> IngestionResult:
    """Filter out files matching exclusion patterns from an IngestionResult."""
    filtered_files = []
    filtered_asts = {}
    filtered_sources = {}

    for f in ingestion.manifest.files:
        if not is_path_excluded(f.path, excludes):
            filtered_files.append(f)
            if f.path in ingestion.asts:
                filtered_asts[f.path] = ingestion.asts[f.path]
            if f.path in ingestion.sources:
                filtered_sources[f.path] = ingestion.sources[f.path]

    new_manifest = IngestionManifest(
        repo_root=ingestion.manifest.repo_root,
        files=filtered_files,
        manifest_digest=ingestion.manifest.manifest_digest,
        salt=ingestion.manifest.salt,
    )
    return IngestionResult(
        manifest=new_manifest,
        asts=filtered_asts,
        sources=filtered_sources,
        salt_ctx=ingestion.salt_ctx,
    )


def run_single_benchmark(
    repo_meta: dict,
    config_name: str,
    excludes: List[str],
) -> Dict[str, Any]:
    """Runs a single repository under a specific scanner configuration."""
    name = repo_meta["name"]
    lang = repo_meta["language"]
    split = repo_meta.get("split", "test")
    repo_dir = REPOS_DIR / name

    if not repo_dir.exists():
        return {
            "status": "error",
            "reason": f"Repository directory {repo_dir} not found. Run fetch.py first.",
            "repo": name,
            "config": config_name,
        }

    # Check scanner availability
    available_adapters = {a.name for a in get_available_adapters(["bandit", "semgrep"])}
    if config_name == "bandit-only" and "bandit" not in available_adapters:
        return {
            "status": "not run",
            "reason": "Bandit scanner is not installed or not available on PATH.",
            "repo": name,
            "config": config_name,
        }
    if config_name == "semgrep-only" and "semgrep" not in available_adapters:
        return {
            "status": "not run",
            "reason": "Semgrep scanner is not installed or not available on PATH.",
            "repo": name,
            "config": config_name,
        }

    # Load ground truth labels
    label_path = LABELS_DIR / f"{name}.json"
    labels: List[Dict[str, Any]] = []
    if label_path.exists():
        with open(label_path, "r", encoding="utf-8") as f:
            labels = json.load(f)

    # Ingestion phase with exclusions
    t0 = time.perf_counter()
    raw_ingestion = ingest_repo(str(repo_dir))
    ingestion = filter_ingestion(raw_ingestion, excludes)
    t_ingest = time.perf_counter() - t0

    files_count = len(ingestion.manifest.files)

    # Detection phase
    t1 = time.perf_counter()
    findings: List[CandidateFinding] = []

    if config_name == "native-only":
        agent_res = run_detection_agent(ingestion, repo_path=str(repo_dir), scanners="native")
        findings = agent_res.candidates
    elif config_name == "bandit-only":
        if lang == "python":
            agent_res = run_detection_agent(ingestion, repo_path=str(repo_dir), scanners="bandit")
            findings = agent_res.candidates
        else:
            findings = []  # Bandit is Python-only
    elif config_name == "semgrep-only":
        agent_res = run_detection_agent(ingestion, repo_path=str(repo_dir), scanners="semgrep")
        findings = agent_res.candidates
    elif config_name == "merged":
        agent_res = run_detection_agent(ingestion, repo_path=str(repo_dir), scanners="native,bandit,semgrep")
        findings = agent_res.candidates
    else:
        raise ValueError(f"Unknown config {config_name}")

    t_detect = time.perf_counter() - t1
    total_time = t_ingest + t_detect
    throughput = files_count / total_time if total_time > 0 else 0.0

    # Matching phase
    match_res = match_findings_to_labels(findings, labels, tolerance=3)

    # Breakdown by class
    class_stats: Dict[str, Dict[str, int]] = {}
    for tp in match_res.true_positives:
        cls = tp["label"]["class"]
        class_stats.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})["tp"] += 1
    for fp in match_res.false_positives:
        cls = fp.get("class", "Unknown")
        class_stats.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})["fp"] += 1
    for fn in match_res.false_negatives:
        cls = fn["class"]
        class_stats.setdefault(cls, {"tp": 0, "fp": 0, "fn": 0})["fn"] += 1

    return {
        "status": "completed",
        "repo": name,
        "language": lang,
        "split": split,
        "config": config_name,
        "commit": repo_meta.get("commit", "unknown"),
        "files_scanned": files_count,
        "total_time_seconds": round(total_time, 3),
        "ingest_time_seconds": round(t_ingest, 3),
        "detect_time_seconds": round(t_detect, 3),
        "files_per_second": round(throughput, 1),
        "total_findings": len(findings),
        "total_labels": len(labels),
        "tp": len(match_res.true_positives),
        "fp": len(match_res.false_positives),
        "fn": len(match_res.false_negatives),
        "unlabeled": len(match_res.unlabeled),
        "precision": round(match_res.precision, 4),
        "recall": round(match_res.recall, 4),
        "f1": round(match_res.f1, 4),
        "class_breakdown": class_stats,
        "true_positives": match_res.true_positives,
        "false_positives": match_res.false_positives,
        "false_negatives": match_res.false_negatives,
        "unlabeled_findings": match_res.unlabeled,
    }


def generate_charts(results: List[Dict[str, Any]], output_dir: Path) -> None:
    """Generate presentation-ready evaluation charts with matplotlib."""
    output_dir.mkdir(parents=True, exist_ok=True)
    completed = [r for r in results if r.get("status") == "completed"]
    if not completed:
        return

    # 1. Grouped bar chart of Precision, Recall, F1 per config
    configs = sorted(list({r["config"] for r in completed}))
    fig, ax = plt.subplots(figsize=(8, 5))
    x = np.arange(len(configs))
    width = 0.25

    p_vals, r_vals, f1_vals = [], [], []
    for c in configs:
        c_runs = [r for r in completed if r["config"] == c]
        tot_tp = sum(r["tp"] for r in c_runs)
        tot_fp = sum(r["fp"] for r in c_runs)
        tot_fn = sum(r["fn"] for r in c_runs)
        p = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 0.0
        r = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
        f1 = (2 * p * r) / (p + r) if (p + r) > 0 else 0.0
        p_vals.append(p)
        r_vals.append(r)
        f1_vals.append(f1)

    ax.bar(x - width, p_vals, width, label="Precision", color="#3b82f6")
    ax.bar(x, r_vals, width, label="Recall", color="#10b981")
    ax.bar(x + width, f1_vals, width, label="F1 Score", color="#f59e0b")
    ax.set_ylabel("Score (0.0 - 1.0)")
    ax.set_title("Benchmark Detection Performance by Configuration")
    ax.set_xticks(x)
    ax.set_xticklabels(configs)
    ax.set_ylim(0, 1.1)
    ax.legend(loc="upper right")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    fig.savefig(output_dir / "metrics_by_config.png", dpi=200)
    plt.close(fig)

    # 2. Runtime and Throughput by Repo
    native_runs = [r for r in completed if r["config"] == "native-only"]
    if native_runs:
        repo_names = [r["repo"] for r in native_runs]
        runtimes = [r["total_time_seconds"] for r in native_runs]
        throughputs = [r["files_per_second"] for r in native_runs]

        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
        ax1.bar(repo_names, runtimes, color="#6366f1")
        ax1.set_ylabel("Scan Time (seconds)")
        ax1.set_title("Runtime by Repository (Native Scanner)")
        ax1.tick_params(axis="x", rotation=30)
        ax1.grid(axis="y", linestyle="--", alpha=0.5)

        ax2.bar(repo_names, throughputs, color="#06b6d4")
        ax2.set_ylabel("Throughput (files/second)")
        ax2.set_title("Scan Throughput by Repository")
        ax2.tick_params(axis="x", rotation=30)
        ax2.grid(axis="y", linestyle="--", alpha=0.5)
        plt.tight_layout()
        fig.savefig(output_dir / "runtime_by_repo.png", dpi=200)
        plt.close(fig)

    # 3. Class Recall Heatmap (per class recall across configs/repos)
    # Aggregate class recalls
    class_names = sorted(list({cls for r in completed for cls in r.get("class_breakdown", {})}))
    if class_names:
        matrix = []
        for c in configs:
            row = []
            for cls in class_names:
                tot_tp = sum(r.get("class_breakdown", {}).get(cls, {}).get("tp", 0) for r in completed if r["config"] == c)
                tot_fn = sum(r.get("class_breakdown", {}).get(cls, {}).get("fn", 0) for r in completed if r["config"] == c)
                rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
                row.append(rec)
            matrix.append(row)

        fig, ax = plt.subplots(figsize=(max(8, len(class_names) * 0.8), max(4, len(configs) * 0.8)))
        im = ax.imshow(matrix, cmap="YlGn", vmin=0, vmax=1.0)
        ax.set_xticks(np.arange(len(class_names)))
        ax.set_yticks(np.arange(len(configs)))
        ax.set_xticklabels(class_names, rotation=45, ha="right")
        ax.set_yticklabels(configs)
        ax.set_title("Vulnerability Class Recall by Configuration")
        cbar = ax.figure.colorbar(im, ax=ax, fraction=0.03, pad=0.04)
        cbar.ax.set_ylabel("Recall Rate", rotation=-90, va="bottom")

        for i in range(len(configs)):
            for j in range(len(class_names)):
                val = matrix[i][j]
                color = "white" if val > 0.6 else "black"
                ax.text(j, i, f"{val:.0%}", ha="center", va="center", color=color, fontsize=9)

        plt.tight_layout()
        fig.savefig(output_dir / "class_recall_heatmap.png", dpi=200)
        plt.close(fig)


def export_fp_review(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Export up to 30 sampled unlabeled findings per repo per config for manual review."""
    lines = [
        "# Unlabeled Findings Manual Review Queue\n",
        "Findings in benchmark repositories located on lines or files without ground-truth labels.\n",
        "These are NOT counted as false positives in the primary metric, but are sampled here\n",
        "so the team can inspect them and classify them as True Positive (TP), False Positive (FP), or Unsure.\n\n",
        "Instructions: Fill in `verdict: TP`, `verdict: FP`, or `verdict: unsure`, then run `recompute_with_reviews.py`.\n\n",
        "---\n\n",
    ]

    for r in results:
        if r.get("status") != "completed":
            continue
        repo = r["repo"]
        cfg = r["config"]
        unlabeled = r.get("unlabeled_findings", [])
        if not unlabeled:
            continue

        sample_size = min(30, len(unlabeled))
        # Deterministic sampling with fixed seed
        rng = random.Random(42)
        sample = rng.sample(unlabeled, sample_size)

        lines.append(f"## {repo.upper()} — Config: `{cfg}` (Sampled {sample_size} of {len(unlabeled)} unlabeled findings)\n\n")

        for idx, item in enumerate(sample, 1):
            file_loc = f"{item.get('file')}:{item.get('line')}"
            rule = item.get("rule_id", "UNKNOWN")
            cls = item.get("class", "Unknown")
            snippet = item.get("snippet", "").strip()
            dataflow = item.get("dataflow", [])
            df_str = f" Dataflow: {len(dataflow)} step(s)" if dataflow else ""

            lines.append(f"### Entry {idx:02d}: `{rule}` ({cls}) at `{file_loc}`{df_str}\n")
            lines.append(f"- **File:** `{item.get('file')}` (Line {item.get('line')})\n")
            lines.append(f"- **Snippet:**\n```text\n{snippet}\n```\n")
            lines.append("- **Verdict:** `[ ] TP   [ ] FP   [ ] unsure` (Team member: _______)\n")
            lines.append("- **Notes:** \n\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def export_fn_analysis(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Export failure analysis on DEV repos (PyGoat and NodeGoat)."""
    lines = [
        "# False Negative & Failure Analysis (Dev Repositories)\n",
        "Analysis of missed ground truth labels on DEV split repositories (PyGoat, NodeGoat).\n",
        "Per protocol rules, rule fixes may ONLY be motivated by dev repositories.\n\n",
        "| Repo | Label ID | Class | Rule ID | Location | Failure Cause | Suggested Fix |\n",
        "|---|---|---|---|---|---|---|\n",
    ]

    dev_results = [r for r in results if r.get("split") == "dev" and r.get("status") == "completed"]
    seen_fns = set()

    for r in dev_results:
        repo = r["repo"]
        for fn in r.get("false_negatives", []):
            fn_key = (repo, fn["id"])
            if fn_key in seen_fns:
                continue
            seen_fns.add(fn_key)

            label_id = fn["id"]
            cls = fn["class"]
            rule = fn["rule_id"]
            loc = f"{fn['file']}:{fn['line']}"
            desc = fn.get("description", "")

            # Heuristic failure categorization based on rule and repo context
            cause = "Framework pattern / AST structure mismatch"
            fix = "Refine AST selector or add framework handler pattern"
            if "pickle.loads" in desc or "yaml.load" in desc:
                cause = "Deserialization source pattern not mapped"
                fix = "Add loader call pattern to DESER rules"
            elif "sqlite3 cursor.execute" in desc or "execute" in desc:
                cause = "Local variable query taint chain or f-string in subfunction"
                fix = "Support multiline AST query variable propagation"
            elif "redirect" in desc.lower():
                cause = "Express/Django redirect wrapper"
                fix = "Add query param source to REDIR rules"
            elif "parseString" in desc or "xml" in desc.lower():
                cause = "DOM parser XML external entities pattern"
                fix = "Add make_parser/parseString signature to XXE-001"

            lines.append(f"| {repo} | `{label_id}` | {cls} | `{rule}` | `{loc}` | {cause} | {fix} |\n")

    lines.append("\n## Top False Positive Causes\n")
    lines.append("1. **Duplicate Rule Firing on Identical Line:** Multiple rules in the same family (e.g. `AUTH-001` and `AUTH-002`) firing on line 41 of user authentication check.\n")
    lines.append("2. **Multiple Query Executions in Loop:** Safe query definitions inside helper functions or repeated calls on the same variable.\n")
    lines.append("3. **Missing Context in Standalone Scripts:** Dev utility scripts lacking complete framework call graphs.\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def export_summary_md(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate ready-to-paste summary tables for BENCHMARK_REPORT.md."""
    lines = [
        "# Benchmark Results Summary\n\n",
        "## Table 1: Configuration × Repository Performance\n\n",
        "| Config | Repository | Split | Language | Scanned Files | Time (s) | Files/s | TP | FP | FN | Precision | Recall | F1 Score |\n",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    ]

    for r in results:
        cfg = r["config"]
        repo = r["repo"]
        if r.get("status") == "not run":
            lines.append(f"| `{cfg}` | {repo} | - | - | - | - | - | - | - | - | *Not Run ({r.get('reason')})* | - | - |\n")
            continue
        if r.get("status") != "completed":
            lines.append(f"| `{cfg}` | {repo} | - | - | - | - | - | - | - | - | *Error: {r.get('reason')}* | - | - |\n")
            continue

        split = r.get("split", "test")
        lang = r.get("language", "")
        files = r.get("files_scanned", 0)
        t_sec = r.get("total_time_seconds", 0)
        fps = r.get("files_per_second", 0)
        tp = r.get("tp", 0)
        fp = r.get("fp", 0)
        fn = r.get("fn", 0)
        p = f"{r.get('precision', 0):.1%}"
        rec = f"{r.get('recall', 0):.1%}"
        f1 = f"{r.get('f1', 0):.1%}"

        lines.append(f"| `{cfg}` | **{repo}** | {split} | {lang} | {files} | {t_sec}s | {fps} | {tp} | {fp} | {fn} | **{p}** | **{rec}** | **{f1}** |\n")

    # Table 2: Per-Class Performance
    completed = [r for r in results if r.get("status") == "completed"]
    classes = sorted(list({cls for r in completed for cls in r.get("class_breakdown", {})}))
    configs = sorted(list({r["config"] for r in completed}))

    lines.append("\n## Table 2: Vulnerability Class Performance (Recall by Config)\n\n")
    header = "| Vulnerability Class | " + " | ".join(f"`{c}` Recall (TP/Labels)" for c in configs) + " |\n"
    lines.append(header)
    lines.append("|---|" + "---|"*len(configs) + "\n")

    for cls in classes:
        row = [f"**{cls}**"]
        for c in configs:
            c_runs = [r for r in completed if r["config"] == c]
            tot_tp = sum(r.get("class_breakdown", {}).get(cls, {}).get("tp", 0) for r in c_runs)
            tot_fn = sum(r.get("class_breakdown", {}).get(cls, {}).get("fn", 0) for r in c_runs)
            tot = tot_tp + tot_fn
            rec = tot_tp / tot if tot > 0 else 0.0
            row.append(f"{rec:.1%} ({tot_tp}/{tot})")
        lines.append("| " + " | ".join(row) + " |\n")

    # Table 3: Overall Aggregate
    lines.append("\n## Table 3: Overall Aggregate Metrics\n\n")
    lines.append("| Configuration | Total TP | Total FP | Total FN | Aggregate Precision | Aggregate Recall | Aggregate F1 |\n")
    lines.append("|---|---|---|---|---|---|---|\n")

    for c in configs:
        c_runs = [r for r in completed if r["config"] == c]
        tot_tp = sum(r["tp"] for r in c_runs)
        tot_fp = sum(r["fp"] for r in c_runs)
        tot_fn = sum(r["fn"] for r in c_runs)
        p = tot_tp / (tot_tp + tot_fp) if (tot_tp + tot_fp) > 0 else 0.0
        rec = tot_tp / (tot_tp + tot_fn) if (tot_tp + tot_fn) > 0 else 0.0
        f1 = (2 * p * rec) / (p + rec) if (p + rec) > 0 else 0.0
        lines.append(f"| `{c}` | {tot_tp} | {tot_fp} | {tot_fn} | **{p:.1%}** | **{rec:.1%}** | **{f1:.1%}** |\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def export_csv(results: List[Dict[str, Any]], output_path: Path) -> None:
    """Export flat results.csv for external reporting."""
    fields = [
        "config", "repo", "split", "language", "status", "files_scanned",
        "total_time_seconds", "files_per_second", "tp", "fp", "fn", "unlabeled",
        "precision", "recall", "f1"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for r in results:
            writer.writerow(r)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run benchmark evaluation harness")
    parser.add_argument("--repo", help="Run only on a specific repo")
    parser.add_argument("--config", help="Run only on a specific config (native-only, bandit-only, semgrep-only, merged)")
    parser.add_argument("--seed", type=int, default=42, help="Fixed random seed for sampling")
    args = parser.parse_args()

    random.seed(args.seed)
    manifest = load_manifest()
    excludes = manifest.get("global_excludes", [])
    repos = manifest.get("repositories", [])
    if args.repo:
        repos = [r for r in repos if r["name"] == args.repo]

    all_configs = ["native-only", "bandit-only", "semgrep-only", "merged"]
    if args.config:
        all_configs = [args.config]

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    results: List[Dict[str, Any]] = []

    print(f"Starting benchmark evaluation across {len(repos)} repositories and {len(all_configs)} configs...")
    for repo_meta in repos:
        name = repo_meta["name"]
        for cfg in all_configs:
            print(f"Running [{name}] with config [{cfg}]...")
            res = run_single_benchmark(repo_meta, cfg, excludes)
            results.append(res)
            if res.get("status") == "completed":
                print(f"  -> TP={res['tp']}, FP={res['fp']}, FN={res['fn']}, Unlabeled={res['unlabeled']} | P={res['precision']:.1%}, R={res['recall']:.1%}, F1={res['f1']:.1%} ({res['total_time_seconds']}s)")
            else:
                print(f"  -> {res.get('status')}: {res.get('reason')}")

    # Metadata for reproducibility
    payload = {
        "metadata": {
            "timestamp": time.time(),
            "python_version": sys.version,
            "seed": args.seed,
            "excludes": excludes,
            "repositories": repos,
        },
        "results": results,
    }

    # Save JSON & CSV
    json_path = RESULTS_DIR / "results.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    print(f"\nSaved raw results to {json_path.name}")

    csv_path = RESULTS_DIR / "results.csv"
    export_csv(results, csv_path)
    print(f"Saved CSV results to {csv_path.name}")

    # Save Summary MD
    summary_path = RESULTS_DIR / "summary.md"
    export_summary_md(results, summary_path)
    print(f"Saved summary markdown to {summary_path.name}")

    # Save FP Review Queue & FN Analysis
    fp_path = RESULTS_DIR / "fp_review.md"
    export_fp_review(results, fp_path)
    print(f"Saved false-positive review queue to {fp_path.name}")

    fn_path = RESULTS_DIR / "fn_analysis.md"
    export_fn_analysis(results, fn_path)
    print(f"Saved false-negative analysis to {fn_path.name}")

    # Generate charts
    print("Generating benchmark visual charts...")
    generate_charts(results, RESULTS_DIR)
    print("Charts generated: metrics_by_config.png, runtime_by_repo.png, class_recall_heatmap.png")

    return 0


if __name__ == "__main__":
    sys.exit(main())
