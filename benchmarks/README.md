# Phase 3 Benchmark Evaluation Suite

Public benchmark evaluation suite for Autonomous Cybersecurity Analyst AI across intentionally vulnerable Python, JavaScript, and TypeScript open-source projects.

## Supported Repositories

| Repository | Split | Language | Pinned Commit SHA | Description |
|---|---|---|---|---|
| **PyGoat** | `dev` | Python | `2aa4cc14` | OWASP PyGoat (Django) |
| **NodeGoat** | `dev` | JavaScript | `c5cb68a7` | OWASP NodeGoat (Express/MongoDB) |
| **Vulpy** | `test` | Python | `5249cc8b` | Vulpy (Flask) |
| **DVPWA** | `test` | Python | `a1d8f89f` | Damn Vulnerable Python Web App (Flask) |
| **OWASP Juice Shop** | `test` | TypeScript / JS | `717f5efa` | OWASP Juice Shop (Angular / Express) |
| **DVNA** | `test` | JavaScript | `9ba473ad` | Damn Vulnerable NodeJS App (Express / Sequelize) |

> **Protocol Rule:**
> - `dev` split repositories (PyGoat, NodeGoat) are permitted for inspection and bug fixes.
> - `test` split repositories (Vulpy, DVPWA, Juice Shop, DVNA) are strictly held-out for honest evaluation reporting.

---

## Quickstart

### 1. Fetch Repositories
Clones all benchmark repositories safely at their pinned commit SHAs without executing any downloaded code:
```bash
python benchmarks/fetch.py
```

### 2. Generate Ground Truth Labels & Review Queue
Extracts annotations (e.g., Juice Shop `vuln-code-snippet`), maps documented challenge endpoints, produces `labels/*.json`, `review_queue.md`, and `out_of_scope.json`:
```bash
python benchmarks/generate_labels.py
```

### 3. Run Benchmark Evaluation
Runs evaluation harness across configurations (`native-only`, `bandit-only`, `semgrep-only`, `merged`):
```bash
python benchmarks/run_benchmarks.py
```

### 4. Review Sampled Unlabeled Findings & Recompute Precision
Review `benchmarks/results/fp_review.md` and enter verdicts (`[x] TP`, `[x] FP`, or `[x] unsure`), then recompute:
```bash
python benchmarks/recompute_with_reviews.py
```

---

## Output Artifacts

- `benchmarks/manifest.yaml`: Pinned commit SHAs, language metadata, licenses, and global exclusion patterns.
- `benchmarks/labels/<repo>.json`: Ground truth vulnerability labels (`file`, `line`, `rule_id`, `class`, `cwe`, `label_source`, `confidence`, `reviewed`).
- `benchmarks/review_queue.md`: Complete queue with 3-line source code excerpts for manual human verification.
- `benchmarks/out_of_scope.json`: Honest accounting of vulnerability classes outside our detection scope (e.g., CSRF, prompt injection, clickjacking).
- `benchmarks/results/results.json`: Machine-readable results with seed, versions, and per-finding data.
- `benchmarks/results/results.csv`: Flat tabular metrics.
- `benchmarks/results/summary.md`: Performance breakdown by repo and vulnerability class.
- `benchmarks/results/metrics_by_config.png`: Grouped bar chart of Precision, Recall, and F1.
- `benchmarks/results/runtime_by_repo.png`: Runtime and scan throughput (files/second).
- `benchmarks/results/class_recall_heatmap.png`: Heatmap of recall by vulnerability class.
- `benchmarks/results/fp_review.md`: Sampled unlabeled findings queue for manual verification.
- `benchmarks/results/fn_analysis.md`: Detailed failure and false-negative root cause analysis on DEV split repositories.
