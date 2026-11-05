# Benchmark Results Summary

## Table 1: Configuration × Repository Performance

| Config | Repository | Split | Language | Scanned Files | Time (s) | Files/s | TP | FP | FN | Precision | Recall | F1 Score |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `native-only` | **pygoat** | dev | python | 463 | 1.826s | 253.5 | 11 | 2 | 0 | **84.6%** | **100.0%** | **91.7%** |
| `bandit-only` | pygoat | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | pygoat | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **pygoat** | dev | python | 463 | 2.003s | 231.2 | 11 | 2 | 0 | **84.6%** | **100.0%** | **91.7%** |
| `native-only` | **nodegoat** | dev | javascript | 74 | 0.442s | 167.5 | 5 | 0 | 2 | **100.0%** | **71.4%** | **83.3%** |
| `bandit-only` | nodegoat | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | nodegoat | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **nodegoat** | dev | javascript | 74 | 0.667s | 110.9 | 5 | 0 | 2 | **100.0%** | **71.4%** | **83.3%** |
| `native-only` | **vulpy** | test | python | 113 | 0.388s | 290.9 | 4 | 0 | 1 | **100.0%** | **80.0%** | **88.9%** |
| `bandit-only` | vulpy | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | vulpy | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **vulpy** | test | python | 113 | 0.565s | 199.9 | 4 | 0 | 1 | **100.0%** | **80.0%** | **88.9%** |
| `native-only` | **dvpwa** | test | python | 56 | 4.95s | 11.3 | 2 | 1 | 1 | **66.7%** | **66.7%** | **66.7%** |
| `bandit-only` | dvpwa | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | dvpwa | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **dvpwa** | test | python | 56 | 5.082s | 11.0 | 2 | 1 | 1 | **66.7%** | **66.7%** | **66.7%** |
| `native-only` | **juice-shop** | test | typescript | 1310 | 24.482s | 53.5 | 2 | 1 | 11 | **66.7%** | **15.4%** | **25.0%** |
| `bandit-only` | juice-shop | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | juice-shop | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **juice-shop** | test | typescript | 1310 | 24.185s | 54.2 | 2 | 1 | 11 | **66.7%** | **15.4%** | **25.0%** |
| `native-only` | **dvna** | test | javascript | 149 | 0.303s | 491.9 | 4 | 0 | 3 | **100.0%** | **57.1%** | **72.7%** |
| `bandit-only` | dvna | - | - | - | - | - | - | - | - | *Not Run (Bandit scanner is not installed or not available on PATH.)* | - | - |
| `semgrep-only` | dvna | - | - | - | - | - | - | - | - | *Not Run (Semgrep scanner is not installed or not available on PATH.)* | - | - |
| `merged` | **dvna** | test | javascript | 149 | 0.469s | 317.4 | 4 | 0 | 3 | **100.0%** | **57.1%** | **72.7%** |

## Table 2: Vulnerability Class Performance (Recall by Config)

| Vulnerability Class | `merged` Recall (TP/Labels) | `native-only` Recall (TP/Labels) |
|---|---|---|
| **Broken Authentication** | 75.0% (6/8) | 75.0% (6/8) |
| **Command Injection** | 100.0% (2/2) | 100.0% (2/2) |
| **Hardcoded Secrets** | 0.0% (0/1) | 0.0% (0/1) |
| **Insecure Cryptography** | 33.3% (1/3) | 33.3% (1/3) |
| **Open Redirect** | 33.3% (2/6) | 33.3% (2/6) |
| **Path Traversal** | 0.0% (0/4) | 0.0% (0/4) |
| **SQL Injection** | 66.7% (8/12) | 66.7% (8/12) |
| **Server-Side Request Forgery** | 50.0% (1/2) | 50.0% (1/2) |
| **Unsafe Deserialization** | 100.0% (7/7) | 100.0% (7/7) |
| **XML External Entity** | 100.0% (1/1) | 100.0% (1/1) |

## Table 3: Overall Aggregate Metrics

| Configuration | Total TP | Total FP | Total FN | Aggregate Precision | Aggregate Recall | Aggregate F1 |
|---|---|---|---|---|---|---|
| `merged` | 28 | 4 | 18 | **87.5%** | **60.9%** | **71.8%** |
| `native-only` | 28 | 4 | 18 | **87.5%** | **60.9%** | **71.8%** |
