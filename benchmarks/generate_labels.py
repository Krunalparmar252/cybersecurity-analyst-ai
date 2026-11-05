#!/usr/bin/env python3
"""
Generate and verify ground truth labels for Phase 3 benchmark repositories.
Extracts annotations from Juice Shop, parses documentation/code for other repos,
generates review_queue.md with code excerpts, and records out_of_scope.json.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List
import yaml

BENCHMARKS_DIR = Path(__file__).resolve().parent
ROOT_DIR = BENCHMARKS_DIR.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
REPOS_DIR = BENCHMARKS_DIR / "repos"
LABELS_DIR = BENCHMARKS_DIR / "labels"
RESULTS_DIR = BENCHMARKS_DIR / "results"
REVIEW_QUEUE_PATH = BENCHMARKS_DIR / "review_queue.md"
OUT_OF_SCOPE_PATH = BENCHMARKS_DIR / "out_of_scope.json"


def normalize_relpath(path: str) -> str:
    return path.replace("\\", "/").lstrip("./")


def parse_juice_shop_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """
    Parse vuln-code-snippet annotations from Juice Shop source files.
    Returns (in_scope_labels, out_of_scope_items).
    """
    challenges_file = repo_dir / "data" / "static" / "challenges.yml"
    challenges: Dict[str, Any] = {}
    if challenges_file.exists():
        with open(challenges_file, "r", encoding="utf-8") as f:
            for item in yaml.safe_load(f):
                challenges[item["key"]] = item

    # Mapping of challenge key or category to our rule IDs and classes
    IN_SCOPE_CHALLENGE_MAP = {
        "unionSqlInjectionChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "dbSchemaChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "loginAdminChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "loginBenderChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "loginJimChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "noSqlReviewsChallenge": {
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
        },
        "redirectChallenge": {
            "rule_id": "REDIR-001",
            "class": "Open Redirect",
            "cwe": "CWE-601",
        },
        "redirectCryptoCurrencyChallenge": {
            "rule_id": "REDIR-001",
            "class": "Open Redirect",
            "cwe": "CWE-601",
        },
        "weakPasswordChallenge": {
            "rule_id": "AUTH-006",
            "class": "Broken Authentication",
            "cwe": "CWE-328",
        },
        "directoryListingChallenge": {
            "rule_id": "PATHTRAV-002",
            "class": "Path Traversal",
            "cwe": "CWE-22",
        },
        "accessLogDisclosureChallenge": {
            "rule_id": "PATHTRAV-002",
            "class": "Path Traversal",
            "cwe": "CWE-22",
        },
    }

    in_scope_labels: List[Dict[str, Any]] = []
    out_of_scope_counts: Dict[str, int] = {}
    seen_keys: set[str] = set()

    for p in repo_dir.rglob("*"):
        if not p.is_file() or p.suffix not in [".ts", ".js"]:
            continue
        rel = normalize_relpath(str(p.relative_to(repo_dir)))
        if any(rel.startswith(x) for x in ["test/", "tests/", "dist/", "build/", "frontend/src/app/"]):
            continue

        text = p.read_text(encoding="utf-8", errors="ignore")
        for line_num, line in enumerate(text.splitlines(), 1):
            m = re.search(r"//\s*vuln-code-snippet\s+vuln-line\s+([\w\s]+)", line)
            if not m:
                continue
            keys = m.group(1).split()
            for k in keys:
                ch = challenges.get(k, {})
                cat = ch.get("category", "Unknown")
                name = ch.get("name", k)

                if k in IN_SCOPE_CHALLENGE_MAP:
                    mapping = IN_SCOPE_CHALLENGE_MAP[k]
                    label_id = f"GT-JUICE-{k}-{line_num}"
                    # Avoid duplicate label on the exact same file/line/rule
                    if any(l["file"] == rel and l["line"] == line_num and l["rule_id"] == mapping["rule_id"] for l in in_scope_labels):
                        continue
                    in_scope_labels.append({
                        "id": label_id,
                        "file": rel,
                        "line": line_num,
                        "rule_id": mapping["rule_id"],
                        "class": mapping["class"],
                        "cwe": mapping["cwe"],
                        "description": f"Juice Shop challenge '{name}' ({k}): {cat}",
                        "label_source": "vuln-code-snippet annotation",
                        "confidence": 1.0,
                        "reviewed": False,
                    })
                else:
                    out_of_scope_counts[cat] = out_of_scope_counts.get(cat, 0) + 1

    out_of_scope = [
        {"class": cat, "count": count, "repo": "juice-shop"}
        for cat, count in sorted(out_of_scope_counts.items())
    ]
    return in_scope_labels, out_of_scope


def build_pygoat_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ground truth labels for OWASP PyGoat (dev split)."""
    labels = [
        {
            "id": "GT-PYGOAT-SQLI-01",
            "file": "dockerized_labs/sql_injection_lab/app.py",
            "line": 50,
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "sqlite3 cursor.execute with raw f-string formatted query from form input",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-CMDINJ-01",
            "file": "dockerized_labs/command_injection_lab/app.py",
            "line": 29,
            "rule_id": "CMDINJ-001",
            "class": "Command Injection",
            "cwe": "CWE-78",
            "description": "subprocess.Popen with shell=True executing user-controlled command",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-SSRF-01",
            "file": "dockerized_labs/ssrf_lab/app.py",
            "line": 37,
            "rule_id": "SSRF-001",
            "class": "Server-Side Request Forgery",
            "cwe": "CWE-918",
            "description": "requests.get called with untrusted user-supplied url parameter",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-DESER-01",
            "file": "dockerized_labs/insec_des_lab/main.py",
            "line": 40,
            "rule_id": "DESER-001",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "pickle.loads called on base64-decoded user cookie data",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-DESER-02",
            "file": "dockerized_labs/software_integrity_lab/app.py",
            "line": 44,
            "rule_id": "DESER-001",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "pickle.loads on base64-decoded token payload",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-DESER-03",
            "file": "dockerized_labs/a9_uckv_lab/app.py",
            "line": 62,
            "rule_id": "DESER-001",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "yaml.load with Loader=yaml.Loader on untrusted uploaded file",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-AUTH-01",
            "file": "dockerized_labs/crypto_failure_lab/app.py",
            "line": 25,
            "rule_id": "AUTH-002",
            "class": "Broken Authentication",
            "cwe": "CWE-328",
            "description": "hashlib.sha1 applied to password",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-AUTH-02",
            "file": "dockerized_labs/crypto_failure_lab/app.py",
            "line": 38,
            "rule_id": "AUTH-002",
            "class": "Broken Authentication",
            "cwe": "CWE-328",
            "description": "hashlib.md5 applied to password",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-CRYPTO-01",
            "file": "dockerized_labs/broken_auth_lab/app.py",
            "line": 103,
            "rule_id": "CRYPTO-001",
            "class": "Insecure Cryptography",
            "cwe": "CWE-328",
            "description": "hashlib.md5 used to generate password reset token",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-XXE-01",
            "file": "dockerized_labs/xxe_lab/app.py",
            "line": 61,
            "rule_id": "XXE-001",
            "class": "XML External Entity",
            "cwe": "CWE-611",
            "description": "parseString with feature_external_ges enabled without defusedxml",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-PYGOAT-CONFIG-01",
            "file": "dockerized_labs/xss_lab/app.py",
            "line": 86,
            "rule_id": "CONFIG-002",
            "class": "Broken Authentication",
            "cwe": "CWE-614",
            "description": "Cookie set without secure or httponly flags",
            "label_source": "lesson source code",
            "confidence": 1.0,
            "reviewed": False,
        },
    ]
    out_of_scope = [
        {"class": "Broken Access Control (A1)", "count": 2, "repo": "pygoat"},
        {"class": "Sensitive Data Exposure (robots.txt)", "count": 1, "repo": "pygoat"},
        {"class": "Insufficient Logging (A10)", "count": 1, "repo": "pygoat"},
        {"class": "Insecure Design (Rate Limiting/Lockout)", "count": 1, "repo": "pygoat"},
    ]
    return labels, out_of_scope


def build_nodegoat_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ground truth labels for OWASP NodeGoat (dev split)."""
    labels = [
        {
            "id": "GT-NODEGOAT-DESER-01",
            "file": "app/routes/contributions.js",
            "line": 32,
            "rule_id": "DESER-002",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "Insecure use of eval() to evaluate user-supplied input (preTax)",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-DESER-02",
            "file": "app/routes/contributions.js",
            "line": 33,
            "rule_id": "DESER-002",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "Insecure use of eval() to evaluate user-supplied input (afterTax)",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-DESER-03",
            "file": "app/routes/contributions.js",
            "line": 34,
            "rule_id": "DESER-002",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "Insecure use of eval() to evaluate user-supplied input (roth)",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-SQLI-01",
            "file": "app/data/allocations-dao.js",
            "line": 78,
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "NoSQL $where clause with unsanitized threshold parameter",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-REDIR-01",
            "file": "app/routes/index.js",
            "line": 72,
            "rule_id": "REDIR-001",
            "class": "Open Redirect",
            "cwe": "CWE-601",
            "description": "res.redirect takes user-controlled url from query string",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-AUTH-01",
            "file": "app/data/user-dao.js",
            "line": 61,
            "rule_id": "AUTH-005",
            "class": "Broken Authentication",
            "cwe": "CWE-287",
            "description": "Plain === equality check for stored password instead of bcrypt compare",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-NODEGOAT-CRYPTO-01",
            "file": "app/data/user-dao.js",
            "line": 51,
            "rule_id": "CRYPTO-003",
            "class": "Insecure Cryptography",
            "cwe": "CWE-338",
            "description": "Math.random() used to generate security-sensitive user data",
            "label_source": "lesson comments in source",
            "confidence": 1.0,
            "reviewed": False,
        },
    ]
    out_of_scope = [
        {"class": "Insecure Direct Object Reference (A4)", "count": 1, "repo": "nodegoat"},
        {"class": "Cross-Site Request Forgery (CSRF / A8)", "count": 1, "repo": "nodegoat"},
        {"class": "CRLF / Log Injection (A1-3)", "count": 1, "repo": "nodegoat"},
    ]
    return labels, out_of_scope


def build_vulpy_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ground truth labels for Vulpy (test split)."""
    labels = [
        {
            "id": "GT-VULPY-SQLI-01",
            "file": "bad/libuser.py",
            "line": 12,
            "rule_id": "SQLI-002",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "sqlite3 cursor.execute with .format() query concatenation in user login",
            "label_source": "project source comparison (bad vs good)",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-VULPY-SQLI-02",
            "file": "bad/libuser.py",
            "line": 53,
            "rule_id": "SQLI-002",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "sqlite3 cursor.execute with .format() query concatenation in user update",
            "label_source": "project source comparison (bad vs good)",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-VULPY-CONFIG-01",
            "file": "bad/libsession.py",
            "line": 7,
            "rule_id": "CONFIG-002",
            "class": "Broken Authentication",
            "cwe": "CWE-614",
            "description": "set_cookie for session cookie without secure/httponly flags",
            "label_source": "project source comparison (bad vs good)",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-VULPY-SSRF-01",
            "file": "bad/api_list.py",
            "line": 10,
            "rule_id": "SSRF-001",
            "class": "Server-Side Request Forgery",
            "cwe": "CWE-918",
            "description": "requests.get with user-controlled parameter concatenation",
            "label_source": "project source comparison (bad vs good)",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-VULPY-SQLI-03",
            "file": "bad/db.py",
            "line": 19,
            "rule_id": "SQLI-002",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "cursor.execute with % format string interpolation",
            "label_source": "project source comparison (bad vs good)",
            "confidence": 1.0,
            "reviewed": False,
        },
    ]
    out_of_scope = [
        {"class": "Brute Force Protection Missing", "count": 1, "repo": "vulpy"},
        {"class": "MFA Bypass", "count": 1, "repo": "vulpy"},
        {"class": "Clickjacking (X-Frame-Options)", "count": 1, "repo": "vulpy"},
    ]
    return labels, out_of_scope


def build_dvpwa_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ground truth labels for DVPWA (test split)."""
    labels = [
        {
            "id": "GT-DVPWA-AUTH-01",
            "file": "sqli/dao/user.py",
            "line": 41,
            "rule_id": "AUTH-002",
            "class": "Broken Authentication",
            "cwe": "CWE-328",
            "description": "md5 applied to password in check_password",
            "label_source": "project source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVPWA-SQLI-01",
            "file": "sqli/dao/student.py",
            "line": 45,
            "rule_id": "SQLI-002",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "cur.execute with % interpolation in INSERT query",
            "label_source": "project source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVPWA-SQLI-02",
            "file": "sqli/dao/course.py",
            "line": 47,
            "rule_id": "SQLI-002",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "cur.execute with dynamically composed SQL query",
            "label_source": "project source code",
            "confidence": 1.0,
            "reviewed": False,
        },
    ]
    out_of_scope = [
        {"class": "Session Invalidation on Logout", "count": 1, "repo": "dvpwa"},
    ]
    return labels, out_of_scope


def build_dvna_labels(repo_dir: Path) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Ground truth labels for DVNA (test split)."""
    labels = [
        {
            "id": "GT-DVNA-SQLI-01",
            "file": "core/appHandler.js",
            "line": 11,
            "rule_id": "SQLI-001",
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "description": "db.sequelize.query with raw string concatenation of req.body.login",
            "label_source": "project documentation and vulns.js",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-CMDINJ-01",
            "file": "core/appHandler.js",
            "line": 39,
            "rule_id": "CMDINJ-002",
            "class": "Command Injection",
            "cwe": "CWE-78",
            "description": "child_process.exec with concatenated user address parameter",
            "label_source": "project documentation and vulns.js",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-REDIR-01",
            "file": "core/appHandler.js",
            "line": 188,
            "rule_id": "REDIR-001",
            "class": "Open Redirect",
            "cwe": "CWE-601",
            "description": "res.redirect called with unsanitized req.query.url parameter",
            "label_source": "project documentation and vulns.js",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-DESER-01",
            "file": "core/appHandler.js",
            "line": 218,
            "rule_id": "DESER-003",
            "class": "Unsafe Deserialization",
            "cwe": "CWE-502",
            "description": "serialize.unserialize called on user-supplied uploaded file data",
            "label_source": "project documentation and vulns.js",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-CRYPTO-01",
            "file": "core/authHandler.js",
            "line": 49,
            "rule_id": "CRYPTO-001",
            "class": "Insecure Cryptography",
            "cwe": "CWE-328",
            "description": "md5 applied to security verification token",
            "label_source": "project documentation and vulns.js",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-SECRET-01",
            "file": "server.js",
            "line": 24,
            "rule_id": "SECRET-001",
            "class": "Hardcoded Secrets",
            "cwe": "CWE-798",
            "description": "Hardcoded session secret 'keyboard cat'",
            "label_source": "project source code",
            "confidence": 1.0,
            "reviewed": False,
        },
        {
            "id": "GT-DVNA-CONFIG-01",
            "file": "server.js",
            "line": 27,
            "rule_id": "CONFIG-002",
            "class": "Broken Authentication",
            "cwe": "CWE-614",
            "description": "Session cookie configured with secure: false",
            "label_source": "project source code",
            "confidence": 1.0,
            "reviewed": False,
        },
    ]
    out_of_scope = [
        {"class": "A4: XML External Entities (XXE via frontend)", "count": 1, "repo": "dvna"},
        {"class": "A5: Broken Access Control", "count": 1, "repo": "dvna"},
        {"class": "A9: Using Components with Known Vulnerabilities", "count": 1, "repo": "dvna"},
        {"class": "A10: Insufficient Logging", "count": 1, "repo": "dvna"},
        {"class": "CSRF", "count": 1, "repo": "dvna"},
    ]
    return labels, out_of_scope


def get_excerpt(file_path: Path, line_num: int) -> str:
    """Return a 3-line excerpt centered around line_num."""
    if not file_path.exists():
        return "[File not found]"
    lines = file_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    start = max(0, line_num - 2)
    end = min(len(lines), line_num + 1)
    excerpt_lines = []
    for idx in range(start, end):
        prefix = " > " if idx + 1 == line_num else "   "
        excerpt_lines.append(f"{prefix}{idx + 1:4d} | {lines[idx]}")
    return "\n".join(excerpt_lines)


def main() -> int:
    LABELS_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    all_out_of_scope: List[Dict[str, Any]] = []
    review_queue_entries: List[str] = [
        "# Benchmark Ground Truth Review Queue\n",
        "Every label in the benchmark ground truth starts with `reviewed: false`.\n",
        "This queue displays each label with its file, line number, rule class, and a 3-line code excerpt.\n",
        "Team members must inspect each excerpt before marking `reviewed: true` in `benchmarks/labels/<repo>.json`.\n\n",
        "| ID | Repo | Class | File:Line | Source | Reviewed |\n",
        "|---|---|---|---|---|---|\n",
    ]

    detail_sections: List[str] = ["\n## Code Excerpts for Manual Review\n"]

    repo_builders = [
        ("pygoat", build_pygoat_labels),
        ("nodegoat", build_nodegoat_labels),
        ("vulpy", build_vulpy_labels),
        ("dvpwa", build_dvpwa_labels),
        ("juice-shop", parse_juice_shop_labels),
        ("dvna", build_dvna_labels),
    ]

    total_labels = 0
    for repo_name, builder in repo_builders:
        repo_dir = REPOS_DIR / repo_name
        labels, out_of_scope = builder(repo_dir)
        all_out_of_scope.extend(out_of_scope)

        # Write labels file
        label_file = LABELS_DIR / f"{repo_name}.json"
        with open(label_file, "w", encoding="utf-8") as f:
            json.dump(labels, f, indent=2)

        total_labels += len(labels)
        print(f"[{repo_name}] Generated {len(labels)} labels -> {label_file.name}")

        detail_sections.append(f"\n### {repo_name.upper()} ({len(labels)} labels)\n")
        for item in labels:
            rel_file = item["file"]
            line = item["line"]
            full_path = repo_dir / rel_file
            excerpt = get_excerpt(full_path, line)

            review_queue_entries.append(
                f"| `{item['id']}` | {repo_name} | {item['class']} | `{rel_file}:{line}` | {item['label_source']} | {item['reviewed']} |\n"
            )

            detail_sections.append(
                f"#### `{item['id']}` — {item['class']} (`{item['rule_id']}`)\n"
                f"- **Location:** `{repo_name}/{rel_file}:{line}`\n"
                f"- **Description:** {item['description']}\n"
                f"- **Source:** {item['label_source']} | **Reviewed:** {item['reviewed']}\n\n"
                f"```text\n{excerpt}\n```\n"
            )

    # Write review_queue.md
    with open(REVIEW_QUEUE_PATH, "w", encoding="utf-8") as f:
        f.writelines(review_queue_entries)
        f.writelines(detail_sections)
    print(f"Generated review queue with {total_labels} labels -> {REVIEW_QUEUE_PATH.name}")

    # Write out_of_scope.json
    with open(OUT_OF_SCOPE_PATH, "w", encoding="utf-8") as f:
        json.dump(all_out_of_scope, f, indent=2)
    print(f"Generated out_of_scope list ({len(all_out_of_scope)} categories) -> {OUT_OF_SCOPE_PATH.name}")

    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
