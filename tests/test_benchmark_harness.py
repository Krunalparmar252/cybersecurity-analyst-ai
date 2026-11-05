"""
Unit tests for Phase 3 Benchmark Evaluation Harness.
Covers label parsing, tolerance matching, one-to-one deduplication,
class mismatch, unlabeled separation, synthetic metric calculations,
and missing scanner handling.
Does NOT require network access or cloned repositories.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
import pytest
from benchmarks.matcher import (
    MatchResult,
    classes_match,
    match_findings_to_labels,
    normalize_path,
)
from benchmarks.generate_labels import parse_juice_shop_labels
from benchmarks.run_benchmarks import is_path_excluded, run_single_benchmark


def test_normalize_path():
    assert normalize_path(r"app\routes\index.js") == "app/routes/index.js"
    assert normalize_path("./app/routes/index.js") == "app/routes/index.js"
    assert normalize_path("app/routes/index.js") == "app/routes/index.js"


def test_classes_match():
    # Exact and case-insensitive
    assert classes_match("SQL Injection", "sql injection")
    assert classes_match("Open Redirect", "OPEN REDIRECT")

    # Family equivalence
    assert classes_match("SQL Injection", "SQLI")
    assert classes_match("Cross-Site Scripting", "XSS")
    assert classes_match("Command Injection", "CMDINJ")
    assert classes_match("Path Traversal", "Zip Slip")
    assert classes_match("Unsafe Deserialization", "Insecure Deserialization")
    assert classes_match("Broken Authentication", "Insecure Authentication")

    # CWE matching
    assert classes_match("Broken Authentication", "Insecure Cryptography", cwe1="CWE-328", cwe2="CWE-328")

    # Negative mismatch
    assert not classes_match("SQL Injection", "Command Injection", cwe1="CWE-89", cwe2="CWE-78")
    assert not classes_match("Cross-Site Scripting", "Path Traversal")


def test_matcher_exact_match():
    labels = [
        {
            "id": "GT-TEST-01",
            "file": "app/db.py",
            "line": 42,
            "class": "SQL Injection",
            "cwe": "CWE-89",
        }
    ]
    findings = [
        {
            "file": "app/db.py",
            "line": 42,
            "class": "SQL Injection",
            "cwe": "CWE-89",
            "rule_id": "SQLI-001",
        }
    ]
    res = match_findings_to_labels(findings, labels)
    assert len(res.true_positives) == 1
    assert len(res.false_positives) == 0
    assert len(res.false_negatives) == 0
    assert len(res.unlabeled) == 0
    assert res.precision == 1.0
    assert res.recall == 1.0
    assert res.f1 == 1.0


def test_matcher_tolerance_boundary():
    labels = [
        {
            "id": "GT-TEST-01",
            "file": "app/db.py",
            "line": 50,
            "class": "SQL Injection",
            "cwe": "CWE-89",
        }
    ]
    # Line 47 (within -3 tolerance)
    res_minus_3 = match_findings_to_labels(
        [{"file": "app/db.py", "line": 47, "class": "SQL Injection"}], labels, tolerance=3
    )
    assert len(res_minus_3.true_positives) == 1

    # Line 53 (within +3 tolerance)
    res_plus_3 = match_findings_to_labels(
        [{"file": "app/db.py", "line": 53, "class": "SQL Injection"}], labels, tolerance=3
    )
    assert len(res_plus_3.true_positives) == 1

    # Line 54 (outside +3 tolerance -> unlabeled line)
    res_outside = match_findings_to_labels(
        [{"file": "app/db.py", "line": 54, "class": "SQL Injection"}], labels, tolerance=3
    )
    assert len(res_outside.true_positives) == 0
    assert len(res_outside.false_negatives) == 1
    assert len(res_outside.unlabeled) == 1


def test_matcher_one_to_one():
    labels = [
        {
            "id": "GT-TEST-01",
            "file": "app/auth.py",
            "line": 20,
            "class": "Broken Authentication",
            "cwe": "CWE-287",
        }
    ]
    # Two findings for the same label
    findings = [
        {"file": "app/auth.py", "line": 20, "class": "Broken Authentication", "rule_id": "AUTH-001"},
        {"file": "app/auth.py", "line": 21, "class": "Broken Authentication", "rule_id": "AUTH-002"},
    ]
    res = match_findings_to_labels(findings, labels, tolerance=3)
    assert len(res.true_positives) == 1
    # Second duplicate finding on the labeled line is an FP
    assert len(res.false_positives) == 1
    assert len(res.false_negatives) == 0
    assert res.precision == 0.5
    assert res.recall == 1.0


def test_matcher_class_mismatch():
    labels = [
        {
            "id": "GT-TEST-01",
            "file": "app/run.py",
            "line": 15,
            "class": "SQL Injection",
            "cwe": "CWE-89",
        }
    ]
    # Finding at line 15 with wrong vulnerability class
    findings = [
        {"file": "app/run.py", "line": 15, "class": "Command Injection", "cwe": "CWE-78"}
    ]
    res = match_findings_to_labels(findings, labels, tolerance=3)
    assert len(res.true_positives) == 0
    assert len(res.false_positives) == 1
    assert len(res.false_negatives) == 1
    assert res.precision == 0.0
    assert res.recall == 0.0


def test_matcher_unlabeled_separation():
    labels = [
        {
            "id": "GT-TEST-01",
            "file": "app/routes.py",
            "line": 10,
            "class": "Open Redirect",
        }
    ]
    findings = [
        # Finding in unlabeled file
        {"file": "app/utils/helper.py", "line": 99, "class": "Hardcoded Secrets"},
        # Finding in labeled file but 80 lines away from any label
        {"file": "app/routes.py", "line": 90, "class": "SQL Injection"},
    ]
    res = match_findings_to_labels(findings, labels, tolerance=3)
    assert len(res.true_positives) == 0
    assert len(res.false_positives) == 0
    assert len(res.false_negatives) == 1
    assert len(res.unlabeled) == 2


def test_metric_calculations_synthetic():
    tp_items = [{"id": f"TP-{i}"} for i in range(8)]
    fp_items = [{"id": f"FP-{i}"} for i in range(2)]
    fn_items = [{"id": f"FN-{i}"} for i in range(2)]
    unlabeled_items = [{"id": f"UN-{i}"} for i in range(5)]

    res = MatchResult(
        true_positives=tp_items,
        false_positives=fp_items,
        false_negatives=fn_items,
        unlabeled=unlabeled_items,
        total_labels=10,
        total_findings=15,
    )
    assert res.precision == pytest.approx(0.8)
    assert res.recall == pytest.approx(0.8)
    assert res.f1 == pytest.approx(0.8)


def test_path_exclusion():
    excludes = ["**/node_modules/**", "**/dist/**", "**/*.min.js", "**/test/**"]
    assert is_path_excluded("node_modules/express/index.js", excludes)
    assert is_path_excluded("dist/bundle.js", excludes)
    assert is_path_excluded("public/jquery.min.js", excludes)
    assert is_path_excluded("test/unit.js", excludes)
    assert not is_path_excluded("routes/api.js", excludes)
    assert not is_path_excluded("server.ts", excludes)


def test_synthetic_juice_shop_label_parser(tmp_path: Path):
    # Create synthetic challenges.yml and a ts file with annotation
    data_dir = tmp_path / "data" / "static"
    data_dir.mkdir(parents=True)
    challenges_file = data_dir / "challenges.yml"
    challenges_file.write_text(
        "---\n"
        "- name: 'User Credentials'\n"
        "  category: 'Injection'\n"
        "  key: unionSqlInjectionChallenge\n"
        "- name: 'Outdated Allowlist'\n"
        "  category: 'Unvalidated Redirects'\n"
        "  key: redirectChallenge\n",
        encoding="utf-8",
    )

    routes_dir = tmp_path / "routes"
    routes_dir.mkdir()
    sample_file = routes_dir / "search.ts"
    sample_file.write_text(
        "import express from 'express'\n"
        "// vuln-code-snippet start unionSqlInjectionChallenge\n"
        "models.sequelize.query(`SELECT * FROM Products WHERE name = '${q}'`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge\n"
        "// vuln-code-snippet end unionSqlInjectionChallenge\n",
        encoding="utf-8",
    )

    in_scope, out_of_scope = parse_juice_shop_labels(tmp_path)
    assert len(in_scope) == 1
    assert in_scope[0]["file"] == "routes/search.ts"
    assert in_scope[0]["line"] == 3
    assert in_scope[0]["rule_id"] == "SQLI-001"
    assert in_scope[0]["class"] == "SQL Injection"


def test_missing_scanner_skips_gracefully():
    # Calling run_single_benchmark with a non-existent scanner or unavailable scanner
    meta = {
        "name": "nonexistent_repo",
        "language": "python",
        "split": "test",
    }
    # bandit-only when bandit is not available
    res = run_single_benchmark(meta, "bandit-only", [])
    assert res["status"] in ["not run", "error"]


def test_dev_fix_cmdinj_variable_taint():
    from tree_sitter_languages import get_parser
    from analyst.detection.engine import _find_more_vulnerabilities_python
    py_parser = get_parser("python")
    code = b"""
import subprocess
def ping_host(host):
    cmd = f"ping -c 1 {host}"
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
"""
    tree = py_parser.parse(code)
    findings = _find_more_vulnerabilities_python(tree, code, "sample.py")
    cmd_findings = [f for f in findings if f.rule_id == "CMDINJ-001"]
    assert len(cmd_findings) == 1
    assert cmd_findings[0].line == 5


def test_dev_fix_xxe_bare_parsestring():
    from tree_sitter_languages import get_parser
    from analyst.detection.rules_extra import find_xxe_001_python
    py_parser = get_parser("python")
    code = b"""
from xml.dom.pulldom import parseString
def handle_xml(data, parser):
    doc = parseString(data, parser=parser)
    return doc
"""
    tree = py_parser.parse(code)
    findings = find_xxe_001_python(tree, code, "xxe_sample.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "XXE-001"
    assert findings[0].line == 4


def test_dev_fix_auth_enclosing_function_name():
    from tree_sitter_languages import get_parser
    from analyst.detection.rules_extra import find_auth_005
    js_parser = get_parser("javascript")
    code = b"""
function comparePassword(fromDB, fromUser) {
    return fromDB === fromUser;
}
"""
    tree = js_parser.parse(code)
    findings = find_auth_005(tree, code, "auth_sample.js")
    assert len(findings) == 1
    assert findings[0].rule_id == "AUTH-005"
    assert findings[0].line == 3
