"""Unit tests for Bandit and Semgrep scanner adapters and deduplication merging."""

from __future__ import annotations

import json
from unittest.mock import patch, MagicMock

import pytest

from analyst.common.types import CandidateFinding
from analyst.detection.adapters import BanditAdapter, SemgrepAdapter, merge_findings, get_available_adapters
from analyst.detection.agent import run_detection_agent
from analyst.ingestion.manifest import IngestionResult, IngestionManifest


CANNED_BANDIT_JSON = {
    "results": [
        {
            "test_id": "B608",
            "filename": "repo/app.py",
            "line_number": 25,
            "code": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            "issue_confidence": "HIGH",
        },
        {
            "test_id": "B105",
            "filename": "repo/config.py",
            "line_number": 12,
            "code": "secret_key = 'super_secret_production_key_1234'",
            "issue_confidence": "MEDIUM",
        },
        {
            "test_id": "B999_UNKNOWN",
            "filename": "repo/misc.py",
            "line_number": 5,
            "code": "unknown_check()",
            "issue_confidence": "LOW",
        },
    ]
}

CANNED_SEMGREP_JSON = {
    "results": [
        {
            "check_id": "rules.offline.sqli",
            "path": "repo/app.py",
            "start": {"line": 26},
            "extra": {
                "lines": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
                "severity": "ERROR",
            },
        },
        {
            "check_id": "rules.offline.open_redirect",
            "path": "repo/routes.py",
            "start": {"line": 40},
            "extra": {
                "lines": "res.redirect(req.query.url)",
                "severity": "WARNING",
            },
        },
        {
            "check_id": "unmapped.rule.id",
            "path": "repo/unmapped.py",
            "start": {"line": 10},
            "extra": {
                "lines": "ignore_this()",
                "severity": "INFO",
            },
        },
    ]
}


def test_bandit_adapter_parsing_and_mapping():
    adapter = BanditAdapter()
    findings = adapter.parse_results(CANNED_BANDIT_JSON, "repo")

    # B999_UNKNOWN should be dropped, mapped ones kept
    assert len(findings) == 2
    f1, f2 = findings[0], findings[1]

    assert f1.rule_id == "SQLI-001"
    assert f1.vuln_class == "SQL Injection"
    assert f1.file == "app.py"
    assert f1.line == 25
    assert f1.source_scanner == "bandit"
    assert f1.confidence == "high"

    assert f2.rule_id == "SECRET-005"
    assert f2.vuln_class == "Hardcoded Secrets"
    assert f2.file == "config.py"
    assert f2.line == 12
    assert "super_secret" not in f2.snippet  # Secret redacted


def test_semgrep_adapter_parsing_and_mapping():
    adapter = SemgrepAdapter()
    findings = adapter.parse_results(CANNED_SEMGREP_JSON, "repo")

    assert len(findings) == 2
    f1, f2 = findings[0], findings[1]

    assert f1.rule_id == "SQLI-001"
    assert f1.vuln_class == "SQL Injection"
    assert f1.file == "app.py"
    assert f1.line == 26
    assert f1.source_scanner == "semgrep"

    assert f2.rule_id == "REDIR-001"
    assert f2.vuln_class == "Open Redirect"
    assert f2.file == "routes.py"
    assert f2.line == 40


def test_merge_and_corroboration():
    native = [
        CandidateFinding(
            rule_id="SQLI-001",
            vuln_class="SQL Injection",
            file="app.py",
            line=25,
            snippet="cursor.execute(...)",
            confidence="medium",
            source_scanner="static",
        )
    ]
    external = [
        # Line 26 is within ±2 lines of line 25 on app.py with same class
        CandidateFinding(
            rule_id="SQLI-001",
            vuln_class="SQL Injection",
            file="app.py",
            line=26,
            snippet="cursor.execute(...)",
            confidence="high",
            source_scanner="semgrep",
        ),
        # New external finding on routes.py
        CandidateFinding(
            rule_id="REDIR-001",
            vuln_class="Open Redirect",
            file="routes.py",
            line=40,
            snippet="res.redirect(...)",
            confidence="medium",
            source_scanner="semgrep",
        ),
    ]

    merged = merge_findings(native, external)
    assert len(merged) == 2

    # Primary native finding kept, corroborated_by populated, confidence raised to high
    primary = merged[0]
    assert primary.file == "app.py"
    assert primary.line == 25
    assert primary.source_scanner == "static"
    assert "semgrep" in primary.corroborated_by
    assert primary.confidence == "high"

    # Distinct finding preserved
    sec = merged[1]
    assert sec.file == "routes.py"
    assert sec.source_scanner == "semgrep"


def test_pipeline_passes_with_no_scanners_installed(tmp_path):
    empty_manifest = IngestionManifest(repo_root=str(tmp_path), files=[])
    ingestion = IngestionResult(manifest=empty_manifest, asts={}, sources={})

    with patch("analyst.detection.agent.get_available_adapters", return_value=[]):
        res = run_detection_agent(ingestion, repo_path=str(tmp_path), scanners="native,bandit,semgrep")
        assert res.decision == "NONE_FOUND"
        assert res.total_candidates == 0
