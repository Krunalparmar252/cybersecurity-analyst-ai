"""Unit tests for C-5 — cache write-back and reporting integration.

Tests cover:
  1. get_head_commit returns clean commit SHA.
  2. get_head_commit returns None on git failure (fail-safe).
  3. _write_scan_cache serializes verify_results into findings_by_file.
  4. _write_scan_cache is fail-safe when save_cache raises OSError.
  5. render_report includes incremental scan summary line when provided.
  6. render_report omits incremental scan summary line when None.
  7. run_reporting_agent forwards incremental_summary to report_text.
  8. End-to-end cache persistence across pipeline run (both linear and graph engines).
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from analyst.common.types import ConfirmedFinding, STATUS_ACCEPTED
from analyst.ingestion.scan_cache import get_head_commit, load_cache
from analyst.orchestrator.pipeline import (
    _write_scan_cache,
    run_pipeline,
)
from analyst.orchestrator.graph import run_pipeline_graph
from analyst.reasoning.patch_loop import PatchVerificationResult
from analyst.reporting.agent import run_reporting_agent
from analyst.reporting.renderer import render_report


# ---------------------------------------------------------------------------
# 1 & 2: get_head_commit tests
# ---------------------------------------------------------------------------

def test_get_head_commit_success():
    """get_head_commit returns stripped SHA when git rev-parse succeeds."""
    with patch("analyst.ingestion.scan_cache._run_git", return_value="deadbeef1234\n"):
        sha = get_head_commit("/some/repo")
    assert sha == "deadbeef1234"


def test_get_head_commit_failure_returns_none():
    """get_head_commit returns None when git raises or fails."""
    with patch(
        "analyst.ingestion.scan_cache._run_git",
        side_effect=subprocess.CalledProcessError(128, ["git", "rev-parse", "HEAD"]),
    ):
        sha = get_head_commit("/not/a/git/repo")
    assert sha is None

    with patch(
        "analyst.ingestion.scan_cache._run_git",
        side_effect=FileNotFoundError("git not found"),
    ):
        sha = get_head_commit("/not/a/git/repo")
    assert sha is None


# ---------------------------------------------------------------------------
# 3 & 4: _write_scan_cache tests
# ---------------------------------------------------------------------------

def test_write_scan_cache_serializes_and_saves(tmp_path):
    """_write_scan_cache populates findings_by_file with serialized findings and clean files."""
    finding = ConfirmedFinding(
        rule_id="SQLI-001",
        vuln_class="sql_injection",
        file="app.py",
        line=10,
        confirmed=True,
        confirmation_reasoning="real bug",
        patch_diff="--- a\n+++ b",
    )
    res = PatchVerificationResult(
        finding=finding,
        loop_status=STATUS_ACCEPTED,
        attempts=1,
        attempt_log=[{"attempt": 1, "applied": True}],
    )

    with (
        patch("analyst.ingestion.scan_cache.get_head_commit", return_value="commit123"),
        patch("analyst.ingestion.scan_cache.save_cache") as mock_save,
    ):
        _write_scan_cache(
            repo_path=str(tmp_path),
            verify_results=[res],
            scanned_files=["app.py", "clean.py"],
        )

        mock_save.assert_called_once()
        args, kwargs = mock_save.call_args
        repo_root, last_commit, findings_by_file = args
        assert repo_root == str(tmp_path)
        assert last_commit == "commit123"
        assert "clean.py" in findings_by_file
        assert findings_by_file["clean.py"] == []
        assert "app.py" in findings_by_file
        assert len(findings_by_file["app.py"]) == 1
        assert findings_by_file["app.py"][0]["loop_status"] == STATUS_ACCEPTED


def test_write_scan_cache_fail_safe_on_os_error(tmp_path):
    """_write_scan_cache catches any OSError from save_cache and does not raise."""
    with (
        patch("analyst.ingestion.scan_cache.get_head_commit", return_value="commit123"),
        patch(
            "analyst.ingestion.scan_cache.save_cache",
            side_effect=OSError("Read-only filesystem"),
        ),
    ):
        # Must not raise
        _write_scan_cache(
            repo_path=str(tmp_path),
            verify_results=[],
            scanned_files=["app.py"],
        )


# ---------------------------------------------------------------------------
# 5, 6 & 7: Reporting integration tests
# ---------------------------------------------------------------------------

def test_render_report_includes_incremental_summary():
    """render_report displays the incremental scan summary line under Executive Summary."""
    summary_text = "3 file(s) re-scanned, 12 carried forward from previous run (commit abc12345)"
    report = render_report(
        confirmed=[],
        repo_path="/test/repo",
        scan_duration_seconds=1.2,
        incremental_summary=summary_text,
    )
    assert "## Executive Summary" in report
    assert f"- **Incremental scan:** {summary_text}" in report


def test_render_report_omits_incremental_summary_when_none():
    """render_report does not include the incremental scan line when summary is None."""
    report = render_report(
        confirmed=[],
        repo_path="/test/repo",
        scan_duration_seconds=1.2,
        incremental_summary=None,
    )
    assert "- **Incremental scan:**" not in report


def test_run_reporting_agent_forwards_incremental_summary():
    """run_reporting_agent passes incremental_summary through to the report text."""
    summary_text = "1 file(s) re-scanned, 5 carried forward"
    result = run_reporting_agent(
        confirmed=[],
        repo_path="/test/repo",
        scan_duration_seconds=0.5,
        incremental_summary=summary_text,
    )
    assert f"- **Incremental scan:** {summary_text}" in result.report_text


# ---------------------------------------------------------------------------
# 8: Full pipeline end-to-end cache write-back test
# ---------------------------------------------------------------------------

def test_pipeline_writes_cache_on_completion(tmp_path):
    """Running run_pipeline writes .analyst_cache/last_scan.json to disk."""
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "main.py").write_text("x = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.md"

    with patch("analyst.ingestion.scan_cache.get_head_commit", return_value="test_commit_sha"):
        result = run_pipeline(
            repo_path=str(dummy_repo),
            output_path=str(out_file),
            offline=True,
        )

    assert result.status == "OK"
    cache = load_cache(str(dummy_repo))
    assert cache is not None
    assert cache["last_commit"] == "test_commit_sha"
    assert "main.py" in cache["findings_by_file"]


def test_graph_pipeline_writes_cache_on_completion(tmp_path):
    """Running run_pipeline_graph writes .analyst_cache/last_scan.json to disk."""
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "main.py").write_text("y = 2\n", encoding="utf-8")
    out_file = tmp_path / "report.md"

    with patch("analyst.ingestion.scan_cache.get_head_commit", return_value="graph_commit_sha"):
        result = run_pipeline_graph(
            repo_path=str(dummy_repo),
            output_path=str(out_file),
            offline=True,
        )

    assert result.status == "OK"
    cache = load_cache(str(dummy_repo))
    assert cache is not None
    assert cache["last_commit"] == "graph_commit_sha"
    assert "main.py" in cache["findings_by_file"]
