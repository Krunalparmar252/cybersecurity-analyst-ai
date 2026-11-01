"""Unit tests for C-6 — CLI flag (--incremental) and fallback behavior.

Tests cover:
  1. CLI help text includes --incremental option.
  2. CLI passes incremental=True to the runner.
  3. CLI with --incremental falls back cleanly on missing cache (full scan, exit 0).
  4. CLI with --incremental falls back cleanly when git fails/missing.
  5. End-to-end differential scan workflow:
     - Run 1 (baseline): populates cache.
     - Run 2 (incremental): detects unchanged files, reports incremental summary.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from analyst.__main__ import cli
from analyst.ingestion.scan_cache import ChangedFileSet, load_cache, save_cache


def test_cli_help_includes_incremental():
    """CLI --help must document the --incremental flag."""
    runner = CliRunner()
    result = runner.invoke(cli, ["scan", "--help"])
    assert result.exit_code == 0
    assert "--incremental" in result.output
    assert "incremental scanning" in result.output.lower()


def test_cli_passes_incremental_flag(tmp_path):
    """When --incremental is given, run_pipeline receives incremental=True."""
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "app.py").write_text("x = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.md"

    mock_run = MagicMock()
    mock_result = MagicMock()
    mock_result.status = "OK"
    mock_result.confirmed_count = 0
    mock_result.rejected_count = 0
    mock_result.escalated_count = 0
    mock_result.duration_seconds = 0.5
    mock_result.fallbacks = []
    mock_result.integrity = {}
    mock_result.incremental_summary = "1 file(s) re-scanned"
    mock_run.return_value = mock_result

    with patch.dict("analyst.__main__.ENGINES", {"linear": mock_run}):
        runner = CliRunner()
        res = runner.invoke(
            cli,
            ["scan", str(dummy_repo), "--incremental", "-o", str(out_file), "--offline"],
        )

        assert res.exit_code == 0
        mock_run.assert_called_once()
        _, kwargs = mock_run.call_args
        assert kwargs.get("incremental") is True


def test_cli_incremental_falls_back_cleanly_on_missing_cache(tmp_path):
    """When --incremental is used but no cache exists, it does a full scan without error."""
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "main.py").write_text("a = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.md"

    runner = CliRunner()
    res = runner.invoke(
        cli,
        ["scan", str(dummy_repo), "--incremental", "-o", str(out_file), "--offline"],
    )

    assert res.exit_code == 0
    assert out_file.exists()


def test_cli_incremental_falls_back_cleanly_when_git_fails(tmp_path):
    """When git diff fails, --incremental gracefully falls back to full scan."""
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "main.py").write_text("a = 1\n", encoding="utf-8")
    out_file = tmp_path / "report.md"

    # Pre-seed a cache with a commit
    save_cache(dummy_repo, "commit_old", {"main.py": []})

    # Simulate git diff failing
    with patch(
        "analyst.ingestion.scan_cache._run_git",
        side_effect=subprocess.CalledProcessError(1, ["git", "diff"]),
    ):
        runner = CliRunner()
        res = runner.invoke(
            cli,
            ["scan", str(dummy_repo), "--incremental", "-o", str(out_file), "--offline"],
        )

    assert res.exit_code == 0
    assert out_file.exists()


def test_end_to_end_differential_scan(tmp_path):
    """End-to-end multi-run workflow:
    Run 1 establishes baseline cache.
    Run 2 with --incremental carries forward unchanged files and outputs summary.
    """
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "clean.py").write_text("b = 2\n", encoding="utf-8")
    (dummy_repo / "vuln.py").write_text("x = 1\n", encoding="utf-8")
    out1 = tmp_path / "report1.md"
    out2 = tmp_path / "report2.md"

    runner = CliRunner()

    # Run 1: baseline
    with patch("analyst.ingestion.scan_cache.get_head_commit", return_value="c001"):
        res1 = runner.invoke(
            cli,
            ["scan", str(dummy_repo), "--incremental", "-o", str(out1), "--offline"],
        )
    assert res1.exit_code == 0
    cache1 = load_cache(dummy_repo)
    assert cache1 is not None
    assert cache1["last_commit"] == "c001"

    # Run 2: incremental with simulated change in vuln.py
    changed_set = ChangedFileSet(
        added=frozenset(),
        modified=frozenset(["vuln.py"]),
        deleted=frozenset(),
    )
    with (
        patch("analyst.ingestion.scan_cache.get_head_commit", return_value="c002"),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed_set),
    ):
        res2 = runner.invoke(
            cli,
            ["scan", str(dummy_repo), "--incremental", "-o", str(out2), "--offline"],
        )

    assert res2.exit_code == 0
    assert "Incremental scan:" in res2.output
    # Check that report2 contains the summary line
    content2 = out2.read_text(encoding="utf-8")
    assert "- **Incremental scan:**" in content2
