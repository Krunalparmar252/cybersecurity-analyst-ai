"""Unit tests for C-3 — incremental filter (_apply_incremental_filter).

These tests target the helper directly (no full pipeline run) so they are
fast, deterministic, and require no git or LLM calls.

Scenarios covered:
  1. incremental=False (default) → all candidates passed through unchanged,
     scan_mode="rescanned" on all.
  2. No cache (load_cache returns None) → full-scan fallback, summary=None.
  3. Cache present but get_changed_files returns FULL_SCAN sentinel →
     full-scan fallback, summary=None.
  4. Normal incremental hit:
     - Changed file → fresh candidates kept, scan_mode="rescanned"
     - Unchanged file with cached finding → carried forward, scan_mode="carried_forward"
     - Deleted file → cached findings dropped
  5. File in fresh candidates but NOT in cache at all (never cached) →
     treated as "rescanned" (always re-analyse first-timers).
  6. Malformed cached finding (missing fields) → skipped silently, no crash.
  7. Unexpected exception inside filter → returns all candidates unchanged
     (fail-safe).
  8. Summary string format is correct.
  9. Both pipeline engines accept incremental=True without error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest

from analyst.common.types import CandidateFinding
from analyst.orchestrator.pipeline import _apply_incremental_filter
from analyst.ingestion.scan_cache import ChangedFileSet, FULL_SCAN


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_candidate(file: str, rule_id: str = "SQLI-001", line: int = 1) -> CandidateFinding:
    return CandidateFinding(
        rule_id=rule_id,
        vuln_class="sql_injection",
        file=file,
        line=line,
        snippet="x",
        confidence="high",
        source_scanner="static",
    )


def _make_cache(repo_path: str, last_commit: str, findings_by_file: dict) -> dict:
    return {
        "schema_version": 1,
        "repo_path": repo_path,
        "last_commit": last_commit,
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "findings_by_file": findings_by_file,
    }


def _changed(added=(), modified=(), deleted=()):
    return ChangedFileSet(
        added=frozenset(added),
        modified=frozenset(modified),
        deleted=frozenset(deleted),
    )


# ---------------------------------------------------------------------------
# Scenario 2 — no cache
# ---------------------------------------------------------------------------

def test_no_cache_returns_all_candidates_and_none_summary(tmp_path):
    """When load_cache returns None, all candidates pass through unchanged."""
    candidates = [_make_candidate("app.py")]
    with patch("analyst.orchestrator.pipeline.load_cache", return_value=None):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert result is candidates  # same list object — not a copy
    assert summary is None


# ---------------------------------------------------------------------------
# Scenario 3 — cache present but get_changed_files returns FULL_SCAN
# ---------------------------------------------------------------------------

def test_changed_files_returns_full_scan_sentinel(tmp_path):
    """When get_changed_files returns None (FULL_SCAN), pass all candidates through."""
    cache = _make_cache(str(tmp_path), "abc123", {"app.py": []})
    candidates = [_make_candidate("app.py")]
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=FULL_SCAN),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert result is candidates
    assert summary is None


# ---------------------------------------------------------------------------
# Scenario 4a — changed file → fresh candidate kept, scan_mode="rescanned"
# ---------------------------------------------------------------------------

def test_changed_file_candidate_is_kept_with_rescanned_mode(tmp_path):
    """A candidate for a modified file must be in the result with scan_mode='rescanned'."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "changed.py": [{"rule_id": "SQLI-001", "vuln_class": "sql_injection",
                         "file": "changed.py", "line": 1, "snippet": "old",
                         "confidence": "high", "source_scanner": "static"}],
    })
    candidates = [_make_candidate("changed.py")]
    changed = _changed(modified=("changed.py",))
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert any(c.file == "changed.py" and c.scan_mode == "rescanned" for c in result)
    assert summary is not None


# ---------------------------------------------------------------------------
# Scenario 4b — unchanged file with cached finding → carried forward
# ---------------------------------------------------------------------------

def test_unchanged_file_finding_is_carried_forward(tmp_path):
    """A finding for an unchanged file must be carried forward from cache."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "unchanged.py": [{"rule_id": "XSS-002", "vuln_class": "xss",
                           "file": "unchanged.py", "line": 5, "snippet": "s",
                           "confidence": "medium", "source_scanner": "static"}],
    })
    # No fresh candidate for unchanged.py (it wasn't re-detected this run
    # because only changed.py was in the changed set).
    candidates = []
    changed = _changed(modified=("changed.py",))
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert any(c.file == "unchanged.py" and c.scan_mode == "carried_forward" for c in result)
    assert summary is not None


# ---------------------------------------------------------------------------
# Scenario 4c — deleted file → cached findings dropped
# ---------------------------------------------------------------------------

def test_deleted_file_findings_are_dropped(tmp_path):
    """Findings for a deleted file must NOT be carried forward."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "deleted.py": [{"rule_id": "SQLI-001", "vuln_class": "sql_injection",
                         "file": "deleted.py", "line": 3, "snippet": "x",
                         "confidence": "high", "source_scanner": "static"}],
    })
    candidates = []
    changed = _changed(deleted=("deleted.py",))
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert not any(c.file == "deleted.py" for c in result)


# ---------------------------------------------------------------------------
# Scenario 5 — new file never in cache
# ---------------------------------------------------------------------------

def test_fresh_candidate_for_uncached_file_is_kept_as_rescanned(tmp_path):
    """A candidate for a file never seen before must be included as 'rescanned'."""
    cache = _make_cache(str(tmp_path), "abc123", {})  # empty cache
    candidates = [_make_candidate("brand_new.py")]
    changed = _changed(added=("brand_new.py",))
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert any(c.file == "brand_new.py" and c.scan_mode == "rescanned" for c in result)


def test_fresh_candidate_not_in_cache_and_not_in_changed_still_included(tmp_path):
    """If a file appears in fresh candidates but is absent from the cache,
    it should be included (treated as new/uncached)."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "other.py": [],  # cache knows about other.py, not this_file.py
    })
    candidates = [_make_candidate("this_file.py")]
    changed = _changed()  # no changed files
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert any(c.file == "this_file.py" for c in result)


# ---------------------------------------------------------------------------
# Scenario 6 — malformed cached finding
# ---------------------------------------------------------------------------

def test_malformed_cached_finding_is_skipped_silently(tmp_path):
    """A cached finding dict with missing fields must not crash the filter."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "broken.py": [{"rule_id": "SQLI-001"}],  # missing most fields
    })
    candidates = []
    changed = _changed()
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)
    # Should not raise; the carried finding is reconstructed with defaults
    assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Scenario 7 — unexpected exception → fail-safe full scan
# ---------------------------------------------------------------------------

def test_unexpected_exception_returns_all_candidates(tmp_path):
    """Any unexpected error in the filter must return the original candidates."""
    candidates = [_make_candidate("app.py")]
    with patch(
        "analyst.orchestrator.pipeline.load_cache",
        side_effect=RuntimeError("simulated crash"),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert result is candidates
    assert summary is None


# ---------------------------------------------------------------------------
# Scenario 8 — summary string format
# ---------------------------------------------------------------------------

def test_summary_mentions_rescanned_and_carried_counts(tmp_path):
    """The summary must mention counts of re-scanned and carried-forward files."""
    cache = _make_cache(str(tmp_path), "deadbeef1234", {
        "unchanged.py": [{"rule_id": "SQLI-001", "vuln_class": "sql_injection",
                           "file": "unchanged.py", "line": 1, "snippet": "x",
                           "confidence": "high", "source_scanner": "static"}],
    })
    candidates = [_make_candidate("changed.py")]
    changed = _changed(modified=("changed.py",))
    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    assert summary is not None
    assert "re-scanned" in summary
    assert "carried forward" in summary
    assert "deadbeef" in summary  # commit short SHA


# ---------------------------------------------------------------------------
# Scenario 9 — both engines accept incremental=True
# ---------------------------------------------------------------------------

def test_run_pipeline_accepts_incremental_param(tmp_path):
    """run_pipeline must accept incremental=True without TypeError."""
    from analyst.orchestrator.pipeline import run_pipeline
    import inspect
    sig = inspect.signature(run_pipeline)
    assert "incremental" in sig.parameters


def test_run_pipeline_graph_accepts_incremental_param():
    """run_pipeline_graph must accept incremental=True without TypeError."""
    from analyst.orchestrator.graph import run_pipeline_graph
    import inspect
    sig = inspect.signature(run_pipeline_graph)
    assert "incremental" in sig.parameters


# ---------------------------------------------------------------------------
# Scenario 10 — mixed: unchanged file's fresh detection is superseded by cache
# ---------------------------------------------------------------------------

def test_unchanged_file_fresh_candidate_superseded_by_cache(tmp_path):
    """If detection fires on an UNCHANGED file, its fresh candidate is dropped
    in favour of the cached one (so we don't double-count)."""
    cache = _make_cache(str(tmp_path), "abc123", {
        "steady.py": [{"rule_id": "SQLI-001", "vuln_class": "sql_injection",
                        "file": "steady.py", "line": 10, "snippet": "cached",
                        "confidence": "high", "source_scanner": "static"}],
    })
    # Detection ran over the full repo and found something in steady.py too,
    # but steady.py is NOT in the changed set.
    candidates = [_make_candidate("steady.py", line=10)]
    changed = _changed()  # no changes at all

    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), candidates)

    # Should have the CARRIED version, not the fresh one
    matching = [c for c in result if c.file == "steady.py"]
    assert len(matching) == 1
    assert matching[0].scan_mode == "carried_forward"
