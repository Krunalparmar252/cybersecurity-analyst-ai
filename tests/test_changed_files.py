"""Unit tests for get_changed_files() — C-2.

All git interaction is mocked via unittest.mock.patch so these tests:
  • require no real git repository
  • pass regardless of network or environment state
  • are deterministic

Scenarios covered:
  1. last_commit=None  → FULL_SCAN sentinel immediately (no subprocess called)
  2. git not on PATH (FileNotFoundError)  → FULL_SCAN
  3. Not a git repo (CalledProcessError exit 128) → FULL_SCAN
  4. Unexpected OSError from subprocess  → FULL_SCAN
  5. Clean diff + clean status (no changes) → empty ChangedFileSet
  6. Added files from git diff  → appear in .added
  7. Modified files from git diff  → appear in .modified
  8. Deleted files from git diff  → appear in .deleted
  9. Uncommitted edits from git status (M modified)  → merged into .modified
 10. Untracked files (?? in status)  → merged into .added
 11. Deleted in status (D)  → merged into .deleted
 12. Rename in git diff (R\told\tnew)  → old in .deleted, new in .added
 13. Rename in git status ("old -> new") → old in .deleted, new in .added
 14. .changed property = added | modified
 15. Contradictory state (deleted in diff, re-created in status) → not in .deleted
 16. File appears in both diff modified and status modified → appears once in .modified
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch, call
import subprocess

import pytest

from analyst.ingestion.scan_cache import (
    FULL_SCAN,
    ChangedFileSet,
    get_changed_files,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _mock_run(diff_stdout: str = "", status_stdout: str = ""):
    """Build a side_effect function for subprocess.run that returns
    different fake CompletedProcess objects for the two expected git calls
    (diff and status), in order."""
    responses = [
        MagicMock(stdout=diff_stdout, stderr="", returncode=0),
        MagicMock(stdout=status_stdout, stderr="", returncode=0),
    ]
    return iter(responses)


def _patch_run(diff_stdout: str = "", status_stdout: str = ""):
    """Context-manager-compatible patcher for subprocess.run."""
    responses = [
        MagicMock(stdout=diff_stdout, stderr="", returncode=0),
        MagicMock(stdout=status_stdout, stderr="", returncode=0),
    ]
    return patch(
        "analyst.ingestion.scan_cache.subprocess.run",
        side_effect=responses,
    )


# ---------------------------------------------------------------------------
# Scenario 1 — last_commit is None
# ---------------------------------------------------------------------------

def test_returns_full_scan_when_last_commit_is_none(tmp_path):
    """No subprocess should be called when last_commit is None."""
    with patch("analyst.ingestion.scan_cache.subprocess.run") as mock_run:
        result = get_changed_files(tmp_path, last_commit=None)
    assert result is FULL_SCAN
    mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Scenario 2 — git not on PATH
# ---------------------------------------------------------------------------

def test_returns_full_scan_when_git_not_found(tmp_path):
    """FileNotFoundError from subprocess → FULL_SCAN, never raises."""
    with patch(
        "analyst.ingestion.scan_cache.subprocess.run",
        side_effect=FileNotFoundError("git: command not found"),
    ):
        result = get_changed_files(tmp_path, last_commit="abc123")
    assert result is FULL_SCAN


# ---------------------------------------------------------------------------
# Scenario 3 — not a git repo (CalledProcessError)
# ---------------------------------------------------------------------------

def test_returns_full_scan_when_not_a_git_repo(tmp_path):
    """git exiting 128 (not a git repo) → FULL_SCAN, never raises."""
    exc = subprocess.CalledProcessError(
        returncode=128,
        cmd=["git", "diff"],
        stderr="fatal: not a git repository",
    )
    with patch("analyst.ingestion.scan_cache.subprocess.run", side_effect=exc):
        result = get_changed_files(tmp_path, last_commit="abc123")
    assert result is FULL_SCAN


def test_returns_full_scan_on_any_nonzero_exit(tmp_path):
    """Any CalledProcessError → FULL_SCAN (not just exit 128)."""
    exc = subprocess.CalledProcessError(returncode=1, cmd=["git", "diff"])
    with patch("analyst.ingestion.scan_cache.subprocess.run", side_effect=exc):
        result = get_changed_files(tmp_path, last_commit="abc123")
    assert result is FULL_SCAN


# ---------------------------------------------------------------------------
# Scenario 4 — unexpected OSError
# ---------------------------------------------------------------------------

def test_returns_full_scan_on_oserror(tmp_path):
    """Generic OSError from subprocess → FULL_SCAN, never raises."""
    with patch(
        "analyst.ingestion.scan_cache.subprocess.run",
        side_effect=OSError("permission denied"),
    ):
        result = get_changed_files(tmp_path, last_commit="abc123")
    assert result is FULL_SCAN


# ---------------------------------------------------------------------------
# Scenario 5 — no changes at all
# ---------------------------------------------------------------------------

def test_empty_diff_and_status_gives_empty_changed_set(tmp_path):
    """No output from either git call → all sets empty, result is not None."""
    with _patch_run(diff_stdout="", status_stdout=""):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not FULL_SCAN
    assert isinstance(result, ChangedFileSet)
    assert result.added == frozenset()
    assert result.modified == frozenset()
    assert result.deleted == frozenset()
    assert result.changed == frozenset()


# ---------------------------------------------------------------------------
# Scenario 6 — added files in git diff
# ---------------------------------------------------------------------------

def test_added_file_from_diff(tmp_path):
    """A line starting with A in git diff → file appears in .added."""
    diff = "A\tnew_file.py\n"
    with _patch_run(diff_stdout=diff):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "new_file.py" in result.added
    assert "new_file.py" not in result.modified
    assert "new_file.py" not in result.deleted


# ---------------------------------------------------------------------------
# Scenario 7 — modified files in git diff
# ---------------------------------------------------------------------------

def test_modified_file_from_diff(tmp_path):
    """M line in git diff → file appears in .modified."""
    diff = "M\tsrc/app.py\n"
    with _patch_run(diff_stdout=diff):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "src/app.py" in result.modified
    assert "src/app.py" not in result.added
    assert "src/app.py" not in result.deleted


# ---------------------------------------------------------------------------
# Scenario 8 — deleted files in git diff
# ---------------------------------------------------------------------------

def test_deleted_file_from_diff(tmp_path):
    """D line in git diff → file appears in .deleted."""
    diff = "D\told_module.py\n"
    with _patch_run(diff_stdout=diff):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "old_module.py" in result.deleted
    assert "old_module.py" not in result.added
    assert "old_module.py" not in result.modified


# ---------------------------------------------------------------------------
# Scenario 9 — uncommitted modified file from git status
# ---------------------------------------------------------------------------

def test_modified_file_from_status(tmp_path):
    """ M (staged modify) or M  (unstaged modify) in status → .modified."""
    status = " M src/views.py\n"
    with _patch_run(status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "src/views.py" in result.modified


def test_staged_modified_file_from_status(tmp_path):
    """M  (index modified, WT clean) → .modified."""
    status = "M  src/models.py\n"
    with _patch_run(status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "src/models.py" in result.modified


# ---------------------------------------------------------------------------
# Scenario 10 — untracked files (??) in git status
# ---------------------------------------------------------------------------

def test_untracked_file_from_status(tmp_path):
    """?? in git status → file appears in .added."""
    status = "?? brand_new.py\n"
    with _patch_run(status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "brand_new.py" in result.added
    assert "brand_new.py" not in result.modified


# ---------------------------------------------------------------------------
# Scenario 11 — deleted in git status
# ---------------------------------------------------------------------------

def test_deleted_file_from_status(tmp_path):
    """ D in status (deleted, not staged) → file appears in .deleted."""
    status = " D gone.py\n"
    with _patch_run(status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "gone.py" in result.deleted
    assert "gone.py" not in result.modified


# ---------------------------------------------------------------------------
# Scenario 12 — rename in git diff
# ---------------------------------------------------------------------------

def test_rename_in_diff(tmp_path):
    """R100\\told.py\\tnew.py → old in .deleted, new in .added."""
    diff = "R100\told_name.py\tnew_name.py\n"
    with _patch_run(diff_stdout=diff):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "old_name.py" in result.deleted
    assert "new_name.py" in result.added
    assert "old_name.py" not in result.added
    assert "new_name.py" not in result.deleted


# ---------------------------------------------------------------------------
# Scenario 13 — rename in git status
# ---------------------------------------------------------------------------

def test_rename_in_status(tmp_path):
    """'R  old.py -> new.py' in status → old in .deleted, new in .added."""
    status = "R  old.py -> new.py\n"
    with _patch_run(status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "new.py" in result.added
    assert "old.py" in result.deleted


# ---------------------------------------------------------------------------
# Scenario 14 — .changed property
# ---------------------------------------------------------------------------

def test_changed_property_is_union_of_added_and_modified(tmp_path):
    """.changed must equal .added | .modified."""
    diff = "A\ta.py\nM\tb.py\nD\tc.py\n"
    with _patch_run(diff_stdout=diff):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert result.changed == result.added | result.modified
    assert "a.py" in result.changed
    assert "b.py" in result.changed
    assert "c.py" not in result.changed


# ---------------------------------------------------------------------------
# Scenario 15 — contradictory state (deleted in diff, re-created in status)
# ---------------------------------------------------------------------------

def test_file_deleted_in_diff_but_recreated_in_status_is_not_deleted(tmp_path):
    """If a file was deleted between commits but then re-created as untracked,
    it should end up in .added (needs re-scanning), not in .deleted."""
    diff = "D\tresurrected.py\n"
    status = "?? resurrected.py\n"
    with _patch_run(diff_stdout=diff, status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "resurrected.py" not in result.deleted
    assert "resurrected.py" in result.added


# ---------------------------------------------------------------------------
# Scenario 16 — same file in both diff and status
# ---------------------------------------------------------------------------

def test_file_in_both_diff_and_status_appears_once_in_modified(tmp_path):
    """A file modified in committed diff AND in working-tree status
    must appear exactly once in .modified (no duplication)."""
    diff = "M\tshared.py\n"
    status = " M shared.py\n"
    with _patch_run(diff_stdout=diff, status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "shared.py" in result.modified
    # frozenset — no duplicates by definition, but verify counts via list
    assert list(result.modified).count("shared.py") == 1


# ---------------------------------------------------------------------------
# Multiple files mixed
# ---------------------------------------------------------------------------

def test_mixed_diff_and_status(tmp_path):
    """Realistic mix of A/M/D from diff and ?? / M from status."""
    diff = "A\tadded_committed.py\nM\tchanged_committed.py\nD\tremoved_committed.py\n"
    status = "?? untracked_new.py\n M dirty_modified.py\n D dirty_deleted.py\n"
    with _patch_run(diff_stdout=diff, status_stdout=status):
        result = get_changed_files(tmp_path, last_commit="abc123")

    assert result is not None
    assert "added_committed.py" in result.added
    assert "untracked_new.py" in result.added
    assert "changed_committed.py" in result.modified
    assert "dirty_modified.py" in result.modified
    assert "removed_committed.py" in result.deleted
    assert "dirty_deleted.py" in result.deleted
