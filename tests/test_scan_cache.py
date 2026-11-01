"""Unit tests for analyst.ingestion.scan_cache — C-1.

These tests cover only the cache file I/O and schema-validation layer.
No git logic is involved (that is C-2).

Scenarios covered:
  1. Missing cache file              → load_cache() returns None
  2. Corrupted / invalid JSON        → load_cache() returns None
  3. Wrong schema_version            → load_cache() returns None
  4. Non-dict JSON value             → load_cache() returns None
  5. Normal round-trip (save + load) → loaded dict matches what was saved
  6. save_cache creates the cache dir if it doesn't exist
  7. Dataclass findings are auto-converted to dicts by save_cache
  8. last_commit=None is preserved faithfully
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from analyst.ingestion.scan_cache import (
    CACHE_DIR_NAME,
    CACHE_FILE_NAME,
    CACHE_SCHEMA_VERSION,
    load_cache,
    save_cache,
)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _cache_file(tmp_path: Path) -> Path:
    return tmp_path / CACHE_DIR_NAME / CACHE_FILE_NAME


def _write_raw(tmp_path: Path, content: str) -> None:
    """Write *content* directly to the cache path (bypasses save_cache)."""
    p = _cache_file(tmp_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# Scenario 1 — missing file
# ---------------------------------------------------------------------------

def test_load_cache_returns_none_when_file_missing(tmp_path: Path):
    """load_cache must return None (not raise) when no cache file exists."""
    result = load_cache(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 2 — corrupted / invalid JSON
# ---------------------------------------------------------------------------

def test_load_cache_returns_none_on_corrupt_json(tmp_path: Path):
    """load_cache must return None when the file is not valid JSON."""
    _write_raw(tmp_path, "this is not json }{")
    result = load_cache(tmp_path)
    assert result is None


def test_load_cache_returns_none_on_empty_file(tmp_path: Path):
    """An empty file is also invalid JSON."""
    _write_raw(tmp_path, "")
    result = load_cache(tmp_path)
    assert result is None


def test_load_cache_returns_none_on_truncated_json(tmp_path: Path):
    """Truncated / partial JSON must not crash."""
    _write_raw(tmp_path, '{"schema_version": 1, "repo_path":')
    result = load_cache(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 3 — wrong schema_version
# ---------------------------------------------------------------------------

def test_load_cache_returns_none_on_wrong_schema_version(tmp_path: Path):
    """A cache with a different schema_version must be treated as incompatible."""
    _write_raw(
        tmp_path,
        json.dumps({
            "schema_version": 999,
            "repo_path": str(tmp_path),
            "last_commit": "abc123",
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "findings_by_file": {},
        }),
    )
    result = load_cache(tmp_path)
    assert result is None


def test_load_cache_returns_none_when_schema_version_missing(tmp_path: Path):
    """No schema_version key at all must also return None."""
    _write_raw(
        tmp_path,
        json.dumps({"repo_path": str(tmp_path), "findings_by_file": {}}),
    )
    result = load_cache(tmp_path)
    assert result is None


def test_load_cache_returns_none_when_schema_version_is_string(tmp_path: Path):
    """schema_version as string '1' (not int 1) must return None."""
    _write_raw(
        tmp_path,
        json.dumps({
            "schema_version": "1",   # string, not int
            "repo_path": str(tmp_path),
            "last_commit": None,
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "findings_by_file": {},
        }),
    )
    result = load_cache(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 4 — non-dict JSON value
# ---------------------------------------------------------------------------

def test_load_cache_returns_none_when_json_is_a_list(tmp_path: Path):
    """A JSON array at the top level (not an object) must return None."""
    _write_raw(tmp_path, json.dumps([1, 2, 3]))
    result = load_cache(tmp_path)
    assert result is None


def test_load_cache_returns_none_when_json_is_a_string(tmp_path: Path):
    """A bare JSON string must return None."""
    _write_raw(tmp_path, json.dumps("hello"))
    result = load_cache(tmp_path)
    assert result is None


# ---------------------------------------------------------------------------
# Scenario 5 — normal round-trip (save then load)
# ---------------------------------------------------------------------------

def test_round_trip_basic(tmp_path: Path):
    """save_cache + load_cache must reproduce the essential fields."""
    findings = {"src/app.py": [{"rule_id": "SQLI-001", "line": 42}]}
    save_cache(tmp_path, last_commit="deadbeef", findings_by_file=findings)

    data = load_cache(tmp_path)

    assert data is not None
    assert data["schema_version"] == CACHE_SCHEMA_VERSION
    assert data["repo_path"] == str(Path(tmp_path).resolve())
    assert data["last_commit"] == "deadbeef"
    assert "scanned_at" in data
    assert data["findings_by_file"] == findings


def test_round_trip_empty_findings(tmp_path: Path):
    """Empty findings_by_file is valid and must survive the round-trip."""
    save_cache(tmp_path, last_commit="abc123", findings_by_file={})
    data = load_cache(tmp_path)

    assert data is not None
    assert data["findings_by_file"] == {}


def test_round_trip_multiple_files(tmp_path: Path):
    """Multiple file entries must all be preserved."""
    findings = {
        "app/views.py": [{"rule_id": "XSS-002", "line": 10}],
        "app/models.py": [{"rule_id": "SQLI-001", "line": 5}, {"rule_id": "SQLI-001", "line": 20}],
        "app/config.py": [],
    }
    save_cache(tmp_path, last_commit="c0ffee", findings_by_file=findings)
    data = load_cache(tmp_path)

    assert data is not None
    assert data["findings_by_file"] == findings


# ---------------------------------------------------------------------------
# Scenario 6 — directory created automatically
# ---------------------------------------------------------------------------

def test_save_cache_creates_directory_if_missing(tmp_path: Path):
    """save_cache must create .analyst_cache/ if it does not exist."""
    cache_dir = tmp_path / CACHE_DIR_NAME
    assert not cache_dir.exists()

    save_cache(tmp_path, last_commit=None, findings_by_file={})

    assert cache_dir.is_dir()
    assert _cache_file(tmp_path).is_file()


def test_save_cache_returns_path(tmp_path: Path):
    """save_cache must return the Path it wrote to."""
    returned = save_cache(tmp_path, last_commit="sha1", findings_by_file={})
    assert returned == _cache_file(tmp_path)


# ---------------------------------------------------------------------------
# Scenario 7 — dataclass findings auto-converted
# ---------------------------------------------------------------------------

@dataclass
class _FakeFinding:
    rule_id: str
    line: int


def test_save_cache_converts_dataclasses(tmp_path: Path):
    """Dataclass instances in findings_by_file must be serialised to dicts."""
    findings = {"src/foo.py": [_FakeFinding(rule_id="SQLI-001", line=7)]}
    save_cache(tmp_path, last_commit=None, findings_by_file=findings)

    data = load_cache(tmp_path)
    assert data is not None
    saved = data["findings_by_file"]["src/foo.py"]
    assert saved == [{"rule_id": "SQLI-001", "line": 7}]


# ---------------------------------------------------------------------------
# Scenario 8 — last_commit=None preserved
# ---------------------------------------------------------------------------

def test_round_trip_null_last_commit(tmp_path: Path):
    """last_commit=None (dirty tree / not a git repo) must survive round-trip."""
    save_cache(tmp_path, last_commit=None, findings_by_file={})
    data = load_cache(tmp_path)

    assert data is not None
    assert data["last_commit"] is None


# ---------------------------------------------------------------------------
# Scenario 9 — overwrite / idempotent second save
# ---------------------------------------------------------------------------

def test_second_save_overwrites_first(tmp_path: Path):
    """A second call to save_cache must overwrite the previous file."""
    save_cache(tmp_path, last_commit="old_sha", findings_by_file={"a.py": []})
    save_cache(tmp_path, last_commit="new_sha", findings_by_file={"b.py": []})

    data = load_cache(tmp_path)
    assert data is not None
    assert data["last_commit"] == "new_sha"
    assert "b.py" in data["findings_by_file"]
    assert "a.py" not in data["findings_by_file"]


# ---------------------------------------------------------------------------
# Scenario 10 — scanned_at is an ISO 8601 string
# ---------------------------------------------------------------------------

def test_scanned_at_is_iso8601(tmp_path: Path):
    """scanned_at must be parseable as an ISO 8601 datetime string."""
    from datetime import datetime

    save_cache(tmp_path, last_commit=None, findings_by_file={})
    data = load_cache(tmp_path)

    assert data is not None
    scanned_at = data["scanned_at"]
    # Should not raise
    dt = datetime.fromisoformat(scanned_at)
    assert dt.tzinfo is not None, "scanned_at must be timezone-aware"
