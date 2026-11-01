"""
Scan cache — stores and retrieves the result of the last successful scan
of a given repository so that incremental runs can skip unchanged files.

WHAT THIS MODULE IS:
  Persistence layer for the incremental-scan baseline.  It knows how to:
    • read and write `.analyst_cache/last_scan.json` (load_cache / save_cache)
    • validate the cache schema and fail safe on every error path
    • detect which files changed since the last scan via git (get_changed_files)

WHAT THIS MODULE IS NOT:
  It is NOT the manifest (analyst/ingestion/manifest.py).  The manifest is
  about cryptographic integrity of THIS run's file set.  The scan cache is
  about comparing TO a PREVIOUS run.  The two concepts are deliberately
  kept separate — do not merge them.

CACHE FILE LOCATION:
  <repo_root>/.analyst_cache/last_scan.json

  This file is intentionally placed inside the scanned repo so it travels
  with the repo.  It should be added to the repo's .gitignore — the system
  prints a reminder but never auto-edits the user's .gitignore without
  explicit permission.

SCHEMA (schema_version = 1):
  {
    "schema_version": 1,
    "repo_path":      "<absolute path that was scanned>",
    "last_commit":    "<git commit SHA, or null if the tree was dirty>",
    "scanned_at":     "<ISO 8601 timestamp>",
    "findings_by_file": {
      "<relative file path>": [ /* serialized finding dicts */ ]
    }
  }

FAIL-SAFE RULES (must never be weakened):
  • load_cache() returns None — not an exception — on every failure mode:
    missing file, unreadable file, invalid JSON, wrong schema_version.
  • Callers MUST treat None as "no cache available, do a full scan."
  • save_cache() raises on I/O errors so the caller knows the cache was
    not written — but a missing .analyst_cache/ directory is created
    automatically (it is not an error).
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, FrozenSet, Optional

log = logging.getLogger(__name__)

# The only schema version this module understands.  If the file contains
# a different integer, load_cache() treats it as incompatible and returns
# None so the caller falls back to a full scan.
CACHE_SCHEMA_VERSION: int = 1

# Relative to the scanned repo root.
CACHE_DIR_NAME = ".analyst_cache"
CACHE_FILE_NAME = "last_scan.json"


def _cache_path(repo_root: str | Path) -> Path:
    """Return the absolute path to the cache file for *repo_root*."""
    return Path(repo_root).resolve() / CACHE_DIR_NAME / CACHE_FILE_NAME


def load_cache(repo_root: str | Path) -> Optional[dict]:
    """Try to read the scan cache for *repo_root*.

    Returns the parsed cache dict on success, or **None** on every failure
    mode.  Callers must treat None as "no usable cache — do a full scan."

    Failure modes that all return None (never raise):
      • Cache file does not exist.
      • Cache file cannot be read (permissions, I/O error).
      • Cache file contains invalid JSON.
      • Parsed JSON is not a dict.
      • ``schema_version`` key is absent.
      • ``schema_version`` value does not equal CACHE_SCHEMA_VERSION.
    """
    path = _cache_path(repo_root)

    if not path.exists():
        log.debug("Scan cache not found at %s — will do a full scan.", path)
        return None

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("Could not read scan cache at %s (%s) — falling back to full scan.", path, exc)
        return None

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        log.warning(
            "Scan cache at %s contains invalid JSON (%s) — falling back to full scan.",
            path, exc,
        )
        return None

    if not isinstance(data, dict):
        log.warning(
            "Scan cache at %s is not a JSON object — falling back to full scan.", path
        )
        return None

    version = data.get("schema_version")
    if version != CACHE_SCHEMA_VERSION:
        log.warning(
            "Scan cache schema_version mismatch at %s "
            "(got %r, expected %d) — falling back to full scan.",
            path, version, CACHE_SCHEMA_VERSION,
        )
        return None

    log.debug("Loaded scan cache from %s (commit=%s).", path, data.get("last_commit"))
    return data


def save_cache(
    repo_root: str | Path,
    last_commit: Optional[str],
    findings_by_file: dict[str, list[Any]],
) -> Path:
    """Write (or overwrite) the scan cache for *repo_root*.

    Parameters
    ----------
    repo_root:
        Absolute path to the repo that was just scanned.
    last_commit:
        The git commit SHA that was HEAD at scan time, or None if the
        working tree was dirty / not a git repo.
    findings_by_file:
        Mapping of relative file path → list of finding dicts (already
        serialised to plain dicts — dataclasses are NOT accepted here to
        keep this module dependency-free of the reasoning layer).

    Returns
    -------
    Path
        The path that was written, so callers can log/confirm it.

    Raises
    ------
    OSError
        If the cache directory cannot be created or the file cannot be
        written.  The caller is responsible for deciding whether to treat
        this as fatal or to proceed with a warning.
    """
    root = Path(repo_root).resolve()
    path = _cache_path(root)

    # Create the cache directory if it does not exist yet.  This is the
    # only directory we ever create — we do NOT touch the repo's .gitignore
    # automatically; that requires explicit user consent.
    path.parent.mkdir(parents=True, exist_ok=True)

    # Normalise findings: accept dataclasses (convert via asdict) or plain
    # dicts.  Anything else is left as-is and will fail at json.dumps time
    # with a clear error — better than silently mangling data.
    def _normalise(items: list[Any]) -> list[dict]:
        out = []
        for item in items:
            if isinstance(item, dict):
                out.append(item)
            elif hasattr(item, "__dataclass_fields__"):
                out.append(asdict(item))  # type: ignore[arg-type]
            else:
                out.append(item)  # let json.dumps raise if not serialisable
        return out

    payload: dict = {
        "schema_version": CACHE_SCHEMA_VERSION,
        "repo_path": str(root),
        "last_commit": last_commit,
        "scanned_at": datetime.now(tz=timezone.utc).isoformat(),
        "findings_by_file": {
            rel_path: _normalise(findings)
            for rel_path, findings in findings_by_file.items()
        },
    }

    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    log.debug("Saved scan cache to %s (commit=%s).", path, last_commit)
    return path

# ---------------------------------------------------------------------------
# C-2 — Changed-file detection via git
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChangedFileSet:
    """The set of files that changed between the last cached scan and HEAD.

    All paths are relative to the repo root, forward-slash normalised,
    matching the keys used in `findings_by_file` in the cache.

    Attributes
    ----------
    added:
        Files that did not exist at ``last_commit`` and now do.
    modified:
        Files that existed at ``last_commit`` and have changed content.
    deleted:
        Files that existed at ``last_commit`` but are no longer present.
    """
    added: FrozenSet[str] = field(default_factory=frozenset)
    modified: FrozenSet[str] = field(default_factory=frozenset)
    deleted: FrozenSet[str] = field(default_factory=frozenset)

    @property
    def changed(self) -> FrozenSet[str]:
        """Union of added + modified — files that need to be re-scanned."""
        return self.added | self.modified


# Sentinel returned by get_changed_files() when git is unavailable,
# last_commit is None, or the repo is not a git repository.  The caller
# is responsible for deciding to fall back to a full scan; this function
# never silently skips files on its own.
FULL_SCAN: Optional[ChangedFileSet] = None


# Porcelain status codes that we treat as "file was deleted from the tree".
_PORCELAIN_DELETED = {"D", "DD", "AD", "RD"}
# Porcelain status codes that map to "added" (new file, untracked).
_PORCELAIN_ADDED = {"A", "AA", "?", "??"}


def _run_git(args: list[str], cwd: str) -> str:
    """Run a git subprocess and return stdout as a string.

    Raises ``subprocess.CalledProcessError`` if git exits non-zero,
    ``FileNotFoundError`` if git is not on PATH, and ``OSError`` for other
    execution failures.  All of these are caught by the caller.
    """
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def get_head_commit(repo_root: str | Path) -> Optional[str]:
    """Return the current HEAD commit SHA for *repo_root*.

    Returns None (never raises) if the directory is not a git repository,
    git is not installed, or any error occurs.
    """
    try:
        out = _run_git(["rev-parse", "HEAD"], cwd=str(Path(repo_root).resolve()))
        sha = out.strip()
        return sha if sha else None
    except Exception as exc:  # noqa: BLE001
        log.debug("get_head_commit: could not get HEAD for %s (%s)", repo_root, exc)
        return None


def get_changed_files(
    repo_root: str | Path,
    last_commit: Optional[str],
) -> Optional[ChangedFileSet]:
    """Compute which files changed between ``last_commit`` and the current
    working tree.

    This function wraps two git calls:
      1. ``git diff --name-status <last_commit>..HEAD``
         Captures files that differ in committed history.
      2. ``git status --porcelain``
         Captures uncommitted edits on top of that (staged + unstaged).

    The results are merged: a file appearing as modified in both sources
    is counted once as ``modified``; a file deleted in history but then
    re-created in the working tree ends up as ``modified`` (the net effect
    is the same — it needs re-scanning).

    Returns
    -------
    ChangedFileSet
        Three frozensets: added, modified, deleted.
    None  (the ``FULL_SCAN`` sentinel)
        Returned — **never raised** — on every failure mode:
          • ``last_commit`` is None (previous scan didn't capture a clean SHA).
          • The directory is not a git repository.
          • ``git`` is not installed / not on PATH.
          • Any ``subprocess.CalledProcessError`` or ``OSError``.
        Callers MUST treat None as "cannot determine changed set — do a full
        scan."
    """
    if last_commit is None:
        log.debug(
            "get_changed_files: last_commit is None — returning FULL_SCAN sentinel."
        )
        return FULL_SCAN

    root = str(Path(repo_root).resolve())

    try:
        # ------------------------------------------------------------------
        # Step 1: committed changes since last_commit
        # ------------------------------------------------------------------
        # --diff-filter separates Added / Deleted / Modified / Renamed /
        # Copied lines so we don't have to parse free-form output.
        diff_out = _run_git(
            ["diff", "--name-status", f"{last_commit}..HEAD"],
            cwd=root,
        )

        added: set[str] = set()
        modified: set[str] = set()
        deleted: set[str] = set()

        for line in diff_out.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split("\t", maxsplit=2)
            if len(parts) < 2:
                continue
            status_code = parts[0].upper()
            # Renamed/Copied lines have two paths: old \t new
            file_path = parts[-1].strip()

            if status_code.startswith("A"):
                added.add(file_path)
            elif status_code.startswith("D"):
                deleted.add(file_path)
            elif status_code.startswith("R") or status_code.startswith("C"):
                # Rename/copy: old path deleted, new path added
                if len(parts) == 3:
                    deleted.add(parts[1].strip())
                    added.add(parts[2].strip())
                else:
                    # Fallback if we only got one path
                    modified.add(file_path)
            else:
                # M, T (type-change), U, X, B — all treated as modified
                modified.add(file_path)

        # ------------------------------------------------------------------
        # Step 2: uncommitted changes layered on top
        # ------------------------------------------------------------------
        # git status --porcelain gives two-character status codes followed by
        # a space and the file path.  We merge these into the sets above so
        # that a file modified in git history AND in the working tree still
        # appears exactly once.
        status_out = _run_git(["status", "--porcelain"], cwd=root)

        for line in status_out.splitlines():
            if len(line) < 4:
                continue
            xy = line[:2].strip().upper()  # XY codes, strip spaces
            path_part = line[3:].strip()
            # Handle renames in status: "old -> new"
            if " -> " in path_part:
                old_p, new_p = path_part.split(" -> ", 1)
                deleted.discard(new_p)  # not deleted, it moved
                added.add(new_p)
                # old path is effectively gone
                deleted.add(old_p)
                modified.discard(old_p)
                added.discard(old_p)
                continue

            # Untracked files (??) are newly added
            if xy in ("??", "?"):
                added.add(path_part)
                modified.discard(path_part)
                deleted.discard(path_part)
            # D in either column means deleted in working tree
            elif "D" in xy:
                deleted.add(path_part)
                modified.discard(path_part)
                added.discard(path_part)
            # A in XY and not already tracked = new file staged
            elif xy.startswith("A"):
                if path_part not in modified and path_part not in deleted:
                    added.add(path_part)
            else:
                # All other combinations (M, R, C, T, U …) = modified
                if path_part not in added and path_part not in deleted:
                    modified.add(path_part)
                elif path_part in added:
                    pass  # added already covers it

        # A file cannot simultaneously be deleted AND (added OR modified).
        # If the working-tree status contradicts the diff, the working-tree
        # wins — the file exists now and needs scanning.
        deleted -= added
        deleted -= modified

        log.debug(
            "get_changed_files: %d added, %d modified, %d deleted since %s.",
            len(added), len(modified), len(deleted), last_commit,
        )
        return ChangedFileSet(
            added=frozenset(added),
            modified=frozenset(modified),
            deleted=frozenset(deleted),
        )

    except FileNotFoundError:
        log.warning(
            "get_changed_files: 'git' not found on PATH — returning FULL_SCAN sentinel."
        )
        return FULL_SCAN
    except subprocess.CalledProcessError as exc:
        log.warning(
            "get_changed_files: git command failed (exit %d: %s) — "
            "returning FULL_SCAN sentinel.",
            exc.returncode, exc.stderr.strip() if exc.stderr else "(no stderr)",
        )
        return FULL_SCAN
    except OSError as exc:
        log.warning(
            "get_changed_files: OS error running git (%s) — returning FULL_SCAN sentinel.",
            exc,
        )
        return FULL_SCAN
