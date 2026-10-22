"""
Repo Fetcher — resolves a user-supplied target (local path OR git URL)
into a local directory that the rest of the ingestion pipeline can walk,
via a context manager that guarantees cleanup.

WHY THIS EXISTS:
manifest.py's docstring documents this gap directly: "RepoFetcher: local
path only (no git clone yet)". Every agent downstream of ingestion
(Detection, Reasoning/patch_loop, Reporting) already takes a repo_path
string and doesn't care where it came from -- so the fetcher's job is
narrowly scoped: accept either input, always hand back a local path, and
clean up temp state itself. It is NOT a general git client -- no auth,
no branch selection, no submodules -- those are out of scope until the
project needs them.

DESIGN:
- fetch_target() is a context manager. On enter: if given a git URL,
  shallow-clone (--depth 1, single branch) into a fresh temp dir; if
  given a local path, pass it through unchanged (no copy -- cloning a
  local path the user already has on disk would be wasteful). On exit:
  if a temp clone was made, delete it; if it was a passthrough local
  path, leave the user's files untouched.
- FetchedTarget.source preserves the ORIGINAL user input (URL or path)
  so reports and CLI output show what the user typed, not an opaque
  /tmp/analyst_fetch_xxx path -- this matters for report readability and
  for repeat scans being recognizable to the user.
- FetchedTarget.local_path is what every existing agent should actually
  operate on. This is a pure additive layer: ingest_repo(), run_detection(),
  etc. keep taking a plain path string, unaware anything changed upstream.

GIT URL DETECTION:
Deliberately conservative regex -- matches https://.../repo(.git)?,
git@host:owner/repo.git, and git:// schemes. Anything that doesn't match
is treated as a local path. This means an ambiguous or malformed URL
fails as "path does not exist" rather than being silently mis-cloned,
which is the safer failure mode for a security-analysis tool.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

_GIT_URL_PATTERN = re.compile(
    r"^(https?://|git://|git@)"
    r"[\w\.\-]+"
    r"[:/][\w\.\-/]+?"
    r"(\.git)?/?$"
)


@dataclass
class FetchedTarget:
    source: str        # original user input, verbatim -- for display/reports
    local_path: str     # actual filesystem path to scan
    was_cloned: bool    # True if this came from a temp git clone


class RepoFetchError(Exception):
    pass


def is_git_url(target: str) -> bool:
    return bool(_GIT_URL_PATTERN.match(target.strip()))


def _shallow_clone(url: str) -> Path:
    dest = Path(tempfile.mkdtemp(prefix="analyst_fetch_"))
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise RepoFetchError(
            "git executable not found on PATH -- required to fetch remote "
            "repositories. Install git, or pass a local path instead."
        ) from exc
    except subprocess.TimeoutExpired as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise RepoFetchError(f"git clone timed out after 120s for {url!r}.") from exc
    except subprocess.CalledProcessError as exc:
        shutil.rmtree(dest, ignore_errors=True)
        stderr = exc.stderr.strip() if exc.stderr else "(no stderr captured)"
        raise RepoFetchError(f"git clone failed for {url!r}: {stderr}") from exc
    return dest


@contextmanager
def fetch_target(target: str) -> Iterator[FetchedTarget]:
    """
    Resolve `target` (local path or git URL) to a local directory,
    yielding a FetchedTarget. Cleans up any temp clone on exit,
    regardless of whether the body raises.

    Usage:
        with fetch_target(user_input) as target:
            manifest = ingest_repo(target.local_path)
            ... use target.source for display ...
    """
    target = target.strip()

    if is_git_url(target):
        cloned_path = _shallow_clone(target)
        try:
            yield FetchedTarget(source=target, local_path=str(cloned_path), was_cloned=True)
        finally:
            shutil.rmtree(cloned_path, ignore_errors=True)
        return

    # Local path passthrough
    local = Path(target)
    if not local.exists():
        raise RepoFetchError(
            f"{target!r} is not a valid git URL and no local path exists at that location."
        )
    if not local.is_dir():
        raise RepoFetchError(f"{target!r} exists but is not a directory.")

    yield FetchedTarget(source=target, local_path=str(local), was_cloned=False)
    # Nothing to clean up -- we never touch the user's own files.
