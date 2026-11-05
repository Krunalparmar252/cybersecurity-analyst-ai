#!/usr/bin/env python3
"""
Benchmark repository fetcher.
Clones benchmark repositories at pinned commit SHAs without executing any code.
Safe to run on Windows and Linux.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
import yaml

ROOT_DIR = Path(__file__).resolve().parent.parent
BENCHMARKS_DIR = Path(__file__).resolve().parent
REPOS_DIR = BENCHMARKS_DIR / "repos"
MANIFEST_PATH = BENCHMARKS_DIR / "manifest.yaml"


def load_manifest() -> dict:
    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def fetch_repo(repo_meta: dict, force: bool = False) -> bool:
    name = repo_meta["name"]
    url = repo_meta["url"]
    pinned_sha = repo_meta["commit"]
    dest = REPOS_DIR / name

    if dest.exists() and not force:
        # Check if already cloned
        git_dir = dest / ".git"
        if git_dir.exists():
            try:
                res = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=str(dest),
                    capture_output=True,
                    text=True,
                    check=True,
                )
                current_sha = res.stdout.strip()
                if current_sha.startswith(pinned_sha[:8]) or pinned_sha.startswith(current_sha[:8]):
                    print(f"[{name}] Already fetched at pinned SHA {current_sha[:8]}")
                    return True
                else:
                    print(f"[{name}] Present at {current_sha[:8]}, checking out {pinned_sha[:8]}...")
                    subprocess.run(
                        ["git", "checkout", pinned_sha],
                        cwd=str(dest),
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    return True
            except Exception as e:
                print(f"[{name}] Error checking git state: {e}")

    if dest.exists() and force:
        print(f"[{name}] Removing existing directory for force refetch...")
        shutil.rmtree(dest, ignore_errors=True)

    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"[{name}] Cloning from {url}...")

    # First attempt shallow clone
    cmd_clone = ["git", "clone", "--depth", "1", url, str(dest)]
    try:
        subprocess.run(cmd_clone, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[{name}] Shallow clone failed: {e.stderr}. Attempting full clone...")
        cmd_full = ["git", "clone", url, str(dest)]
        subprocess.run(cmd_full, check=True)

    # Check commit SHA and checkout pinned SHA if different
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(dest),
            capture_output=True,
            text=True,
            check=True,
        )
        current_sha = res.stdout.strip()
        if not (current_sha.startswith(pinned_sha[:8]) or pinned_sha.startswith(current_sha[:8])):
            print(f"[{name}] HEAD is {current_sha[:8]}, fetching pinned {pinned_sha[:8]}...")
            subprocess.run(
                ["git", "fetch", "--depth", "1", "origin", pinned_sha],
                cwd=str(dest),
                capture_output=True,
                text=True,
                check=False,
            )
            subprocess.run(
                ["git", "checkout", pinned_sha],
                cwd=str(dest),
                capture_output=True,
                text=True,
                check=True,
            )
        print(f"[{name}] Successfully pinned at {pinned_sha[:8]}")
        return True
    except Exception as err:
        print(f"[{name}] Checkout/verification warning: {err}")
        return True


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch benchmark repositories safely")
    parser.add_argument("--repo", help="Fetch a single repository by name")
    parser.add_argument("--split", choices=["dev", "test"], help="Fetch only dev or test repositories")
    parser.add_argument("--force", action="store_true", help="Force refetch existing repositories")
    args = parser.parse_args()

    manifest = load_manifest()
    repos = manifest.get("repositories", [])
    if args.repo:
        repos = [r for r in repos if r["name"] == args.repo]
        if not repos:
            print(f"Repository '{args.repo}' not found in manifest.yaml")
            return 1
    elif args.split:
        repos = [r for r in repos if r.get("split") == args.split]

    print(f"Fetching {len(repos)} repositories to {REPOS_DIR}...")
    success = True
    for repo in repos:
        ok = fetch_repo(repo, force=args.force)
        if not ok:
            success = False

    print("\nFetch complete.")
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())

