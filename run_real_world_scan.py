"""
Real-world repo scan — runs the pipeline against a real-world target repo
instead of demo_app/ (our seeded ground-truth fixture).

Output is written per-target to real_world_run/<repo-name>/, so multiple
targets don't overwrite each other and are never confused with
real_artifacts/ / real_report.md, which are actually from a demo_app run
despite the "real_" naming.

This is a thin wrapper around the existing CLI plumbing (analyst.__main__ /
analyst.orchestrator.graph.run_pipeline_graph) -- it does not reimplement
any pipeline logic. For everyday scanning, `python -m analyst scan <target>
--engine graph` already does this; this script exists for a reproducible,
clearly-labeled run with a fixed per-target output location and a
Q&A-friendly summary.

Usage (Windows cmd.exe):
    set GROQ_API_KEY=your_key_here
    python run_real_world_scan.py                     (uses default target below)
    python run_real_world_scan.py <git-url-or-path>    (scans a different target)

Usage (bash):
    export GROQ_API_KEY=your_key_here
    python run_real_world_scan.py
    python run_real_world_scan.py <git-url-or-path>

Requires `git` on PATH (used by repo_fetcher.py to shallow-clone git URLs;
not needed if you pass a local path).
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

DEFAULT_TARGET_REPO_URL = "https://github.com/Krunalparmar252/seeded-vuln-repo"


def _slug_for(target: str) -> str:
    """Derive a filesystem-safe folder name from a repo URL or local path,
    so different targets get their own output folder instead of
    overwriting each other's report/artifacts."""
    name = target.rstrip("/").split("/")[-1]
    name = re.sub(r"\.git$", "", name)
    name = re.sub(r"[^\w\-.]", "_", name)
    return name or "target"


def main() -> int:
    target = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_TARGET_REPO_URL

    output_dir = Path("real_world_run") / _slug_for(target)
    output_report = output_dir / "report.md"
    artifact_dir = output_dir / "artifacts"

    if not os.environ.get("GROQ_API_KEY"):
        env_file = Path(".env")
        if env_file.is_file():
            with open(env_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() == "GROQ_API_KEY":
                            os.environ["GROQ_API_KEY"] = v.strip().strip("'\"")

    if not os.environ.get("GROQ_API_KEY"):
        print(
            "ERROR: GROQ_API_KEY is not set.\n"
            "  Windows cmd.exe:  set GROQ_API_KEY=your_key_here\n"
            "  bash:             export GROQ_API_KEY=your_key_here\n"
            "Get a free key (no credit card) at https://console.groq.com",
            file=sys.stderr,
        )
        return 1

    # Import here (not at module top) so the API-key check above runs even
    # if analyst's dependencies aren't fully installed yet -- fail on the
    # cheap check first.
    from analyst.orchestrator.graph import run_pipeline_graph

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print("REAL-WORLD SCAN")
    print("=" * 70)
    print(f"Target:    {target}")
    print(f"Engine:    graph (LangGraph StateGraph)")
    print(f"Report ->  {output_report}")
    print(f"Artifacts->{artifact_dir}")
    print("=" * 70)
    print()

    def on_stage_start(stage):
        print(f"[{stage}] starting...")

    def on_stage_done(stage):
        print(f"[{stage}] done.")

    def on_route(decision):
        print(f"  [orchestrator decision] {decision}")

    start = time.time()
    try:
        result = run_pipeline_graph(
            repo_path=target,
            output_path=str(output_report),
            artifact_dir=str(artifact_dir),
            on_stage_start=on_stage_start,
            on_stage_done=on_stage_done,
            on_route=on_route,
        )
    except Exception as exc:  # noqa: BLE001 - top-level run script, want a clean message not a traceback dump
        print(f"\nPipeline failed: {exc}", file=sys.stderr)
        return 1

    elapsed = time.time() - start

    print()
    print("=" * 70)
    print(f"STATUS: {result.status}")
    if result.stage_errors:
        print("Stage errors:")
        for stage, err in result.stage_errors.items():
            print(f"  - {stage}: {err}")
    print(
        f"Confirmed: {result.confirmed_count}  |  "
        f"Rejected (false positives): {result.rejected_count}  |  "
        f"Escalated (needs human review): {result.escalated_count}"
    )
    print(f"Duration: {result.duration_seconds:.1f}s (wall clock: {elapsed:.1f}s)")
    print(f"Report written to: {output_report}")
    print(f"Stage artifacts written to: {artifact_dir}")
    print("=" * 70)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
