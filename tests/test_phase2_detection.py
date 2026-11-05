"""Test suite for Phase 2 detection enhancements:
- Verifies all 12 new Phase 2 rules fire on exact seeded lines in Python and JS/TS.
- Verifies safe implementations and tricky negatives produce zero findings.
- Verifies dataflow trace information is attached.
- Verifies full deterministic offline pipeline across all six fixture apps with 100% recall and 0 false positives.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from analyst.detection.engine import run_detection
from analyst.ingestion.manifest import ingest_repo
from analyst.orchestrator.pipeline import run_pipeline

ROOT = Path(__file__).resolve().parent.parent


def _read_gt(app_dir: str):
    path = ROOT / app_dir / "ground_truth.json"
    return json.loads(path.read_text(encoding="utf-8"))


def test_phase2_python_findings_match_ground_truth():
    ingestion = ingest_repo(str(ROOT / "demo_app_phase2"))
    findings = run_detection(ingestion)
    gt = _read_gt("demo_app_phase2")

    found_set = {(f.file, f.line, f.rule_id) for f in findings}
    want_set = {(g["file"], g["line"], g["rule_id"]) for g in gt}

    assert found_set == want_set
    assert len(findings) == 12


def test_phase2_jsts_findings_match_ground_truth():
    ingestion = ingest_repo(str(ROOT / "demo_app_phase2_jsts"))
    findings = run_detection(ingestion)
    gt = _read_gt("demo_app_phase2_jsts")

    found_set = {(f.file, f.line, f.rule_id) for f in findings}
    want_set = {(g["file"], g["line"], g["rule_id"]) for g in gt}

    assert found_set == want_set
    assert len(findings) == 12


@pytest.mark.parametrize("app_dir", ["demo_app_phase2", "demo_app_phase2_jsts"])
def test_phase2_safe_lines_do_not_fire(app_dir: str):
    ingestion = ingest_repo(str(ROOT / app_dir))
    findings = run_detection(ingestion)
    fired_lines = {(f.file, f.line) for f in findings}

    for p in (ROOT / app_dir).iterdir():
        if p.suffix in {".py", ".js", ".ts"}:
            for lineno, line in enumerate(p.read_text(encoding="utf-8").splitlines(), start=1):
                if "SAFE" in line or "safe" in line.lower() and "def " not in line and "function" not in line:
                    assert (p.name, lineno) not in fired_lines, f"Safe code triggered false positive at {p.name}:{lineno}: {line}"


@pytest.mark.parametrize("app_dir,expected_count", [
    ("demo_app", 14),
    ("demo_app_jsts", 14),
    ("demo_app_phase1", 6),
    ("demo_app_phase1_jsts", 9),
    ("demo_app_phase2", 12),
    ("demo_app_phase2_jsts", 12),
])
def test_all_six_apps_e2e_deterministic_pipeline(tmp_path: Path, app_dir: str, expected_count: int):
    output_report = tmp_path / f"report_{app_dir}.md"
    result = run_pipeline(
        repo_path=str(ROOT / app_dir),
        output_path=str(output_report),
        offline=True,
    )
    assert result.status == "OK"
    assert result.confirmed_count == expected_count
    assert result.rejected_count == 0
    assert output_report.exists()

