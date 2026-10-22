"""
Pytest suite for JS/TS fixture (demo_app_jsts).
Verifies tree-sitter parsing and rule detection across JavaScript and TypeScript files.
"""

import json
from pathlib import Path
import pytest

from analyst.ingestion.manifest import ingest_repo
from analyst.detection.engine import run_detection

FIXTURE_DIR = Path(__file__).parent / "demo_app_jsts"


def test_jsts_ingestion():
    ingestion = ingest_repo(str(FIXTURE_DIR))
    parsed_files = {f.path: f.parsed for f in ingestion.manifest.files}
    assert parsed_files.get("server.js") is True
    assert parsed_files.get("service.ts") is True


def test_jsts_detection_matches_ground_truth():
    ingestion = ingest_repo(str(FIXTURE_DIR))
    findings = run_detection(ingestion)

    gt_file = FIXTURE_DIR / "ground_truth.json"
    with open(gt_file, "r", encoding="utf-8") as f:
        ground_truth = json.load(f)

    for gt in ground_truth:
        matched = any(
            f.rule_id == gt["rule_id"]
            and f.file == gt["file"]
            and f.line == gt["line"]
            for f in findings
        )
        assert matched is True, f"Ground truth record {gt['id']} ({gt['rule_id']} @ {gt['file']}:{gt['line']}) was not detected by engine."


def test_jsts_findings_count():
    ingestion = ingest_repo(str(FIXTURE_DIR))
    findings = run_detection(ingestion)
    rule_ids = {f.rule_id for f in findings}
    assert "SECRET-005" in rule_ids
    assert "SQLI-001" in rule_ids
    assert "XSS-002" in rule_ids
    with open(FIXTURE_DIR / "ground_truth.json", "r", encoding="utf-8") as f:
        assert len(findings) == len(json.load(f))  # exactly the seeded set, no extras
