"""Task 5: every new rule has a seeded case in a demo app; safe variants stay
quiet; no raw secret value survives detection."""
import json
import re
from pathlib import Path

import pytest

from analyst.detection.engine import run_detection
from analyst.ingestion.manifest import ingest_repo

ROOT = Path(__file__).resolve().parent.parent
APPS = ["demo_app", "demo_app_jsts"]
NEW_RULES = {
    "SQLI-002", "XSS-001", "XSS-003", "AUTH-001", "AUTH-002", "DESER-002",
    "SECRET-001", "SECRET-002", "SECRET-003", "SECRET-006", "SECRET-007",
}


def _gt(app):
    return json.loads((ROOT / app / "ground_truth.json").read_text(encoding="utf-8"))


def _findings(app):
    return run_detection(ingest_repo(str(ROOT / app)))


@pytest.mark.parametrize("app", APPS)
def test_fires_exactly_the_seeded_set(app):
    found = {(f.file, f.line, f.rule_id) for f in _findings(app)}
    want = {(g["file"], g["line"], g["rule_id"]) for g in _gt(app)}
    assert found == want  # every seed detected AND nothing extra (incl. SAFE lines)


def test_ground_truth_breadth():
    entries = _gt("demo_app") + _gt("demo_app_jsts")
    assert len(entries) >= 12
    assert len({e["class"] for e in entries}) >= 6
    assert NEW_RULES <= {e["rule_id"] for e in entries}
    ids = [e["id"] for e in entries]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("app", APPS)
def test_safe_lines_do_not_fire(app):
    fired = {(f.file, f.line) for f in _findings(app)}
    safe = []
    for p in (ROOT / app).iterdir():
        if p.suffix in {".py", ".js", ".ts"}:
            for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"(#|//)\s*SAFE\b", line):
                    safe.append((p.name, i))
    assert safe, "each app must contain at least one SAFE case"
    assert not (set(safe) & fired)


@pytest.mark.parametrize("app", APPS)
def test_no_raw_secret_in_any_finding(app):
    raw = set()
    for g in _gt(app):
        if g["class"] != "Hardcoded Secrets":
            continue
        line = (ROOT / app / g["file"]).read_text(encoding="utf-8").splitlines()[g["line"] - 1]
        raw |= set(re.findall(r"""['"]([^'"\s]{12,})['"]""", line))
    assert raw, "fixture must actually contain secret literals"
    blob = json.dumps([f.to_dict() for f in _findings(app)])
    for value in raw:
        assert value not in blob
