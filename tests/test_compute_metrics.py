"""Task 6: metrics script runs offline and reports internally consistent numbers."""
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("compute_metrics", ROOT / "scripts" / "compute_metrics.py")
cm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cm)


def test_metrics_for_demo_apps_are_consistent():
    for app in cm.DEFAULT_APPS:
        m = cm.compute_app_metrics(app, offline=True)
        b, a = m["before_reason"], m["after_reason"]
        assert b["true_positives"] + b["false_positives"] == b["findings"]
        assert a["findings"] == b["findings"] - m["rejected_by_reason"]
        assert b["recall"] == 1.0  # every seeded bug is detected
        p = m["patches"]
        assert p["accepted"] <= p["proposed"]
        assert m["run_seconds"] > 0


def test_cli_writes_md_and_json(tmp_path):
    md, js = tmp_path / "m.md", tmp_path / "m.json"
    assert cm.main(["demo_app", "-o", str(md), "--json", str(js)]) == 0
    data = json.loads(js.read_text())
    assert data["runs"][0]["app"] == "demo_app"
    text = md.read_text()
    assert "Recall before" in text and "not exercised" in text
