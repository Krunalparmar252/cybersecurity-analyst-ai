"""Task 1: Reasoning reaches Detection only through the bus (CAP_RULE_RECHECK)."""
import ast
from pathlib import Path

from analyst.reasoning import patch_loop


def test_patch_loop_does_not_import_detection():
    tree = ast.parse(Path(patch_loop.__file__).read_text())
    imported = [
        n.module for n in ast.walk(tree)
        if isinstance(n, ast.ImportFrom) and n.module
    ]
    assert not any(m.startswith("analyst.detection.agent") for m in imported)
    assert "recheck_rule" not in {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}


def test_busless_call_still_routes_via_bus(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\n")
    seen = []
    orig = patch_loop._local_bus

    def spy():
        bus = orig()
        real = bus.request_capability

        def wrapped(**kw):
            seen.append(kw["capability"])
            return real(**kw)

        bus.request_capability = wrapped
        return bus

    monkeypatch.setattr(patch_loop, "_local_bus", spy)
    still, evidence, corr = patch_loop._request_peer_validation(
        None, tmp_path, "app.py", "SQLI-001", 1
    )
    assert seen == ["rule.recheck"]
    assert still is False and corr is not None
