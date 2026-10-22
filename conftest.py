"""Root-level shared fixtures."""
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent


@pytest.fixture
def original_demo_app(tmp_path):
    """The original 3-bug demo_app (secret, SQLi, XSS): the seeded bugs at
    app.py lines 7/15/28, without the Task 5 additions. The mocked pipeline
    tests pin their 1-accept / 2-escalate expectation to exactly this app."""
    src = (ROOT / "demo_app" / "app.py").read_bytes().decode()
    head, _, tail = src.partition("# SEEDED BUG 4")
    main = "if __name__ =="
    body = head + main + tail.split(main, 1)[1]
    d = tmp_path / "demo_app"
    d.mkdir()
    (d / "app.py").write_bytes(body.encode())
    return d


@pytest.fixture(autouse=True)
def ensure_groq_api_key_cleared(monkeypatch):
    """Ensure tests run offline by default without hitting live Groq APIs."""
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
