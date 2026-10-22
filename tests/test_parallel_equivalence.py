"""Task 3: parallel INGEST/DETECT output must equal sequential output."""
from dataclasses import asdict
from pathlib import Path

import pytest

from analyst.common.parallel import chunked, parallel_chunks
from analyst.detection.engine import run_detection
from analyst.ingestion.manifest import ingest_repo
from analyst.protocol.crypto import SaltContext

ROOT = Path(__file__).resolve().parent.parent

PY_VULN = (
    "import sqlite3\n"
    "def q(name):\n"
    "    c = sqlite3.connect('x')\n"
    "    return c.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n"
)


@pytest.fixture
def many_files_repo(tmp_path):
    for i in range(23):
        (tmp_path / f"m{i:02d}.py").write_text(PY_VULN + f"# {i}\n")
    sub = tmp_path / "pkg"
    sub.mkdir()
    for i in range(7):
        (sub / f"n{i}.js").write_text("const a = 1;\nel.innerHTML = req.query.x;\n")
    (tmp_path / "notes.txt").write_text("not source\n")
    return tmp_path


def _snapshot(repo, workers, ctx):
    ing = ingest_repo(str(repo), salt_ctx=ctx, workers=workers)
    found = [asdict(f) for f in run_detection(ing, workers=workers)]
    return {
        "manifest": ing.manifest.to_json(),
        "sources": list(ing.sources.items()),
        "ast_paths": list(ing.asts),
        "findings": found,
    }


@pytest.mark.parametrize("workers", [2, 3, 8])
def test_parallel_equals_sequential_synthetic(many_files_repo, workers):
    ctx = SaltContext.generate(run_id="par-test")
    seq = _snapshot(many_files_repo, 1, ctx)
    par = _snapshot(many_files_repo, workers, ctx)
    assert seq["findings"], "fixture must produce findings or the test is vacuous"
    assert par == seq  # includes ordering


@pytest.mark.parametrize("app", ["demo_app", "demo_app_jsts"])
def test_parallel_equals_sequential_demo_apps(app):
    ctx = SaltContext.generate(run_id="par-demo")
    assert _snapshot(ROOT / app, 4, ctx) == _snapshot(ROOT / app, 1, ctx)


def test_chunked_helper_contiguous_and_complete():
    items = list(range(10))
    for n in (1, 3, 4, 10, 50):
        chunks = chunked(items, n)
        assert [x for c in chunks for x in c] == items
        assert all(chunks)
    assert chunked([], 4) == []
    assert parallel_chunks([], lambda c: c, 4) == []
