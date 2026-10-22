"""Task 7: --format md|html|pdf, safe HTML, valid PDF, no raw secret in any rendering."""
import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from analyst.__main__ import cli
from analyst.reporting.export import markdown_to_html, markdown_to_pdf, plan_outputs

ROOT = Path(__file__).resolve().parent.parent
APPS = ["demo_app", "demo_app_jsts"]


def _raw_secrets(app):
    raw = set()
    for g in json.loads((ROOT / app / "ground_truth.json").read_text(encoding="utf-8")):
        if g["class"] == "Hardcoded Secrets":
            line = (ROOT / app / g["file"]).read_text(encoding="utf-8").splitlines()[g["line"] - 1]
            raw |= set(re.findall(r"""['"]([^'"\s]{12,})['"]""", line))
    return raw


def test_plan_outputs():
    assert plan_outputs("r.md", "md") == (Path("r.md"), Path("r.md"))
    assert plan_outputs("r.md", "html") == (Path("r.md"), Path("r.html"))
    assert plan_outputs("out/r.pdf", "pdf") == (Path("out/r.md"), Path("out/r.pdf"))
    assert plan_outputs("r", "pdf") == (Path("r.md"), Path("r.pdf"))


def test_html_escapes_untrusted_markup():
    md = "# T\n\n`<script>alert(1)</script>`\n\n```\n<img src=x onerror=alert(1)>\n```\n"
    out = markdown_to_html(md)
    assert "<script>" not in out and "<img" not in out
    assert "&lt;script&gt;" in out and "&lt;img" in out


def test_pdf_is_structurally_valid_and_paginates():
    md = "\n".join(f"line {i} with (parens) and \\ backslash — dash" for i in range(300))
    pdf = markdown_to_pdf(md)
    assert pdf.startswith(b"%PDF-1.4") and pdf.rstrip().endswith(b"%%EOF")
    n_pages = len(re.findall(rb"/Type /Page /Parent", pdf))
    assert n_pages >= 5
    # xref offsets point at real objects
    xref = int(re.search(rb"startxref\n(\d+)", pdf).group(1))
    entries = re.findall(rb"(\d{10}) 00000 n ", pdf[xref:])
    for k, off in enumerate(entries, start=1):
        assert pdf[int(off):].startswith(f"{k} 0 obj".encode())
    assert b"line 299" in pdf


@pytest.mark.parametrize("app", APPS)
@pytest.mark.parametrize("fmt", ["md", "html", "pdf"])
def test_cli_format_and_no_raw_secret_in_rendered_reports(tmp_path, app, fmt):
    out = tmp_path / "report.md"
    art = tmp_path / "art"
    res = CliRunner().invoke(cli, ["scan", str(ROOT / app), "--offline", "-o", str(out),
                                   "--artifacts", str(art), "--format", fmt])
    assert res.exit_code == 0, res.output
    produced = {"md": out, "html": tmp_path / "report.html", "pdf": tmp_path / "report.pdf"}[fmt]
    assert produced.exists() and out.exists()  # markdown is always kept
    if fmt == "pdf":
        assert produced.read_bytes().startswith(b"%PDF")
    raw = _raw_secrets(app)
    assert raw
    files = [out, produced, *art.glob("*.json")]
    for f in files:
        data = f.read_bytes().decode("latin-1")
        for value in raw:
            assert value not in data, f"raw secret leaked into {f.name}"
