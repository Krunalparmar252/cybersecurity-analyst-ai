"""Export the Markdown report as HTML or PDF (stdlib only, no new dependencies).

The Markdown report stays the canonical artifact: its integrity sidecar is
computed over it. HTML/PDF are renderings of that exact text. All report text
is HTML-escaped before markup is added, because findings quote attacker-
influenced source code (a snippet containing <script> must not become live
script in the HTML export).
"""

from __future__ import annotations

import html
import re
import textwrap
from pathlib import Path
from typing import Tuple

FORMATS = ("md", "html", "pdf")

_DETAILS_OPEN = re.compile(r"^<details><summary>(.*)</summary>\s*$")


def plan_outputs(output: str, fmt: str) -> Tuple[Path, Path]:
    """Return (markdown_path, target_path). Markdown is always produced (it is
    what the integrity sidecar covers); html/pdf go next to it."""
    out = Path(output)
    if fmt == "md":
        return out, out
    target = out if out.suffix.lower() == f".{fmt}" else out.with_suffix(f".{fmt}")
    return target.with_suffix(".md"), target


# ------------------------------------------------------------------ HTML
def _inline(escaped: str) -> str:
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", escaped)
    return re.sub(r"(?<![\w])_([^_]+)_(?![\w])", r"<em>\1</em>", escaped)


_CSS = (
    "body{font:15px/1.5 -apple-system,Segoe UI,Helvetica,Arial,sans-serif;max-width:920px;"
    "margin:2rem auto;padding:0 1rem;color:#1f2328}h1,h2,h3{line-height:1.25}"
    "pre{background:#f6f8fa;padding:.75rem;overflow:auto;border-radius:6px;font-size:13px}"
    "code{background:#f6f8fa;padding:.1rem .3rem;border-radius:4px}pre code{padding:0}"
    "table{border-collapse:collapse}td,th{border:1px solid #d0d7de;padding:.3rem .6rem}"
    "blockquote{border-left:4px solid #d0d7de;margin:0;padding:0 1rem;color:#57606a}"
    "details{margin:.5rem 0}li.l1{margin-left:1.5rem}"
)


def markdown_to_html(md: str, title: str = "Security Scan Report") -> str:
    out, lines, i = [], md.splitlines(), 0
    para: list[str] = []

    def flush():
        if para:
            out.append("<p>" + "<br>\n".join(_inline(html.escape(p.rstrip())) for p in para) + "</p>")
            para.clear()

    while i < len(lines):
        line = lines[i]
        if line.startswith("```"):
            flush()
            i += 1
            buf = []
            while i < len(lines) and not lines[i].startswith("```"):
                buf.append(html.escape(lines[i]))
                i += 1
            out.append("<pre><code>" + "\n".join(buf) + "</code></pre>")
        elif (m := _DETAILS_OPEN.match(line)):
            flush()
            out.append(f"<details><summary>{_inline(html.escape(m.group(1)))}</summary>")
        elif line.strip() == "</details>":
            flush()
            out.append("</details>")
        elif re.match(r"^#{1,6} ", line):
            flush()
            n = len(line) - len(line.lstrip("#"))
            out.append(f"<h{n}>{_inline(html.escape(line[n:].strip()))}</h{n}>")
        elif line.strip() == "---":
            flush()
            out.append("<hr>")
        elif line.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            i -= 1
            body = [r for r in rows if not all(re.fullmatch(r":?-{2,}:?", c) for c in r)]
            t = []
            for n, r in enumerate(body):
                tag = "th" if n == 0 else "td"
                t.append("<tr>" + "".join(f"<{tag}>{_inline(html.escape(c))}</{tag}>" for c in r) + "</tr>")
            out.append("<table>" + "".join(t) + "</table>")
        elif re.match(r"^\s*[-*] ", line):
            flush()
            indent = len(line) - len(line.lstrip())
            cls = ' class="l1"' if indent >= 2 else ""
            out.append(f"<ul><li{cls}>{_inline(html.escape(line.strip()[2:]))}</li></ul>")
        elif line.startswith(">"):
            flush()
            out.append(f"<blockquote>{_inline(html.escape(line.lstrip('> ').strip()))}</blockquote>")
        elif not line.strip():
            flush()
        else:
            para.append(line)
        i += 1
    flush()
    return (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        f"<title>{html.escape(title)}</title><style>{_CSS}</style></head><body>\n"
        + "\n".join(out) + "\n</body></html>\n"
    )


# ------------------------------------------------------------------- PDF
_TRANSLIT = {"—": "-", "–": "-", "…": "...", "“": '"', "”": '"', "‘": "'", "’": "'",
             "🚩": "[!]", "✅": "[ok]", "⚠": "[!]", "•": "*", "→": "->", "×": "x"}
_PAGE_W, _PAGE_H, _MARGIN, _LEAD = 612, 792, 50, 11.5
_WRAP = 92  # Courier 9pt: 5.4pt/char across 512pt


def _latin1(s: str) -> str:
    for k, v in _TRANSLIT.items():
        s = s.replace(k, v)
    return s.encode("cp1252", "replace").decode("cp1252")


def _pdf_lines(md: str) -> list[tuple[str, bool]]:
    """Markdown -> [(text, bold)] already wrapped to the page width."""
    out: list[tuple[str, bool]] = []
    in_code = False

    def add(text: str, bold: bool = False, indent: str = ""):
        text = _latin1(text)
        for seg in textwrap.wrap(text, _WRAP, subsequent_indent=indent + "  ", initial_indent=indent,
                                 break_long_words=True, replace_whitespace=False) or [""]:
            out.append((seg, bold))

    for line in md.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            continue
        if in_code:
            out.append((_latin1(line)[:_WRAP * 2].rstrip(), False))  # code: keep verbatim, hard-clip
            continue
        if (m := _DETAILS_OPEN.match(line)):
            add("[" + re.sub(r"[`*]", "", m.group(1)) + "]", True)
            continue
        if line.strip() == "</details>":
            continue
        if re.match(r"^#{1,6} ", line):
            out.append(("", False))
            add(re.sub(r"[`*]", "", line.lstrip("#").strip()).upper(), True)
            continue
        if line.startswith("|"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells):
                continue
            add(re.sub(r"[`*]", "", " | ".join(cells)))
            continue
        if line.strip() == "---":
            out.append(("-" * _WRAP, False))
            continue
        plain = re.sub(r"[`*]|(?<!\w)_|_(?!\w)", "", line.rstrip())
        lead = len(line) - len(line.lstrip())
        add(plain.strip(), False, " " * lead) if plain.strip() else out.append(("", False))
    return out


def _pdf_escape(s: str) -> bytes:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("cp1252", "replace")


def markdown_to_pdf(md: str) -> bytes:
    lines = _pdf_lines(md)
    per_page = int((_PAGE_H - 2 * _MARGIN) // _LEAD)
    pages = [lines[i:i + per_page] for i in range(0, len(lines), per_page)] or [[("", False)]]

    objs: list[bytes] = [b""] * (3 + 2 * len(pages) + 1)  # 1-indexed below
    # 1 catalog, 2 pages, 3 Courier, 4 Courier-Bold, then (page, content) pairs
    kids = b" ".join(f"{5 + 2 * n} 0 R".encode() for n in range(len(pages)))
    objs[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objs[1] = b"<< /Type /Pages /Kids [" + kids + b"] /Count " + str(len(pages)).encode() + b" >>"
    objs[2] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>"
    objs[3] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier-Bold /Encoding /WinAnsiEncoding >>"
    for n, page in enumerate(pages):
        ops = [b"BT", f"{_LEAD} TL".encode(), f"{_MARGIN} {_PAGE_H - _MARGIN - 9} Td".encode()]
        for text, bold in page:
            ops.append((b"/F2 9 Tf (" if bold else b"/F1 9 Tf (") + _pdf_escape(text) + b") Tj T*")
        ops.append(b"ET")
        stream = b"\n".join(ops)
        objs[4 + 2 * n] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {_PAGE_W} {_PAGE_H}] "
            f"/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents {5 + 2 * n + 1} 0 R >>"
        ).encode()
        objs[5 + 2 * n] = b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
    objs = objs[: 4 + 2 * len(pages)]

    buf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(buf))
        buf += f"{i} 0 obj\n".encode() + body + b"\nendobj\n"
    xref = len(buf)
    buf += f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode()
    for off in offsets:
        buf += f"{off:010d} 00000 n \n".encode()
    buf += f"trailer\n<< /Size {len(objs) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode()
    return bytes(buf)


def write_export(md_path: Path, fmt: str, target: Path) -> Path:
    """Render the Markdown report at md_path into `fmt` at target."""
    md = Path(md_path).read_text(encoding="utf-8")
    if fmt == "html":
        Path(target).write_text(markdown_to_html(md), encoding="utf-8")
    elif fmt == "pdf":
        Path(target).write_bytes(markdown_to_pdf(md))
    elif fmt != "md":
        raise ValueError(f"unsupported format: {fmt}")
    return Path(target)
