"""Additional rules from Document/rules.md (Task 4).

SQLI-002, XSS-001, XSS-003, AUTH-001, AUTH-002, DESER-002 (AST/regex) and
SECRET-001/002/003/006/007 (secrets scanner). Rule METADATA lives in
rules.yaml; this module is the implementation. tests/test_rule_registry.py
keeps the two in sync.

Secrets are redacted HERE, at detection time: no CandidateFinding produced by
this module ever carries a raw secret value in `snippet`.
"""

from __future__ import annotations

import math
import re

from analyst.common.types import CandidateFinding


from analyst.common.redact import (  # noqa: E402  single source for secret shapes
    AWS_KEY_ID_RE as _AWS_KEY_ID_RE,
    AWS_SECRET_RE as _AWS_SECRET_RE,
    GH_TOKEN_RE as _GH_TOKEN_RE,
    PRIVKEY_RE as _PRIVKEY_RE,
    redact_value as _redact,
)


def _mk(rule_id, vuln_class, rel_path, line, snippet, confidence="high", scanner="static"):
    return CandidateFinding(
        rule_id=rule_id, vuln_class=vuln_class, file=rel_path, line=line,
        snippet=snippet[:200], confidence=confidence, source_scanner=scanner,
    )


def _text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


# ---------------------------------------------------------------------------
# SQLI-002 (Python): .execute()/.raw() argument built via %-formatting or
# .format() with a variable. (f-strings / "+" are SQLI-001.)
# ---------------------------------------------------------------------------
_SQL_CALLS = {"execute", "executemany", "raw"}
_PCT_FORMAT_RE = re.compile(r"""["']\s*%\s*[\w(\[]""")      # "..." % var / (a, b)
_STR_FORMAT_RE = re.compile(r"""["']\s*\.format\s*\(\s*[^)\s]""")


def find_sqli_002(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        if _text(source, fn).rsplit(".", 1)[-1] not in _SQL_CALLS:
            continue
        first = args.named_children[0] if args.named_children else None
        if first is None:
            continue
        arg_text = _text(source, first)
        # Only the FIRST argument is the query; a "%s" + params tuple in the
        # second argument is the safe, parameterised form.
        if first.type == "binary_operator" and "%" in arg_text and _PCT_FORMAT_RE.search(arg_text):
            out.append(_mk("SQLI-002", "SQL Injection", rel_path, node.start_point[0] + 1, _text(source, node)))
        elif first.type == "call" and _STR_FORMAT_RE.search(arg_text):
            out.append(_mk("SQLI-002", "SQL Injection", rel_path, node.start_point[0] + 1, _text(source, node)))
    return out


# ---------------------------------------------------------------------------
# XSS-001 (JS/TS/React): dangerouslySetInnerHTML={{ __html: <non-literal> }}
# not passed through a sanitizer.
# ---------------------------------------------------------------------------
_SANITIZER_RE = re.compile(r"(DOMPurify|sanitize|sanitise|escapeHtml|xss\()", re.IGNORECASE)


def find_xss_001(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "jsx_attribute":
            continue
        text = _text(source, node)
        if "dangerouslySetInnerHTML" not in text:
            continue
        m = re.search(r"__html\s*:\s*(.+?)\s*\}?\}?\s*$", text, re.DOTALL)
        value = m.group(1) if m else ""
        if not value or re.fullmatch(r"""(['"`])[^${}]*\1""", value.strip()):
            continue  # missing or a constant literal
        if _SANITIZER_RE.search(value):
            continue
        out.append(_mk("XSS-001", "Cross-Site Scripting", rel_path, node.start_point[0] + 1, text))
    return out


# ---------------------------------------------------------------------------
# XSS-003: autoescaping disabled in a server-rendered template.
# Jinja2: {{ var|safe }} / Markup(var) in Python source strings;
# EJS: <%- var %> in JS/TS template strings. Regex over source lines: template
# text lives inside string literals / template files, not in AST structure.
# ---------------------------------------------------------------------------
_JINJA_SAFE_RE = re.compile(r"\{\{\s*[^}]*?\|\s*safe\s*\}\}")
_EJS_RAW_RE = re.compile(r"<%-\s*[A-Za-z_][^%]*%>")


def find_xss_003(source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    text = source.decode("utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _JINJA_SAFE_RE.search(line) or _EJS_RAW_RE.search(line):
            out.append(_mk("XSS-003", "Cross-Site Scripting", rel_path, lineno, line.strip(), scanner="static"))
    return out


# ---------------------------------------------------------------------------
# AUTH-001 (Python): password compared with == / != directly, i.e. stored or
# compared as plaintext instead of via a hash-verification call.
# ---------------------------------------------------------------------------
_PW_NAME = re.compile(r"password|passwd|pwd", re.IGNORECASE)
_HASH_VERIFY = re.compile(r"(check_password_hash|checkpw|verify|compare_digest|argon2|bcrypt|hash)", re.IGNORECASE)


def find_auth_001(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "comparison_operator":
            continue
        text = _text(source, node)
        if not re.search(r"(==|!=)", text) or not _PW_NAME.search(text):
            continue
        if _HASH_VERIFY.search(text):
            continue
        # Comparing a password to a literal is a hardcoded credential check;
        # comparing two password-named values is a plaintext comparison.
        out.append(_mk("AUTH-001", "Broken Authentication", rel_path, node.start_point[0] + 1, text))
    return out


# ---------------------------------------------------------------------------
# AUTH-002 (Python): md5 / sha1 applied directly to a password value.
# ---------------------------------------------------------------------------
def find_auth_002(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if fn is None:
            continue
        ftext = _text(source, fn)
        if not re.search(r"(^|\.)(md5|sha1)$", ftext):
            continue
        # hashlib.md5(password.encode()): the call mentions a password name.
        if _PW_NAME.search(_text(source, node)):
            out.append(_mk("AUTH-002", "Broken Authentication", rel_path, node.start_point[0] + 1, _text(source, node)))
    return out


# ---------------------------------------------------------------------------
# DESER-002 (JS/TS): eval() / new Function() with a non-literal argument.
# ---------------------------------------------------------------------------
def find_deser_002(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type not in ("call_expression", "new_expression"):
            continue
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        name = _text(source, fn)
        if name not in ("eval", "Function"):
            continue
        arg_nodes = args.named_children
        if not arg_nodes:
            continue
        # Any argument that is not a plain string literal is "non-literal".
        if all(a.type == "string" or (a.type == "template_string" and not any(
                c.type == "template_substitution" for c in a.children)) for a in arg_nodes):
            continue
        out.append(_mk("DESER-002", "Unsafe Deserialization", rel_path, node.start_point[0] + 1, _text(source, node)))
    return out


# ---------------------------------------------------------------------------
# Secrets: SECRET-001/002/003/006/007. Redacted at detection time.
# ---------------------------------------------------------------------------
_ASSIGN_LITERAL_RE = re.compile(r"""[\w.\-]+\s*(?::\s*\w+\s*)?[:=]\s*['"]([^'"\s]{20,})['"]""")
_PLACEHOLDER_RE = re.compile(r"(example|placeholder|changeme|xxxx|your[_-]?|dummy|sample|test)", re.IGNORECASE)
ENTROPY_MIN_LEN = 20
ENTROPY_MIN_BITS = 4.0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def find_secrets_extra(source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    text = source.decode("utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        claimed: list[str] = []  # values already reported on this line by a specific rule

        def report(rule, raw, conf="high"):
            claimed.append(raw)
            out.append(_mk(rule, "Hardcoded Secrets", rel_path, lineno,
                           line.strip().replace(raw, _redact(raw)), conf, "secrets"))

        for m in _AWS_KEY_ID_RE.finditer(line):
            report("SECRET-001", m.group(0))
        for m in _AWS_SECRET_RE.finditer(line):
            report("SECRET-002", m.group(1))
        for m in _GH_TOKEN_RE.finditer(line):
            report("SECRET-003", m.group(0))
        if _PRIVKEY_RE.search(line):
            # The header itself is not secret material, but the key body on
            # following lines is; report the header line and never echo body.
            out.append(_mk("SECRET-007", "Hardcoded Secrets", rel_path, lineno,
                           "Private key block header present (key material not shown)", "high", "secrets"))
        for m in _ASSIGN_LITERAL_RE.finditer(line):
            val = m.group(1)
            if any(val in c or c in val for c in claimed):
                continue  # already covered by a specific rule
            if _PLACEHOLDER_RE.search(val) or "{" in val:
                continue
            if len(val) >= ENTROPY_MIN_LEN and shannon_entropy(val) >= ENTROPY_MIN_BITS:
                report("SECRET-006", val, "low")
    return out
