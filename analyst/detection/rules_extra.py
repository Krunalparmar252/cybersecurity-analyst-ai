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
from pathlib import Path
from typing import Optional

from analyst.common.types import CandidateFinding


from analyst.common.redact import (  # noqa: E402  single source for secret shapes
    AWS_KEY_ID_RE as _AWS_KEY_ID_RE,
    AWS_SECRET_RE as _AWS_SECRET_RE,
    GH_TOKEN_RE as _GH_TOKEN_RE,
    JWT_RE as _JWT_RE,
    PRIVKEY_RE as _PRIVKEY_RE,
    redact_value as _redact,
)


def _mk(rule_id, vuln_class, rel_path, line, snippet, confidence="high", scanner="static", dataflow=None):
    return CandidateFinding(
        rule_id=rule_id, vuln_class=vuln_class, file=rel_path, line=line,
        snippet=snippet[:200], confidence=confidence, source_scanner=scanner,
        dataflow=dataflow or [],
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
_HASH_VERIFY = re.compile(r"(check_password_hash|checkpw|verify|compare_digest|argon2|bcrypt|timingSafeEqual)", re.IGNORECASE)


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
        for m in _JWT_RE.finditer(line):
            val = m.group(0)
            if any(val in c or c in val for c in claimed):
                continue
            if _PLACEHOLDER_RE.search(val) or "{" in val:
                continue
            report("SECRET-004", val, "medium")
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


# ---------------------------------------------------------------------------
# SECRET-008: Tracked .env file present in repository (not in .gitignore).
# ---------------------------------------------------------------------------
def find_secret_008(rel_path: str, gitignore_content: Optional[str] = None) -> list[CandidateFinding]:
    p = re.split(r"[\\/]", rel_path)[-1]
    if p in (".env", ".env.local", ".env.production", ".env.development") or p.startswith(".env."):
        if gitignore_content:
            for line in gitignore_content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    pattern = line.strip("/")
                    if pattern in (".env", ".env*", p) or (pattern.startswith(".env") and p.startswith(".env")):
                        return []
        return [_mk("SECRET-008", "Hardcoded Secrets", rel_path, 1,
                    ".env file present in repository (potential credential exposure)", "medium", "secrets")]
    return []


# ---------------------------------------------------------------------------
# XSS-004 (Python): Flask render_template_string() called with tainted template.
# ---------------------------------------------------------------------------
def find_xss_004(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        if _text(source, fn).rsplit(".", 1)[-1] != "render_template_string":
            continue
        named = args.named_children
        if not named:
            continue
        first = named[0]
        first_text = _text(source, first)
        call_text = _text(source, node)

        is_tainted = False
        if first.type == "string" and ('{' in first_text and ('f"' in first_text or "f'" in first_text)):
            is_tainted = True
        elif first.type == "binary_operator" and any(op in first_text for op in ("+", "%")):
            is_tainted = True
        elif first.type == "call" and ".format" in first_text:
            is_tainted = True
        elif first.type == "identifier":
            var_name = first_text
            scope = node.parent
            while scope is not None and scope.type != "function_definition":
                scope = scope.parent
            if scope is not None:
                for n in _walk(scope):
                    if n.type == "assignment":
                        left = n.child_by_field_name("left")
                        right = n.child_by_field_name("right")
                        if left and right and _text(source, left) == var_name:
                            rtext = _text(source, right)
                            if ('f"' in rtext or "f'" in rtext or "+" in rtext or "%" in rtext or
                                ".format" in rtext or "request." in rtext):
                                is_tainted = True
                                break
        if is_tainted:
            out.append(_mk("XSS-004", "Cross-Site Scripting", rel_path, node.start_point[0] + 1, call_text, "high"))
    return out


# ---------------------------------------------------------------------------
# AUTH-003: Login/auth route with no rate-limiting decorator/middleware.
# ---------------------------------------------------------------------------
_AUTH_ROUTE_RE = re.compile(r"/(login|signin|auth|token|authenticate)\b", re.IGNORECASE)
_AUTH_FUNC_NAME_RE = re.compile(r"^(login|signin|authenticate|auth_user|token|auth)$", re.IGNORECASE)
_AUTH_ACTION_RE = re.compile(r"(check_password_hash|verify_password|authenticate|login_user|create_access_token|set_cookie|session\[|jwt\.encode)", re.IGNORECASE)
_RATE_LIMIT_RE = re.compile(r"(limit|limiter|ratelimit|throttle)", re.IGNORECASE)


def find_auth_003(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "decorated_definition":
            decorators = [c for c in node.children if c.type == "decorator"]
            func_node = next((c for c in node.children if c.type == "function_definition"), None)
            if func_node is None or not decorators:
                continue
            is_route = False
            is_auth_route = False
            has_rate_limit = False
            for dec in decorators:
                dtext = _text(source, dec)
                if any(kw in dtext for kw in ("route", "post", "get", "put")):
                    is_route = True
                    if _AUTH_ROUTE_RE.search(dtext):
                        is_auth_route = True
                if _RATE_LIMIT_RE.search(dtext):
                    has_rate_limit = True

            fname_node = func_node.child_by_field_name("name")
            if fname_node and _AUTH_FUNC_NAME_RE.search(_text(source, fname_node)):
                is_auth_route = True

            func_text = _text(source, func_node)
            has_auth_action = bool(_AUTH_ACTION_RE.search(func_text))

            if is_route and is_auth_route and has_auth_action and not has_rate_limit:
                out.append(_mk("AUTH-003", "Broken Authentication", rel_path,
                               func_node.start_point[0] + 1, _text(source, decorators[0]), "medium"))
    return out


def find_auth_003_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn is None or args is None:
                continue
            fn_text = _text(source, fn)
            if not any(fn_text.endswith("." + m) for m in ("post", "get", "put", "route", "use")):
                continue
            args_named = args.named_children
            if not args_named:
                continue
            first_arg = _text(source, args_named[0])
            if not _AUTH_ROUTE_RE.search(first_arg):
                continue
            call_text = _text(source, node)
            if not _AUTH_ACTION_RE.search(call_text) and "password" not in call_text.lower():
                continue
            if not _RATE_LIMIT_RE.search(call_text):
                out.append(_mk("AUTH-003", "Broken Authentication", rel_path,
                               node.start_point[0] + 1, call_text[:200], "medium"))
    return out


# ---------------------------------------------------------------------------
# AUTH-004: Session cookie set without HttpOnly and/or Secure flags.
# ---------------------------------------------------------------------------
def find_auth_004(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        if _text(source, fn).rsplit(".", 1)[-1] != "set_cookie":
            continue
        call_text = _text(source, node)
        if not re.search(r"['\"](session|auth|sid|token|login|jwt|user_id)['\"]", call_text, re.IGNORECASE):
            continue
        has_httponly = bool(re.search(r"httponly\s*=\s*True", call_text, re.IGNORECASE))
        has_secure = bool(re.search(r"secure\s*=\s*True", call_text, re.IGNORECASE))
        if not (has_httponly and has_secure):
            out.append(_mk("AUTH-004", "Broken Authentication", rel_path,
                           node.start_point[0] + 1, call_text[:200], "medium"))
    return out


def find_auth_004_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not (fn_text.endswith(".cookie") or fn_text.endswith(".setCookie") or fn_text.endswith(".set_cookie")):
            continue
        call_text = _text(source, node)
        if not re.search(r"['\"](session|auth|sid|token|login|jwt|user_id)['\"]", call_text, re.IGNORECASE):
            continue
        has_httponly = bool(re.search(r"httpOnly\s*:\s*true", call_text, re.IGNORECASE))
        has_secure = bool(re.search(r"secure\s*:\s*true", call_text, re.IGNORECASE))
        if not (has_httponly and has_secure):
            out.append(_mk("AUTH-004", "Broken Authentication", rel_path,
                           node.start_point[0] + 1, call_text[:200], "medium"))
    return out


# ---------------------------------------------------------------------------
# SSRF-001: HTTP client call with user-controlled URL without allowlist.
# ---------------------------------------------------------------------------
_SSRF_PY_CALLS = re.compile(r"(requests\.(get|post|put|delete|request)|urllib\.request\.urlopen|urlopen|httpx\.(get|post|put|delete|request)|aiohttp\..*\.get|session\.(get|post))")
_SSRF_JS_CALLS = re.compile(r"(fetch|axios(\.(get|post|put|delete))?|http\.(get|request)|https\.(get|request))")
_ALLOWLIST_RE = re.compile(r"(ALLOWED_HOSTS|ALLOWED_DOMAINS|ALLOWLIST|ALLOWED_URLS|ALLOWED_ORIGINS|is_safe_url|urlparse|startswith|whitelist)", re.IGNORECASE)


def find_ssrf_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not _SSRF_PY_CALLS.search(fn_text):
            continue
        named = args.named_children
        if not named:
            continue
        first = named[0]
        first_text = _text(source, first)
        call_text = _text(source, node)

        # Constant literal string without formatting -> safe
        if first.type == "string" and not any(c in first_text for c in ("{", "%")) and not first_text.startswith("f"):
            continue

        scope = node.parent
        while scope is not None and scope.type != "function_definition":
            scope = scope.parent
        scope_text = _text(source, scope) if scope else _text(source, tree.root_node)
        if _ALLOWLIST_RE.search(scope_text):
            continue

        is_tainted = False
        if first.type == "string" and ('{' in first_text and ('f"' in first_text or "f'" in first_text)):
            is_tainted = True
        elif first.type == "binary_operator" and "+" in first_text:
            is_tainted = True
        elif first.type == "identifier":
            var_name = first_text
            if scope:
                for n in _walk(scope):
                    if n.type == "assignment":
                        left = n.child_by_field_name("left")
                        right = n.child_by_field_name("right")
                        if left and right and _text(source, left) == var_name:
                            rtext = _text(source, right)
                            if "request." in rtext or "req." in rtext or "+" in rtext or "f" in rtext:
                                is_tainted = True
                                break
                    elif n.type == "parameters":
                        if var_name in _text(source, n):
                            is_tainted = True
        if is_tainted:
            out.append(_mk("SSRF-001", "Server-Side Request Forgery", rel_path,
                           node.start_point[0] + 1, call_text[:200], "medium"))
    return out


def find_ssrf_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not _SSRF_JS_CALLS.search(fn_text):
            continue
        named = args.named_children
        if not named:
            continue
        first = named[0]
        first_text = _text(source, first)
        call_text = _text(source, node)

        # Constant literal string -> safe
        if first.type == "string" or (first.type == "template_string" and not any(
                c.type == "template_substitution" for c in first.children)):
            continue

        scope = node.parent
        while scope is not None and scope.type not in ("function_declaration", "arrow_function", "function_expression"):
            scope = scope.parent
        scope_text = _text(source, scope) if scope else _text(source, tree.root_node)
        if _ALLOWLIST_RE.search(scope_text):
            continue

        is_tainted = False
        if first.type == "template_string" and any(c.type == "template_substitution" for c in first.children):
            is_tainted = True
        elif first.type == "binary_expression" and "+" in first_text:
            is_tainted = True
        elif first.type == "identifier":
            var_name = first_text
            if scope:
                for n in _walk(scope):
                    if n.type == "variable_declarator":
                        name_node = n.child_by_field_name("name")
                        val_node = n.child_by_field_name("value")
                        if name_node and val_node and _text(source, name_node) == var_name:
                            vtext = _text(source, val_node)
                            if "req." in vtext or "+" in vtext or "${" in vtext:
                                is_tainted = True
                                break
                    elif n.type == "formal_parameters":
                        if var_name in _text(source, n):
                            is_tainted = True
        if is_tainted:
            out.append(_mk("SSRF-001", "Server-Side Request Forgery", rel_path,
                           node.start_point[0] + 1, call_text[:200], "medium"))
    return out



# ---------------------------------------------------------------------------
# CMDINJ-002 (JS/TS): child_process.exec/execSync/spawn with tainted input.
# ---------------------------------------------------------------------------
_JS_CMD_CALLS = re.compile(r"(^|\.)(exec|execSync|spawn|spawnSync)$")


def find_cmdinj_002(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not _JS_CMD_CALLS.search(fn_text):
            continue
        named = args.named_children
        if not named:
            continue
        first = named[0]
        first_text = _text(source, first)
        call_text = _text(source, node)

        if "spawn" in fn_text:
            if not re.search(r"shell\s*:\s*true", call_text, re.IGNORECASE):
                continue

        # Constant literal string without substitution -> safe
        if first.type == "string" or (first.type == "template_string" and not any(
                c.type == "template_substitution" for c in first.children)):
            continue

        is_tainted = False
        if first.type == "template_string" and any(c.type == "template_substitution" for c in first.children):
            is_tainted = True
        elif first.type == "binary_expression" and "+" in first_text:
            is_tainted = True
        elif first.type == "identifier":
            is_tainted = True

        if is_tainted:
            out.append(_mk("CMDINJ-002", "Command Injection", rel_path,
                           node.start_point[0] + 1, call_text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# PATHTRAV-002 (JS/TS): fs.readFile/writeFile/res.sendFile with tainted input.
# ---------------------------------------------------------------------------
_JS_FS_PATH_CALLS = re.compile(r"(^|\.)(readFile|readFileSync|createReadStream|writeFile|writeFileSync|sendFile|download)$")


def find_pathtrav_002(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not _JS_FS_PATH_CALLS.search(fn_text):
            continue
        named = args.named_children
        if not named:
            continue
        first = named[0]
        first_text = _text(source, first)
        call_text = _text(source, node)

        # Constant literal string -> safe
        if first.type == "string" or (first.type == "template_string" and not any(
                c.type == "template_substitution" for c in first.children)):
            continue

        scope = node.parent
        while scope is not None and scope.type not in ("function_declaration", "arrow_function", "function_expression"):
            scope = scope.parent
        scope_text = _text(source, scope) if scope else _text(source, tree.root_node)
        if "startsWith" in scope_text or "indexOf" in scope_text:
            continue

        is_tainted = False
        if first.type == "template_string" and any(c.type == "template_substitution" for c in first.children):
            is_tainted = True
        elif first.type == "binary_expression" and "+" in first_text:
            is_tainted = True
        elif first.type == "call_expression" and ("path.join" in first_text or "path.resolve" in first_text):
            if any(c.type == "identifier" or c.type == "template_string" for c in first.children):
                is_tainted = True
        elif first.type == "identifier":
            is_tainted = True

        if is_tainted:
            out.append(_mk("PATHTRAV-002", "Path Traversal", rel_path,
                           node.start_point[0] + 1, call_text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# DESER-003 (JS/TS): node-serialize, unsafe yaml.load, vm.runInContext.
# ---------------------------------------------------------------------------
_DESER_JS_CALLS = re.compile(r"(unserialize|yaml\.(load|unsafeLoad)|jsyaml\.(load|unsafeLoad)|vm\.(runInContext|runInNewContext|runInThisContext|Script))")


def find_deser_003(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type not in ("call_expression", "new_expression"):
            continue
        fn = node.child_by_field_name("function") or node.child_by_field_name("constructor")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not _DESER_JS_CALLS.search(fn_text):
            continue
        call_text = _text(source, node)

        if "load" in fn_text and "unsafeLoad" not in fn_text:
            if any(s in call_text for s in ("FAILSAFE_SCHEMA", "CORE_SCHEMA", "DEFAULT_SCHEMA", "schema:")):
                continue

        if "vm." in fn_text or fn_text == "Script":
            named = args.named_children
            if named and (named[0].type == "string" or (named[0].type == "template_string" and not any(
                    c.type == "template_substitution" for c in named[0].children))):
                continue

        out.append(_mk("DESER-003", "Unsafe Deserialization", rel_path,
                       node.start_point[0] + 1, call_text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# AUTH-005 (JS/TS): password compared with == / === instead of hash compare.
# ---------------------------------------------------------------------------
def find_auth_005(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "binary_expression":
            continue
        op = node.child_by_field_name("operator")
        if op is None or _text(source, op) not in ("==", "===", "!=", "!=="):
            continue
        text = _text(source, node)
        if not _PW_NAME.search(text):
            continue
        if _HASH_VERIFY.search(text):
            continue
        out.append(_mk("AUTH-005", "Broken Authentication", rel_path,
                       node.start_point[0] + 1, text, "high"))
    return out


# ---------------------------------------------------------------------------
# AUTH-006 (JS/TS): crypto.createHash('md5'|'sha1') applied to password.
# ---------------------------------------------------------------------------
def find_auth_006(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not (fn_text.endswith("createHash") or fn_text == "createHash"):
            continue
        call_text = _text(source, node)
        if not re.search(r"createHash\s*\(\s*['\"](md5|sha1)['\"]\s*\)", call_text, re.IGNORECASE):
            continue
        stmt = node.parent
        while stmt is not None and stmt.type not in ("expression_statement", "variable_declaration", "lexical_declaration", "return_statement"):
            stmt = stmt.parent
        stmt_text = _text(source, stmt) if stmt else call_text
        if _PW_NAME.search(stmt_text):
            out.append(_mk("AUTH-006", "Broken Authentication", rel_path,
                           node.start_point[0] + 1, stmt_text[:200], "high"))
    return out


# ===========================================================================
# PHASE 2 RULES
# ===========================================================================

# ---------------------------------------------------------------------------
# REDIR-001 (Python & JS/TS): Open redirect with unvalidated URL target.
# ---------------------------------------------------------------------------
_REDIR_CALLS = {"redirect", "flask.redirect", "res.redirect", "response.redirect"}
_ALLOWLIST_CHECK = re.compile(r"(?i)(in\s+allowed|in\s+whitelist|is_safe_url|starts?with\s*\(\s*['\"]/['\"]\)|includes|indexOf)")


def find_redir_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        called = fn_text.rsplit(".", 1)[-1]
        if called != "redirect":
            continue
        named = args.named_children
        if not named:
            continue
        target_arg = named[0]
        # Ignore literal constant targets e.g. redirect("/login")
        if target_arg.type == "string":
            continue
        # Check enclosing function for allowlist or relative-path checks
        scope = node.parent
        while scope is not None and scope.type != "function_definition":
            scope = scope.parent
        scope_text = _text(source, scope) if scope else ""
        if _ALLOWLIST_CHECK.search(scope_text):
            continue
        out.append(_mk("REDIR-001", "Open Redirect", rel_path, node.start_point[0] + 1, _text(source, node), "high"))
    return out


def find_redir_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if fn is None or args is None:
            continue
        fn_text = _text(source, fn)
        if not (fn_text == "redirect" or fn_text.endswith(".redirect")):
            continue
        named = args.named_children
        if not named:
            continue
        target_arg = named[0]
        if target_arg.type == "string":
            continue
        scope = node.parent
        while scope is not None and scope.type not in ("function_declaration", "arrow_function", "method_definition"):
            scope = scope.parent
        scope_text = _text(source, scope) if scope else ""
        if _ALLOWLIST_CHECK.search(scope_text):
            continue
        out.append(_mk("REDIR-001", "Open Redirect", rel_path, node.start_point[0] + 1, _text(source, node), "high"))
    return out


# ---------------------------------------------------------------------------
# TLS-001 (Python & JS/TS): Certificate verification disabled.
# ---------------------------------------------------------------------------
_HTTP_CLIENT_CALLS = re.compile(r"\b(requests\.(get|post|put|delete|patch|head|request)|httpx\.(get|post|put|delete|patch|head|request|Client|AsyncClient)|urllib\.request\.urlopen|aiohttp\.(request|ClientSession)|Session)\b")


def find_tls_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        fn_text = _text(source, fn) if fn else ""
        call_text = _text(source, node)
        if _HTTP_CLIENT_CALLS.search(fn_text) or _HTTP_CLIENT_CALLS.search(call_text):
            if re.search(r"\bverify\s*=\s*(False|0)\b", call_text):
                out.append(_mk("TLS-001", "Insecure TLS Configuration", rel_path, node.start_point[0] + 1, call_text[:200], "high"))
        elif "_create_unverified_context" in fn_text or "_create_unverified_context" in call_text:
            out.append(_mk("TLS-001", "Insecure TLS Configuration", rel_path, node.start_point[0] + 1, call_text[:200], "high"))
    return out


def find_tls_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        text = _text(source, node)
        if node.type in ("pair", "property"):
            if re.search(r"['\"]?rejectUnauthorized['\"]?\s*:\s*false\b", text, re.IGNORECASE):
                out.append(_mk("TLS-001", "Insecure TLS Configuration", rel_path, node.start_point[0] + 1, text[:200], "high"))
        elif node.type in ("assignment_expression", "expression_statement"):
            if "NODE_TLS_REJECT_UNAUTHORIZED" in text and re.search(r"['\"]0['\"]|0", text):
                out.append(_mk("TLS-001", "Insecure TLS Configuration", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# CORS-001 (Python & JS/TS): Wildcard origin combined with credentials.
# ---------------------------------------------------------------------------
def find_cors_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        text = _text(source, node)
        if "CORS" in text and "supports_credentials=True" in text and ('origins="*"' in text or "origins=['*']" in text or 'origins=["*"]' in text):
            out.append(_mk("CORS-001", "CORS Misconfiguration", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


def find_cors_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if not fn or _text(source, fn) != "cors":
                continue
            text = _text(source, node)
            if re.search(r"origin\s*:\s*['\"]\*['\"]", text) and re.search(r"credentials\s*:\s*true\b", text, re.IGNORECASE):
                out.append(_mk("CORS-001", "CORS Misconfiguration", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# CRYPTO-001 (Python & JS/TS): Weak hash (md5/sha1) for security tokens/sigs.
# ---------------------------------------------------------------------------
_SEC_HASH_TARGET = re.compile(r"(?i)(token|secret|signature|auth_key|authKey|session|apiKey|api_key)")
_NON_SEC_HASH = re.compile(r"(?i)(password|cache|etag|checksum|file|content|blob)")


def find_crypto_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if not fn:
            continue
        fn_text = _text(source, fn)
        if not re.search(r"\b(hashlib\.(md5|sha1)|MD5\.new|SHA1\.new)$", fn_text):
            continue
        call_text = _text(source, node)
        stmt = node.parent
        while stmt is not None and stmt.type not in ("assignment", "return_statement", "expression_statement"):
            stmt = stmt.parent
        stmt_text = _text(source, stmt) if stmt else call_text
        if _SEC_HASH_TARGET.search(stmt_text) and not _NON_SEC_HASH.search(stmt_text):
            out.append(_mk("CRYPTO-001", "Insecure Cryptography", rel_path, node.start_point[0] + 1, stmt_text[:200], "medium"))
    return out


def find_crypto_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if not fn:
            continue
        fn_text = _text(source, fn)
        if not (fn_text.endswith("createHash") or fn_text == "createHash"):
            continue
        call_text = _text(source, node)
        if not re.search(r"createHash\s*\(\s*['\"](md5|sha1)['\"]\s*\)", call_text, re.IGNORECASE):
            continue
        stmt = node.parent
        while stmt is not None and stmt.type not in ("expression_statement", "variable_declaration", "lexical_declaration", "return_statement"):
            stmt = stmt.parent
        stmt_text = _text(source, stmt) if stmt else call_text
        if _SEC_HASH_TARGET.search(stmt_text) and not _NON_SEC_HASH.search(stmt_text):
            out.append(_mk("CRYPTO-001", "Insecure Cryptography", rel_path, node.start_point[0] + 1, stmt_text[:200], "medium"))
    return out


# ---------------------------------------------------------------------------
# CRYPTO-002 (Python & JS/TS): Weak cipher or insecure cipher mode (DES/RC4/ECB).
# ---------------------------------------------------------------------------
_WEAK_CIPHER_RE = re.compile(r"(?i)\b(DES\.new|ARC4\.new|Blowfish\.new|algorithms\.ARC4|algorithms\.TripleDES|modes\.ECB|AES\.MODE_ECB)\b")
_WEAK_CIPHER_JS = re.compile(r"(?i)['\"](des(-ecb|-cbc)?|rc4|blowfish|aes-(128|192|256)-ecb)['\"]")


def find_crypto_002_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if not fn:
            continue
        text = _text(source, fn)
        if _WEAK_CIPHER_RE.search(text):
            out.append(_mk("CRYPTO-002", "Insecure Cryptography", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


def find_crypto_002_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn and (_text(source, fn).endswith("createCipheriv") or _text(source, fn).endswith("createCipher")):
                text = _text(source, node)
                if _WEAK_CIPHER_JS.search(text):
                    out.append(_mk("CRYPTO-002", "Insecure Cryptography", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# CRYPTO-003 (Python & JS/TS): Insecure pseudo-random generator for secrets.
# ---------------------------------------------------------------------------
_RANDOM_SEC_VAR = re.compile(r"(?i)(token|session|secret|password|auth_key|authKey|api_key|apiKey|reset_code|resetCode|nonce)")
_RANDOM_BENIGN = re.compile(r"(?i)(dice|roll|game|shuffle|card|sample|color|item|element|test)")


def find_crypto_003_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "assignment":
            continue
        left = node.child_by_field_name("left")
        right = node.child_by_field_name("right")
        if not left or not right:
            continue
        left_text = _text(source, left)
        right_text = _text(source, right)
        if _RANDOM_SEC_VAR.search(left_text) and not _RANDOM_BENIGN.search(left_text):
            if re.search(r"\brandom\.(random|randint|choice|sample|randrange)\b", right_text):
                out.append(_mk("CRYPTO-003", "Insecure Cryptography", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


def find_crypto_003_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type in ("variable_declarator", "assignment_expression"):
            left = node.child_by_field_name("name") or node.child_by_field_name("left")
            right = node.child_by_field_name("value") or node.child_by_field_name("right")
            if not left or not right:
                continue
            left_text = _text(source, left)
            right_text = _text(source, right)
            if _RANDOM_SEC_VAR.search(left_text) and not _RANDOM_BENIGN.search(left_text):
                if "Math.random()" in right_text:
                    out.append(_mk("CRYPTO-003", "Insecure Cryptography", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# JWT-001 (Python & JS/TS): JWT verification disabled or alg 'none'.
# ---------------------------------------------------------------------------
def find_jwt_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        call_text = _text(source, node)
        if "jwt.decode" in call_text:
            if re.search(r"verify\s*=\s*False\b", call_text) or re.search(r"verify_signature['\"]\s*:\s*False\b", call_text) or re.search(r"algorithms\s*=\s*\[['\"]none['\"]\]", call_text, re.IGNORECASE):
                out.append(_mk("JWT-001", "Insecure Authentication", rel_path, node.start_point[0] + 1, call_text[:200], "high"))
    return out


def find_jwt_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if not fn:
            continue
        fn_text = _text(source, fn)
        if not (fn_text == "jwt.verify" or fn_text.endswith(".verify") or fn_text == "jwt.decode" or fn_text.endswith(".decode")):
            continue
        call_text = _text(source, node)
        if re.search(r"algorithms\s*:\s*\[\s*['\"]none['\"]\s*\]", call_text, re.IGNORECASE):
            out.append(_mk("JWT-001", "Insecure Authentication", rel_path, node.start_point[0] + 1, call_text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# CONFIG-001 (Python & JS/TS): Debug mode enabled in production code.
# ---------------------------------------------------------------------------
def _is_inside_main_guard(node, source: bytes) -> bool:
    curr = node.parent
    while curr is not None:
        if curr.type == "if_statement":
            cond = curr.child_by_field_name("condition")
            if cond and "__main__" in _text(source, cond):
                return True
        curr = curr.parent
    return False


def find_config_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call":
            text = _text(source, node)
            if re.search(r"\bapp\.run\s*\(.*debug\s*=\s*True", text):
                if _is_inside_main_guard(node, source):
                    continue
                out.append(_mk("CONFIG-001", "Security Misconfiguration", rel_path, node.start_point[0] + 1, text[:200], "high"))
        elif node.type == "assignment":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left and right:
                left_text = _text(source, left).strip()
                right_text = _text(source, right).strip()
                if (left_text == "DEBUG" or "config['DEBUG']" in left_text or 'config["DEBUG"]' in left_text) and right_text == "True":
                    out.append(_mk("CONFIG-001", "Security Misconfiguration", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


def find_config_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            text = _text(source, node)
            if re.search(r"app\.set\s*\(\s*['\"]env['\"]\s*,\s*['\"]development['\"]\s*\)", text):
                out.append(_mk("CONFIG-001", "Security Misconfiguration", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# CONFIG-002 (Python & JS/TS): Insecure cookie/session flags.
# ---------------------------------------------------------------------------
def find_config_002_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if not fn or not _text(source, fn).endswith("set_cookie"):
            continue
        text = _text(source, node)
        has_secure = "secure=True" in text
        has_httponly = "httponly=True" in text
        if not (has_secure and has_httponly):
            out.append(_mk("CONFIG-002", "Broken Authentication", rel_path, node.start_point[0] + 1, text[:200], "medium"))
    return out


def find_config_002_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if not fn or not _text(source, fn).endswith("cookie"):
            continue
        text = _text(source, node)
        has_secure = re.search(r"secure\s*:\s*true\b", text, re.IGNORECASE)
        has_httponly = re.search(r"httpOnly\s*:\s*true\b", text, re.IGNORECASE)
        if not (has_secure and has_httponly):
            out.append(_mk("CONFIG-002", "Broken Authentication", rel_path, node.start_point[0] + 1, text[:200], "medium"))
    return out


# ---------------------------------------------------------------------------
# XXE-001 (Python & JS/TS): Unsafe XML parsing with entity expansion.
# ---------------------------------------------------------------------------
_XML_UNSAFE_CALLS = re.compile(r"\b((lxml\.)?(etree|ElementTree|ET|minidom|sax)\.(parse|fromstring|parseString))\b")


def find_xxe_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    source_str = source.decode("utf-8", errors="replace")
    if "defusedxml" in source_str:
        return []
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        text = _text(source, node)
        if _XML_UNSAFE_CALLS.search(text):
            out.append(_mk("XXE-001", "XML External Entity", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


def find_xxe_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        if not fn or not (_text(source, fn).endswith("parseXml") or _text(source, fn) == "parseXml"):
            continue
        text = _text(source, node)
        if re.search(r"noent\s*:\s*true\b", text, re.IGNORECASE):
            out.append(_mk("XXE-001", "XML External Entity", rel_path, node.start_point[0] + 1, text[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# SSTI-001 (Python & JS/TS): Server-side template injection via tainted templates.
# ---------------------------------------------------------------------------
def find_ssti_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if not fn or not args:
            continue
        fn_text = _text(source, fn)
        called = fn_text.rsplit(".", 1)[-1]
        if called in ("Template", "from_string"):
            named = args.named_children
            if named:
                first = named[0]
                if first.type != "string":
                    out.append(_mk("SSTI-001", "Server-Side Template Injection", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


def find_ssti_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call_expression":
            continue
        fn = node.child_by_field_name("function")
        args = node.child_by_field_name("arguments")
        if not fn or not args:
            continue
        fn_text = _text(source, fn)
        if fn_text in ("ejs.render", "pug.compile", "pug.render"):
            named = args.named_children
            if named:
                first = named[0]
                if first.type != "string":
                    out.append(_mk("SSTI-001", "Server-Side Template Injection", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


# ---------------------------------------------------------------------------
# ZIPSLIP-001 (Python & JS/TS): Unsafe archive extraction without path check.
# ---------------------------------------------------------------------------
def find_zipslip_001_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type != "call":
            continue
        fn = node.child_by_field_name("function")
        if not fn or not _text(source, fn).endswith("extractall"):
            continue
        scope = node.parent
        while scope is not None and scope.type != "function_definition":
            scope = scope.parent
        scope_text = _text(source, scope) if scope else ""
        if "commonpath" in scope_text or "startswith" in scope_text or "is_safe_path" in scope_text:
            continue
        out.append(_mk("ZIPSLIP-001", "Path Traversal", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out


def find_zipslip_001_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    out = []
    for node in _walk(tree.root_node):
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            if fn and _text(source, fn).endswith("extractAllTo"):
                scope = node.parent
                while scope is not None and scope.type not in ("function_declaration", "arrow_function", "method_definition"):
                    scope = scope.parent
                scope_text = _text(source, scope) if scope else ""
                if "indexOf('..')" in scope_text or "startsWith" in scope_text or "includes('..')" in scope_text:
                    continue
                out.append(_mk("ZIPSLIP-001", "Path Traversal", rel_path, node.start_point[0] + 1, _text(source, node)[:200], "high"))
    return out
