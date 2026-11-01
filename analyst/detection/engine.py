"""
Detection Layer — static rule + secrets engine.

Scope for Mid-1 (see DOc/phases.md Phase 2): only the 3 rule families that
demo_app/ground_truth.json actually exercises. The other rule families in
rules.md (AUTH, DESER, SSRF, CONFIG) are documented but intentionally not
implemented yet — building detectors with no test fixture to validate
against isn't useful this week.

Every finding traces back to a rule_id from DOc/rules.md, per the
"auditability" principle in architecture.md §7.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, asdict
from typing import Optional

from analyst.common.parallel import parallel_chunks
from analyst.common.types import CandidateFinding  # noqa: F401  (re-export)
from analyst.detection import rules_extra
from analyst.ingestion.manifest import IngestionResult


# ---------------------------------------------------------------------------
# SQLI-001: string-built query (f-string / concatenation / %-format) passed
# directly to cursor.execute() / .query() / .raw()
# ---------------------------------------------------------------------------
_EXECUTE_CALL_NAMES = {"execute", "executemany", "raw", "query"}


def _looks_tainted_expr(text: str) -> bool:
    """Heuristic for 'this string expression is built from a variable', not a
    constant. Parameter placeholders like %s, %d, ?, $1 are safe database drivers parameters,
    not string formatting injection vectors."""
    # Strip safe SQL driver parameter placeholders (%s, %d, %f, ?, $1, $2) before checking
    cleaned = re.sub(r'%\s*[sdfb]', '', text)
    cleaned = re.sub(r'\$\d+|\?', '', cleaned)

    return bool(
        re.search(r'f["\']', text)
        or ('"' in text and "+" in text)
        or ("'" in text and "+" in text)
        or ("%" in cleaned and ("SELECT" in cleaned.upper() or "INSERT" in cleaned.upper() or "UPDATE" in cleaned.upper() or "DELETE" in cleaned.upper()))
    )


def _find_sqli_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def find_function_ancestor(node):
        """Walk up to the nearest enclosing function_definition, so we only
        resolve variables within the same function scope (avoids false
        cross-function matches)."""
        current = node.parent
        while current is not None and current.type != "function_definition":
            current = current.parent
        return current

    def variable_is_tainted_in_scope(var_name: str, call_node) -> Optional[tuple[str, int]]:
        """Look for `var_name = <expr>` assignments earlier in the same
        function body and check if the assigned expression looks tainted.
        Returns (matched_text, line_number) if found, else None."""
        scope = find_function_ancestor(call_node)
        if scope is None:
            return None

        result = None

        def walk_scope(node):
            nonlocal result
            if node.type == "assignment":
                left = node.child_by_field_name("left")
                right = node.child_by_field_name("right")
                if left is not None and right is not None:
                    if node_text(left) == var_name:
                        right_text = node_text(right)
                        if _looks_tainted_expr(right_text):
                            result = (f"{var_name} = {right_text}", node.start_point[0] + 1)
            for child in node.children:
                walk_scope(child)

        walk_scope(scope)
        return result

    def walk(node):
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = node_text(func_node)
                # match `cursor.execute(...)`, `conn.execute(...)`, `.raw(...)`, etc.
                called_name = func_text.rsplit(".", 1)[-1]
                if called_name in _EXECUTE_CALL_NAMES:
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        arg_text = node_text(args_node)
                        matched_snippet = node_text(node)

                        # Case 1: tainted expression built inline in the call itself
                        if _looks_tainted_expr(arg_text):
                            findings.append(
                                CandidateFinding(
                                    rule_id="SQLI-001",
                                    vuln_class="SQL Injection",
                                    file=rel_path,
                                    line=node.start_point[0] + 1,
                                    snippet=matched_snippet[:200],
                                    confidence="high",
                                    source_scanner="static",
                                )
                            )
                        else:
                            # Case 2: plain variable passed in — check whether
                            # that variable was assigned from a tainted
                            # expression earlier in the same function.
                            var_name = arg_text.strip("()").strip()
                            if var_name.isidentifier():
                                tainted = variable_is_tainted_in_scope(var_name, node)
                                if tainted:
                                    assignment_text, assignment_line = tainted
                                    # Report at the taint-source line (where the
                                    # tainted string is built), not the call
                                    # site — more actionable for a developer.
                                    findings.append(
                                        CandidateFinding(
                                            rule_id="SQLI-001",
                                            vuln_class="SQL Injection",
                                            file=rel_path,
                                            line=assignment_line,
                                            snippet=assignment_text[:200],
                                            confidence="high",
                                            source_scanner="static",
                                        )
                                    )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


# ---------------------------------------------------------------------------
# XSS-002: direct interpolation of a variable into an HTML-returning string
# (heuristic: f-string containing an HTML tag, returned from a Flask route)
# ---------------------------------------------------------------------------
def _find_xss_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def walk(node):
        if node.type == "return_statement":
            text = node_text(node)
            # f-string with an HTML tag AND a variable interpolation -> candidate
            if re.search(r'f["\'].*<\w+.*\{[^}]+\}.*["\']', text, re.DOTALL):
                findings.append(
                    CandidateFinding(
                        rule_id="XSS-002",
                        vuln_class="Cross-Site Scripting",
                        file=rel_path,
                        line=node.start_point[0] + 1,
                        snippet=text[:200],
                        confidence="high",
                        source_scanner="static",
                    )
                )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


# ---------------------------------------------------------------------------
# CMDINJ-001: Command Injection (os.system, subprocess.Popen/run with shell=True)
# PATHTRAV-001: Path Traversal (open / send_file with raw string concat or f-string)
# DESER-001: Unsafe Deserialization (pickle.loads, yaml.load without SafeLoader)
# ---------------------------------------------------------------------------
_CMD_EXEC_CALLS = {"system", "popen", "exec", "eval"}
_PATH_TRAV_CALLS = {"open", "send_file", "send_from_directory"}
_DESER_CALLS = {"pickle.loads", "yaml.load"}


def _find_more_vulnerabilities_python(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def walk(node):
        if node.type == "call":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = node_text(func_node)
                called_name = func_text.rsplit(".", 1)[-1]
                matched_snippet = node_text(node)

                # CMDINJ-001
                if called_name in _CMD_EXEC_CALLS or ("subprocess" in func_text and ("shell=True" in matched_snippet or "system" in func_text)):
                    if _looks_tainted_expr(matched_snippet):
                        findings.append(
                            CandidateFinding(
                                rule_id="CMDINJ-001",
                                vuln_class="Command Injection",
                                file=rel_path,
                                line=node.start_point[0] + 1,
                                snippet=matched_snippet[:200],
                                confidence="high",
                                source_scanner="static",
                            )
                        )

                # PATHTRAV-001
                if called_name in _PATH_TRAV_CALLS:
                    if _looks_tainted_expr(matched_snippet):
                        findings.append(
                            CandidateFinding(
                                rule_id="PATHTRAV-001",
                                vuln_class="Path Traversal",
                                file=rel_path,
                                line=node.start_point[0] + 1,
                                snippet=matched_snippet[:200],
                                confidence="high",
                                source_scanner="static",
                            )
                        )

                # DESER-001
                if "pickle.loads" in func_text or ("yaml.load" in func_text and "Loader=SafeLoader" not in matched_snippet and "Loader=CSafeLoader" not in matched_snippet):
                    findings.append(
                        CandidateFinding(
                            rule_id="DESER-001",
                            vuln_class="Unsafe Deserialization",
                            file=rel_path,
                            line=node.start_point[0] + 1,
                            snippet=matched_snippet[:200],
                            confidence="high",
                            source_scanner="static",
                        )
                    )

        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


# ---------------------------------------------------------------------------
# JavaScript equivalents of SQLI-001 / XSS-002.
#
# Node-type mapping vs. the Python rules above (verified against
# tree_sitter_languages 'javascript' grammar):
#   Python              JavaScript
#   call                call_expression
#   attribute (field)   member_expression (field: "function")
#   assignment           variable_declarator (inside lexical_declaration)
#   function_definition  function_declaration / arrow_function / function_expression
#   f-string             template_string (tainted if it contains a
#                         template_substitution, i.e. `${...}`)
#
# Same rule_ids, same _EXECUTE_CALL_NAMES / vuln classes as Python — this is
# the same taint heuristic (string built from a variable, not a constant)
# re-expressed for JS syntax, not a different rule.
# ---------------------------------------------------------------------------
# NOTE: tree-sitter's javascript grammar uses "function" (not
# "function_expression") for the anonymous `function (...) {...}` form —
# verified empirically, differs from the more commonly assumed node name.
_JS_FUNCTION_SCOPE_TYPES = {"function_declaration", "function_expression", "function", "arrow_function"}


def _js_looks_tainted_expr(node, node_text) -> bool:
    """JS taint heuristic: a template literal with at least one ${...}
    substitution is 'built from a variable', same spirit as the Python
    f-string / concatenation check in _looks_tainted_expr()."""
    if node.type == "template_string":
        return any(c.type == "template_substitution" for c in node.children)
    if node.type == "binary_expression" and "+" in node_text(node):
        return True
    return False


def _find_sqli_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def find_function_ancestor(node):
        current = node.parent
        while current is not None and current.type not in _JS_FUNCTION_SCOPE_TYPES:
            current = current.parent
        return current

    def variable_is_tainted_in_scope(var_name: str, call_node) -> Optional[tuple[str, int]]:
        """Look for `const/let/var name = <expr>` earlier in the same
        enclosing function, mirroring the Python assignment-scan."""
        scope = find_function_ancestor(call_node)
        if scope is None:
            return None

        result = None

        def walk_scope(node):
            nonlocal result
            if node.type == "variable_declarator":
                name_node = node.child_by_field_name("name")
                value_node = node.child_by_field_name("value")
                if name_node is not None and value_node is not None:
                    if node_text(name_node) == var_name and _js_looks_tainted_expr(value_node, node_text):
                        result = (f"{var_name} = {node_text(value_node)}", node.start_point[0] + 1)
            for child in node.children:
                walk_scope(child)

        walk_scope(scope)
        return result

    def walk(node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                func_text = node_text(func_node)
                called_name = func_text.rsplit(".", 1)[-1]
                if called_name in _EXECUTE_CALL_NAMES:
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        matched_snippet = node_text(node)
                        # Case 1: tainted template literal built inline
                        first_arg = args_node.named_children[0] if args_node.named_children else None
                        if first_arg is not None and _js_looks_tainted_expr(first_arg, node_text):
                            findings.append(
                                CandidateFinding(
                                    rule_id="SQLI-001",
                                    vuln_class="SQL Injection",
                                    file=rel_path,
                                    line=node.start_point[0] + 1,
                                    snippet=matched_snippet[:200],
                                    confidence="high",
                                    source_scanner="static",
                                )
                            )
                        elif first_arg is not None and first_arg.type == "identifier":
                            # Case 2: plain variable — trace back to its declaration
                            var_name = node_text(first_arg)
                            tainted = variable_is_tainted_in_scope(var_name, node)
                            if tainted:
                                assignment_text, assignment_line = tainted
                                findings.append(
                                    CandidateFinding(
                                        rule_id="SQLI-001",
                                        vuln_class="SQL Injection",
                                        file=rel_path,
                                        line=assignment_line,
                                        snippet=assignment_text[:200],
                                        confidence="high",
                                        source_scanner="static",
                                    )
                                )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


# XSS-002 (JS): res.send(...) / res.write(...) — the Express analog of
# "return an HTML string built with a tainted f-string" — called with a
# template literal that both looks like HTML and interpolates a variable.
_HTML_RESPONSE_CALL_NAMES = {"send", "write"}


def _find_xss_javascript(tree, source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []

    def node_text(node) -> str:
        return source[node.start_byte : node.end_byte].decode("utf-8", errors="replace")

    def walk(node):
        if node.type == "call_expression":
            func_node = node.child_by_field_name("function")
            if func_node is not None:
                called_name = node_text(func_node).rsplit(".", 1)[-1]
                if called_name in _HTML_RESPONSE_CALL_NAMES:
                    args_node = node.child_by_field_name("arguments")
                    if args_node is not None:
                        text = node_text(args_node)
                        # HTML tag AND a ${...} interpolation -> candidate,
                        # same shape as the Python f-string/HTML-tag regex.
                        if re.search(r"<\w+.*\$\{[^}]+\}.*", text, re.DOTALL):
                            findings.append(
                                CandidateFinding(
                                    rule_id="XSS-002",
                                    vuln_class="Cross-Site Scripting",
                                    file=rel_path,
                                    line=node.start_point[0] + 1,
                                    snippet=node_text(node)[:200],
                                    confidence="high",
                                    source_scanner="static",
                                )
                            )
        for child in node.children:
            walk(child)

    walk(tree.root_node)
    return findings


# ---------------------------------------------------------------------------
# Secrets scanner — SECRET-005 (generic assignment pattern) via regex,
# applied to every ingested file regardless of parse success (per
# architecture.md §2.2.B: "runs independently over the full file index").
#
# Redaction is enforced here, at detection time, per rules.md's mandatory
# redaction rule — the raw value never leaves this function.
# ---------------------------------------------------------------------------
_SECRET_GENERIC_RE = re.compile(
    # Allow an optional TypeScript-style type annotation (`: string`) between
    # the name and `=` — e.g. `const apiKey: string = "..."`. Python/JS have
    # no equivalent syntax in assignment position, so this is purely additive
    # and doesn't change matching for those languages.
    r"""\w*(api[_-]?key|secret|password|token)\w*\s*(?::\s*\w+\s*)?=\s*['"]([^'"]{8,})['"]""",
    re.IGNORECASE,
)


def _redact(value: str) -> str:
    if len(value) <= 4:
        return "*" * len(value)
    return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}<len={len(value)}>"


def _find_secrets(source: bytes, rel_path: str) -> list[CandidateFinding]:
    findings: list[CandidateFinding] = []
    text = source.decode("utf-8", errors="replace")
    for lineno, line in enumerate(text.splitlines(), start=1):
        for match in _SECRET_GENERIC_RE.finditer(line):
            raw_value = match.group(2)
            # Reject f-string variable interpolation, e.g. password = '{password}'
            # — that's a template placeholder, not a literal secret value.
            # (This is the kind of case rules.md §3 flags as needing LLM
            # confirmation to filter out — we do a cheap syntactic filter
            # here so it never even reaches candidate_findings.json.)
            if re.fullmatch(r"\{[^{}]+\}", raw_value):
                continue
            redacted = _redact(raw_value)
            findings.append(
                CandidateFinding(
                    rule_id="SECRET-005",
                    vuln_class="Hardcoded Secrets",
                    file=rel_path,
                    line=lineno,
                    snippet=line.strip().replace(raw_value, redacted),
                    confidence="medium",
                    source_scanner="secrets",
                )
            )
    return findings


# Per-language AST rule matchers. Adding a language means adding an entry
# here (plus a LANGUAGE_BY_EXTENSION entry in manifest.py) — run_detection
# itself doesn't need to change.
_AST_RULES_BY_LANGUAGE = {
    "python": (
        _find_sqli_python, _find_xss_python, _find_more_vulnerabilities_python,
        rules_extra.find_sqli_002, rules_extra.find_auth_001, rules_extra.find_auth_002,
        rules_extra.find_xss_004, rules_extra.find_auth_003, rules_extra.find_auth_004,
        rules_extra.find_ssrf_001_python,
    ),
    "javascript": (
        _find_sqli_javascript, _find_xss_javascript,
        rules_extra.find_xss_001, rules_extra.find_deser_002,
        rules_extra.find_cmdinj_002, rules_extra.find_pathtrav_002,
        rules_extra.find_deser_003, rules_extra.find_auth_005, rules_extra.find_auth_006,
        rules_extra.find_auth_003_javascript, rules_extra.find_auth_004_javascript,
        rules_extra.find_ssrf_001_javascript,
    ),
    # TypeScript's tree-sitter grammar reuses the exact same node type names
    # for the constructs these rules key on (call_expression, member_expression,
    # variable_declarator, template_string/template_substitution) — type
    # annotations live in separate child nodes our field lookups never touch.
    # Verified empirically against synthetic TS snippets before wiring this in
    # (see conversation notes); no separate _typescript rule functions needed.
    "typescript": (
        _find_sqli_javascript, _find_xss_javascript,
        rules_extra.find_xss_001, rules_extra.find_deser_002,
        rules_extra.find_cmdinj_002, rules_extra.find_pathtrav_002,
        rules_extra.find_deser_003, rules_extra.find_auth_005, rules_extra.find_auth_006,
        rules_extra.find_auth_003_javascript, rules_extra.find_auth_004_javascript,
        rules_extra.find_ssrf_001_javascript,
    ),
}


def _detect_file(ingestion: IngestionResult, language_by_path: dict, rel_path: str) -> list[CandidateFinding]:
    source = ingestion.sources[rel_path]
    found = list(_find_secrets(source, rel_path))  # runs regardless of AST parse success
    found.extend(rules_extra.find_secrets_extra(source, rel_path))
    gitignore_bytes = ingestion.sources.get(".gitignore")
    gitignore_text = gitignore_bytes.decode("utf-8", errors="replace") if gitignore_bytes else None
    found.extend(rules_extra.find_secret_008(rel_path, gitignore_text))
    found.extend(rules_extra.find_xss_003(source, rel_path))  # template text: source-level
    tree = ingestion.asts.get(rel_path)
    if tree is not None:
        language = language_by_path.get(rel_path)
        for rule_fn in _AST_RULES_BY_LANGUAGE.get(language, ()):
            found.extend(rule_fn(tree, source, rel_path))
    return _prefer_specific(found)


# A generic rule is dropped when a more specific rule fires on the same line,
# so one defect is reported once (and counted once in the metrics).
_SUPERSEDED_BY = {
    "SQLI-001": {"SQLI-002"},
    "SECRET-005": {"SECRET-001", "SECRET-002", "SECRET-003", "SECRET-004", "SECRET-006"},
}


def _prefer_specific(found: list[CandidateFinding]) -> list[CandidateFinding]:
    at = {(f.file, f.line, f.rule_id) for f in found}
    return [
        f for f in found
        if not any((f.file, f.line, sp) in at for sp in _SUPERSEDED_BY.get(f.rule_id, ()))
    ]


def run_detection(ingestion: IngestionResult, workers: Optional[int] = None) -> list[CandidateFinding]:
    """Run all implemented rule matchers across every ingested file.

    Files are split into contiguous chunks scanned on a thread pool and merged
    in chunk order, so the result is identical to a sequential run (workers=1).
    """
    language_by_path = {f.path: f.language for f in ingestion.manifest.files}

    def _scan_chunk(chunk):
        return [f for rel in chunk for f in _detect_file(ingestion, language_by_path, rel)]

    return parallel_chunks(list(ingestion.sources), _scan_chunk, workers)
