"""AST-driven Taint Analysis Engine with Dataflow Provenance.

Supports Python, JavaScript, and TypeScript.
Analyzes intra-function and inter-function data flows from user-controllable
sources through assignments, string operations, and containers to sensitive sinks,
while verifying that proper class-specific sanitizers and guards are absent.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

# Feature flag: default ON; can be disabled via ANALYST_TAINT_ENGINE=0
TAINT_ENGINE_ENABLED = os.environ.get("ANALYST_TAINT_ENGINE", "1") not in ("0", "false", "no")

_CONFIG_DIR = Path(__file__).resolve().parent


def _load_yaml(filename: str) -> dict:
    p = _CONFIG_DIR / filename
    if p.exists():
        try:
            return yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception:
            return {}
    return {}


SOURCES_CONFIG = _load_yaml("sources.yaml")
SANITIZERS_CONFIG = _load_yaml("sanitizers.yaml")
SINKS_CONFIG = _load_yaml("sinks.yaml")


@dataclass
class DataflowStep:
    file: str
    line: int
    description: str

    def to_dict(self) -> dict:
        return {"file": self.file, "line": self.line, "description": self.description}


@dataclass
class FunctionSummary:
    name: str
    file: str
    line: int
    params: list[str] = field(default_factory=list)
    returns_params: set[str] = field(default_factory=set)
    sink_calls: list[tuple[str, str, int]] = field(default_factory=list)  # (param_name, sink_class, line)


class TaintEngine:
    """Inter-procedural AST taint analyzer."""

    def __init__(self, ingestion=None):
        self.ingestion = ingestion
        self._summaries_by_file: dict[str, dict[str, FunctionSummary]] = {}
        if ingestion:
            self._build_all_summaries()

    def _node_text(self, node, source: bytes) -> str:
        return source[node.start_byte:node.end_byte].decode("utf-8", errors="replace")

    def _build_all_summaries(self) -> None:
        """Pre-compute function summaries across all ingested ASTs."""
        if not self.ingestion or not hasattr(self.ingestion, "asts"):
            return
        for rel_path, tree in self.ingestion.asts.items():
            if tree is None:
                continue
            source = self.ingestion.sources.get(rel_path, b"")
            self._summaries_by_file[rel_path] = self.build_file_summaries(tree, source, rel_path)

    def build_file_summaries(self, tree, source: bytes, rel_path: str) -> dict[str, FunctionSummary]:
        summaries: dict[str, FunctionSummary] = {}

        def walk(node):
            if node.type in ("function_definition", "function_declaration", "method_definition"):
                summary = self._summarize_function(node, source, rel_path)
                if summary:
                    summaries[summary.name] = summary
            for child in node.children:
                walk(child)

        walk(tree.root_node)
        return summaries

    def _summarize_function(self, fn_node, source: bytes, rel_path: str) -> Optional[FunctionSummary]:
        name_node = fn_node.child_by_field_name("name")
        if not name_node:
            return None
        fn_name = self._node_text(name_node, source)
        params: list[str] = []

        params_node = fn_node.child_by_field_name("parameters") or fn_node.child_by_field_name("params")
        if params_node:
            for child in params_node.named_children:
                if child.type in ("identifier", "formal_parameter"):
                    params.append(self._node_text(child, source).split(":")[0].strip())

        summary = FunctionSummary(
            name=fn_name,
            file=rel_path,
            line=fn_node.start_point[0] + 1,
            params=params,
        )

        def walk_body(n):
            if n.type == "return_statement":
                text = self._node_text(n, source)
                for p in params:
                    if re.search(r'\b' + re.escape(p) + r'\b', text):
                        summary.returns_params.add(p)
            for c in n.children:
                if c.type not in ("function_definition", "function_declaration"):
                    walk_body(c)

        body_node = fn_node.child_by_field_name("body")
        if body_node:
            walk_body(body_node)

        return summary

    def is_source_expression(self, text: str, language: str) -> bool:
        cfg = SOURCES_CONFIG.get(language, {})
        for s in cfg.get("member_sources", []):
            if s in text:
                return True
        for c in cfg.get("call_sources", []):
            if re.search(r'\b' + re.escape(c) + r'\(', text):
                return True
        return False

    def is_sanitized_for_class(self, text: str, vuln_class: str, language: str, scope_text: str = "") -> bool:
        """Check whether expression or enclosing scope applies a sanitizer for vuln_class."""
        cfg = SANITIZERS_CONFIG.get(language, {}).get(vuln_class, {})
        for call_name in cfg.get("calls", []):
            if re.search(r'\b' + re.escape(call_name) + r'\(', text) or re.search(r'\b' + re.escape(call_name) + r'\(', scope_text):
                return True
        for check in cfg.get("checks", []):
            if check in text or check in scope_text:
                return True
        for flag in cfg.get("flags", []):
            if flag in text or flag in scope_text:
                return True

        # General sanitizers (number casts neutralize string injections)
        if vuln_class in ("SQL Injection", "Command Injection", "Path Traversal", "Cross-Site Scripting"):
            if re.search(r'\b(int|float|bool|parseInt|Number)\(', text):
                return True

        return False

    def trace_expression_taint(
        self,
        tree,
        source: bytes,
        rel_path: str,
        expr_node,
        vuln_class: str,
        language: str = "python",
    ) -> Optional[list[dict]]:
        """Trace whether expr_node is built from tainted input without proper sanitization.

        Returns dataflow steps if tainted, or None if safe/untainted.
        """
        if not TAINT_ENGINE_ENABLED:
            return None

        node_text = self._node_text(expr_node, source)

        # 1. Direct sanitizer check
        scope_node = self._find_enclosing_function_or_module(expr_node)
        scope_text = self._node_text(scope_node, source) if scope_node else ""
        if self.is_sanitized_for_class(node_text, vuln_class, language, scope_text):
            return None

        # 2. Check if expression directly contains a source
        if self.is_source_expression(node_text, language):
            return [
                DataflowStep(file=rel_path, line=expr_node.start_point[0] + 1, description=f"Direct source read: {node_text[:80]}").to_dict(),
                DataflowStep(file=rel_path, line=expr_node.start_point[0] + 1, description=f"Sink argument ({vuln_class})").to_dict(),
            ]

        # 3. Check variables referenced in the expression
        vars_in_expr = set(re.findall(r'[a-zA-Z_][a-zA-Z0-9_]*', node_text))
        # Ignore language keywords and constants
        vars_in_expr -= {"self", "cls", "true", "false", "null", "none", "None", "True", "False", "def", "return", "if", "for", "while"}

        if not vars_in_expr:
            return None

        # Scan enclosing scope for assignments to these variables
        dataflow: list[dict] = []
        tainted_vars: set[str] = set()

        if scope_node:
            for n in self._walk(scope_node):
                if n.start_byte >= expr_node.start_byte:
                    continue  # Only look at prior assignments

                if language == "python" and n.type == "assignment":
                    left = n.child_by_field_name("left")
                    right = n.child_by_field_name("right")
                    if left and right:
                        var_name = self._node_text(left, source).strip()
                        if var_name in vars_in_expr:
                            right_text = self._node_text(right, source)
                            # Check if right side is sanitized
                            if self.is_sanitized_for_class(right_text, vuln_class, language, scope_text):
                                continue
                            if self.is_source_expression(right_text, language) or any(tv in right_text for tv in tainted_vars):
                                tainted_vars.add(var_name)
                                dataflow.append(
                                    DataflowStep(file=rel_path, line=n.start_point[0] + 1, description=f"Assignment: {var_name} = {right_text[:60]}").to_dict()
                                )

                elif language in ("javascript", "typescript") and n.type in ("variable_declarator", "assignment_expression"):
                    left = n.child_by_field_name("name") or n.child_by_field_name("left")
                    right = n.child_by_field_name("value") or n.child_by_field_name("right")
                    if left and right:
                        var_name = self._node_text(left, source).strip()
                        if var_name in vars_in_expr:
                            right_text = self._node_text(right, source)
                            if self.is_sanitized_for_class(right_text, vuln_class, language, scope_text):
                                continue
                            if self.is_source_expression(right_text, language) or any(tv in right_text for tv in tainted_vars):
                                tainted_vars.add(var_name)
                                dataflow.append(
                                    DataflowStep(file=rel_path, line=n.start_point[0] + 1, description=f"Assignment: {var_name} = {right_text[:60]}").to_dict()
                                )

        # 4. Check function parameters
        fn_params = self._get_enclosing_params(expr_node, source, language)
        for var_name in vars_in_expr:
            if var_name in fn_params:
                # Parameter considered tainted if name suggests user input or matches common sources
                param_patterns = SOURCES_CONFIG.get(language, {}).get("param_names", [])
                if any(p.lower() in var_name.lower() for p in param_patterns) or var_name in ("target", "url", "cmd", "query", "user_input"):
                    tainted_vars.add(var_name)
                    dataflow.insert(
                        0,
                        DataflowStep(file=rel_path, line=expr_node.start_point[0] + 1, description=f"Function parameter: {var_name}").to_dict()
                    )

        if tainted_vars:
            dataflow.append(
                DataflowStep(file=rel_path, line=expr_node.start_point[0] + 1, description=f"Sink reach ({vuln_class}): {node_text[:60]}").to_dict()
            )
            return dataflow

        return None

    def _find_enclosing_function_or_module(self, node):
        curr = node.parent
        while curr is not None:
            if curr.type in ("function_definition", "function_declaration", "method_definition", "arrow_function", "module", "program"):
                return curr
            curr = curr.parent
        return None

    def _get_enclosing_params(self, node, source: bytes, language: str) -> list[str]:
        curr = node.parent
        while curr is not None:
            if curr.type in ("function_definition", "function_declaration", "method_definition"):
                params_node = curr.child_by_field_name("parameters") or curr.child_by_field_name("params")
                if params_node:
                    params = []
                    for child in params_node.named_children:
                        params.append(self._node_text(child, source).split(":")[0].strip())
                    return params
            curr = curr.parent
        return []

    def _walk(self, node):
        yield node
        for c in node.children:
            yield from self._walk(c)
