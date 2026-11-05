"""Unit tests for the AST Taint Analysis Engine."""

from __future__ import annotations

import pytest
from tree_sitter_languages import get_language, get_parser

from analyst.detection.taint.engine import TaintEngine

PY_LANG = get_language("python")
PY_PARSER = get_parser("python")
JS_LANG = get_language("javascript")
JS_PARSER = get_parser("javascript")


def _parse_py(code: str):
    source = code.strip().encode("utf-8")
    return PY_PARSER.parse(source), source


def _parse_js(code: str):
    source = code.strip().encode("utf-8")
    return JS_PARSER.parse(source), source


def _find_sink_arg(root_node, source: bytes, sink_name: str):
    for node in _walk(root_node):
        if node.type in ("call", "call_expression"):
            fn = node.child_by_field_name("function")
            if fn:
                fn_text = source[fn.start_byte:fn.end_byte].decode("utf-8", errors="replace")
                if sink_name in fn_text:
                    args = node.child_by_field_name("arguments")
                    if args and args.named_children:
                        return args.named_children[0]
    return None


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def test_taint_source_to_sink_direct():
    code = """
def handler(request):
    user_input = request.args.get('target')
    cursor.execute(user_input)
"""
    tree, source = _parse_py(code)
    engine = TaintEngine()
    arg_node = _find_sink_arg(tree.root_node, source, "execute")
    assert arg_node is not None
    flow = engine.trace_expression_taint(tree, source, "test.py", arg_node, "SQL Injection", "python")
    assert flow is not None
    assert len(flow) >= 2
    assert any("user_input" in step["description"] for step in flow)


def test_taint_sanitizer_stops_flow():
    code = """
import html

def handler(request):
    user_input = request.args.get('name')
    safe_val = html.escape(user_input)
    render_template_string(safe_val)
"""
    tree, source = _parse_py(code)
    engine = TaintEngine()
    arg_node = _find_sink_arg(tree.root_node, source, "render_template_string")
    assert arg_node is not None
    flow = engine.trace_expression_taint(tree, source, "test.py", arg_node, "Cross-Site Scripting", "python")
    # Flow should be stopped by html.escape
    assert flow is None


def test_taint_cross_function_flow():
    code = """
def sanitize_or_pass(val):
    return val

def controller(request):
    raw_data = request.args.get('q')
    flowed = raw_data
    cursor.execute(f"SELECT * FROM users WHERE name = '{flowed}'")
"""
    tree, source = _parse_py(code)
    engine = TaintEngine()
    summaries = engine.build_file_summaries(tree, source, "test.py")
    assert "sanitize_or_pass" in summaries
    assert "val" in summaries["sanitize_or_pass"].returns_params

    arg_node = _find_sink_arg(tree.root_node, source, "execute")
    assert arg_node is not None
    flow = engine.trace_expression_taint(tree, source, "test.py", arg_node, "SQL Injection", "python")
    assert flow is not None
    assert any("flowed" in step["description"] or "raw_data" in step["description"] for step in flow)


def test_taint_fstring_propagation():
    code = """
def search(request):
    q = request.args.get('query')
    query = f"SELECT * FROM items WHERE id = {q}"
    db.execute(query)
"""
    tree, source = _parse_py(code)
    engine = TaintEngine()
    arg_node = _find_sink_arg(tree.root_node, source, "execute")
    assert arg_node is not None
    flow = engine.trace_expression_taint(tree, source, "test.py", arg_node, "SQL Injection", "python")
    assert flow is not None
    assert any("query" in step["description"] or "q" in step["description"] for step in flow)


def test_taint_javascript_propagation():
    code = """
app.get('/search', (req, res) => {
    const userInput = req.query.q;
    const query = "SELECT * FROM users WHERE name = " + userInput;
    db.query(query);
});
"""
    tree, source = _parse_js(code)
    engine = TaintEngine()
    arg_node = _find_sink_arg(tree.root_node, source, "query")
    assert arg_node is not None
    flow = engine.trace_expression_taint(tree, source, "test.js", arg_node, "SQL Injection", "javascript")
    assert flow is not None
    assert any("query" in step["description"] or "userInput" in step["description"] for step in flow)
