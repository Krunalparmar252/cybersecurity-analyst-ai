"""
Confidence-tiering system for automated fix suggestions.
Provides PatchConfidence dataclass and evaluation functions to determine
fix verification tiers: verified_full, verified_narrow, unverified.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, asdict
from typing import Optional, Tuple


@dataclass
class PatchConfidence:
    tier: str  # "verified_full" | "verified_narrow" | "unverified"
    syntax_ok: bool
    redetection_clean: bool
    tests_run: bool
    tests_passed: bool
    diff_in_scope: bool
    reason: str

    def to_dict(self) -> dict:
        return asdict(self)


def _get_python_function_scope(source: str, line_no: int) -> Tuple[int, int]:
    """Find start and end line numbers (1-indexed) of the function or class
    enclosing line_no in Python code using ast parsing. Fallback to line window."""
    try:
        tree = ast.parse(source)
        enclosing_scopes = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                start = getattr(node, "lineno", 1)
                end = getattr(node, "end_lineno", start + 30)
                if start <= line_no <= end:
                    enclosing_scopes.append((start, end))

        if enclosing_scopes:
            enclosing_scopes.sort(key=lambda s: s[1] - s[0])
            return enclosing_scopes[0]
    except Exception:
        pass

    total_lines = len(source.splitlines())
    start = max(1, line_no - 15)
    end = min(total_lines, line_no + 15)
    return (start, end)


# An added top-level import is not "the patch wandered outside the vulnerable
# function" — it is the cost of using a safe API (escape(), os.environ). Holding
# a fix's new import to the flagged function's line range is nonsensical, and it
# was grading every otherwise-verified deterministic-fallback patch "unverified".
_IMPORT_LINE = re.compile(r"^\s*(import\s+\w|from\s+[\w\.]+\s+import\s)")


def diff_scope_check(
    original_source: str, diff_text: str, finding_line: int
) -> Tuple[bool, str]:
    """Confirms whether all changed/removed lines in a proposed unified diff
    fall within the function or class scope of the original flagged finding."""
    if not diff_text or not diff_text.strip():
        return False, "Diff text is empty."

    scope_start, scope_end = _get_python_function_scope(original_source, finding_line)
    lines = original_source.splitlines()
    scope_margin_end = scope_end + 1

    # Track exact line numbers of modified (-) lines within hunks
    diff_lines = diff_text.splitlines()
    curr_old_line = None

    has_modifications = False
    for line in diff_lines:
        if line.startswith("--- ") or line.startswith("+++ "):
            continue
        if line.startswith("@@"):
            match = re.search(r"@@ -(\d+)", line)
            if match:
                curr_old_line = int(match.group(1))
            continue

        if curr_old_line is not None:
            if line.startswith("-"):
                has_modifications = True
                if _IMPORT_LINE.match(line[1:]):
                    curr_old_line += 1  # import lines are scope-exempt, see above
                    continue
                if curr_old_line < scope_start or curr_old_line > scope_margin_end:
                    return (
                        False,
                        f"Diff modifies line {curr_old_line} which falls outside function scope ({scope_start}-{scope_end}).",
                    )
                curr_old_line += 1
            elif line.startswith("+"):
                has_modifications = True
            else:
                # Context line
                curr_old_line += 1

    # Fallback check if line numbers were not tracked
    if not has_modifications:
        removed_lines = [
            l[1:] for l in diff_lines if l.startswith("-") and not l.startswith("---")
        ]
        removed_lines = [l for l in removed_lines if not _IMPORT_LINE.match(l)]
        if removed_lines:
            scope_source = "\n".join(lines[max(0, scope_start - 1):scope_end])
            removed_block = "\n".join(removed_lines)
            if removed_block.strip() and removed_block not in scope_source:
                return (
                    False,
                    f"Diff modifications fall outside target scope lines ({scope_start}-{scope_end}).",
                )

    return True, f"All diff modifications fall within target scope ({scope_start}-{scope_end})."


def evaluate_patch_confidence(
    original_source: str,
    patched_source: Optional[str],
    diff_text: Optional[str],
    finding_line: int,
    rule_still_fires: bool,
    patch_applied: bool,
    tests_run: bool = False,
    tests_passed: bool = False,
    file_path: str = "",
) -> PatchConfidence:
    """Evaluate fix confidence and determine tier: verified_full, verified_narrow, or unverified."""

    if not patch_applied or patched_source is None or not diff_text:
        return PatchConfidence(
            tier="unverified",
            syntax_ok=False,
            redetection_clean=not rule_still_fires,
            tests_run=tests_run,
            tests_passed=tests_passed,
            diff_in_scope=False,
            reason="Patch failed to apply cleanly.",
        )

    # 1. Syntax Check
    syntax_ok = True
    syntax_reason = ""
    if file_path.endswith(".py") or not file_path:
        try:
            ast.parse(patched_source)
        except SyntaxError as exc:
            syntax_ok = False
            syntax_reason = f"Syntax error in patched Python code: {exc}"

    # 2. Re-detection Check
    redetection_clean = not rule_still_fires

    # 3. Scope Check
    diff_in_scope, scope_reason = diff_scope_check(
        original_source, diff_text, finding_line
    )

    # 4. Tier Determination
    if not syntax_ok:
        tier = "unverified"
        reason = syntax_reason
    elif not redetection_clean:
        tier = "unverified"
        reason = "Rule still fires after applying the patch."
    elif not diff_in_scope:
        tier = "unverified"
        reason = scope_reason
    elif tests_run and tests_passed:
        tier = "verified_full"
        reason = "Patch fully verified: syntax valid, re-detection clean, in scope, and all unit tests passed."
    else:
        tier = "verified_narrow"
        reason = f"Patch verified (narrow): syntax valid, re-detection clean, and in scope. {scope_reason}"

    return PatchConfidence(
        tier=tier,
        syntax_ok=syntax_ok,
        redetection_clean=redetection_clean,
        tests_run=tests_run,
        tests_passed=tests_passed,
        diff_in_scope=diff_in_scope,
        reason=reason,
    )
