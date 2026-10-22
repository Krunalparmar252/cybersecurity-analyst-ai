"""
Unit tests for the fix-confidence tiering system (Module 3 confidence.py).
Verifies that all three tiers (verified_full, verified_narrow, unverified)
and diff_scope_check behave as expected under all conditions.
"""

import pytest
from analyst.reasoning.confidence import (
    PatchConfidence,
    diff_scope_check,
    evaluate_patch_confidence,
)

SAMPLE_PYTHON_SOURCE = """def process_user_data(user_input: str) -> str:
    # Function scope start
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    return query

def calculate_total(a: int, b: int) -> int:
    return a + b
"""

VALID_IN_SCOPE_DIFF = """--- a/app.py
+++ b/app.py
@@ -1,5 +1,5 @@
 def process_user_data(user_input: str) -> str:
-    query = f"SELECT * FROM users WHERE name = '{user_input}'"
+    query = "SELECT * FROM users WHERE name = %s"
     return query
"""

OUT_OF_SCOPE_DIFF = """--- a/app.py
+++ b/app.py
@@ -6,7 +6,7 @@
 def calculate_total(a: int, b: int) -> int:
-    return a + b
+    return a * b
"""


def test_patch_confidence_dataclass_fields():
    conf = PatchConfidence(
        tier="verified_full",
        syntax_ok=True,
        redetection_clean=True,
        tests_run=True,
        tests_passed=True,
        diff_in_scope=True,
        reason="Test reason",
    )
    d = conf.to_dict()
    assert d["tier"] == "verified_full"
    assert d["syntax_ok"] is True
    assert d["redetection_clean"] is True
    assert d["tests_run"] is True
    assert d["tests_passed"] is True
    assert d["diff_in_scope"] is True
    assert d["reason"] == "Test reason"


def test_diff_scope_check_in_scope():
    in_scope, reason = diff_scope_check(
        original_source=SAMPLE_PYTHON_SOURCE,
        diff_text=VALID_IN_SCOPE_DIFF,
        finding_line=3,
    )
    assert in_scope is True
    assert "scope" in reason.lower()


def test_diff_scope_check_out_of_scope():
    in_scope, reason = diff_scope_check(
        original_source=SAMPLE_PYTHON_SOURCE,
        diff_text=OUT_OF_SCOPE_DIFF,
        finding_line=3,  # finding is on line 3, but diff modifies calculate_total on line 7
    )
    assert in_scope is False
    assert "outside" in reason.lower()


def test_tier_verified_full():
    patched_source = SAMPLE_PYTHON_SOURCE.replace(
        'query = f"SELECT * FROM users WHERE name = \'{user_input}\'"',
        'query = "SELECT * FROM users WHERE name = %s"',
    )
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=patched_source,
        diff_text=VALID_IN_SCOPE_DIFF,
        finding_line=3,
        rule_still_fires=False,
        patch_applied=True,
        tests_run=True,
        tests_passed=True,
        file_path="app.py",
    )
    assert conf.tier == "verified_full"
    assert conf.syntax_ok is True
    assert conf.redetection_clean is True
    assert conf.tests_run is True
    assert conf.tests_passed is True
    assert conf.diff_in_scope is True


def test_tier_verified_narrow():
    patched_source = SAMPLE_PYTHON_SOURCE.replace(
        'query = f"SELECT * FROM users WHERE name = \'{user_input}\'"',
        'query = "SELECT * FROM users WHERE name = %s"',
    )
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=patched_source,
        diff_text=VALID_IN_SCOPE_DIFF,
        finding_line=3,
        rule_still_fires=False,
        patch_applied=True,
        tests_run=False,  # No unit test suite executed
        tests_passed=False,
        file_path="app.py",
    )
    assert conf.tier == "verified_narrow"
    assert conf.syntax_ok is True
    assert conf.redetection_clean is True
    assert conf.tests_run is False
    assert conf.diff_in_scope is True


def test_tier_unverified_due_to_syntax_error():
    bad_syntax_source = """def process_user_data(user_input: str) -> str:
    query = (invalid python syntax here
"""
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=bad_syntax_source,
        diff_text=VALID_IN_SCOPE_DIFF,
        finding_line=3,
        rule_still_fires=False,
        patch_applied=True,
        file_path="app.py",
    )
    assert conf.tier == "unverified"
    assert conf.syntax_ok is False


def test_tier_unverified_due_to_redetection_still_firing():
    patched_source = SAMPLE_PYTHON_SOURCE
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=patched_source,
        diff_text=VALID_IN_SCOPE_DIFF,
        finding_line=3,
        rule_still_fires=True,  # Vulnerability rule still fires
        patch_applied=True,
        file_path="app.py",
    )
    assert conf.tier == "unverified"
    assert conf.redetection_clean is False


def test_tier_unverified_due_to_out_of_scope():
    patched_source = SAMPLE_PYTHON_SOURCE.replace("return a + b", "return a * b")
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=patched_source,
        diff_text=OUT_OF_SCOPE_DIFF,
        finding_line=3,
        rule_still_fires=False,
        patch_applied=True,
        file_path="app.py",
    )
    assert conf.tier == "unverified"
    assert conf.diff_in_scope is False


def test_tier_unverified_due_to_unapplied_patch():
    conf = evaluate_patch_confidence(
        original_source=SAMPLE_PYTHON_SOURCE,
        patched_source=None,
        diff_text=None,
        finding_line=3,
        rule_still_fires=True,
        patch_applied=False,
        file_path="app.py",
    )
    assert conf.tier == "unverified"
    assert conf.syntax_ok is False
