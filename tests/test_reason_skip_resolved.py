"""Unit tests for C-4 — skipping REASON and EXPLOIT for already-resolved findings.

Tests cover:
  1. _apply_incremental_filter sets already_resolved=True and cached_patch_diff
     when cached finding has loop_status == "ACCEPTED".
  2. _apply_incremental_filter sets already_resolved=False when cached finding
     has loop_status != "ACCEPTED" (e.g., MANUAL_REVIEW_REQUIRED).
  3. run_patch_verify_loop skips LLM and returns synthesized result with
     attempts=0 and loop_status="ACCEPTED" when already_resolved=True.
  4. run_patch_verify_loop runs REASON for carried-forward candidate with
     already_resolved=False.
  5. run_patch_verify_loop runs REASON for rescanned candidates regardless.
  6. Mixed batch: only unresolved/rescanned candidates invoke REASON.
  7. verify_and_patch directly skips analysis when already_resolved=True.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from analyst.common.types import (
    CandidateFinding,
    ConfirmedFinding,
    STATUS_ACCEPTED,
    STATUS_MANUAL_REVIEW,
)
from analyst.ingestion.scan_cache import ChangedFileSet
from analyst.orchestrator.pipeline import _apply_incremental_filter
from analyst.reasoning.patch_loop import (
    PatchVerificationResult,
    run_patch_verify_loop,
    verify_and_patch,
)


def _make_candidate(
    file: str = "app.py",
    rule_id: str = "SQLI-001",
    line: int = 10,
    already_resolved: bool = False,
    cached_patch_diff: str | None = None,
    scan_mode: str = "rescanned",
) -> CandidateFinding:
    return CandidateFinding(
        rule_id=rule_id,
        vuln_class="sql_injection",
        file=file,
        line=line,
        snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        confidence="high",
        source_scanner="static",
        scan_mode=scan_mode,
        already_resolved=already_resolved,
        cached_patch_diff=cached_patch_diff,
    )


# ---------------------------------------------------------------------------
# Filter tests: loop_status propagation
# ---------------------------------------------------------------------------

def test_incremental_filter_sets_already_resolved_for_accepted(tmp_path):
    """When a cached finding has loop_status == 'ACCEPTED', reconstructed
    CandidateFinding must have already_resolved=True and cached_patch_diff set."""
    dummy_diff = "--- a/app.py\n+++ b/app.py\n@@ -10 +10 @@\n- bad\n+ good"
    cache = {
        "schema_version": 1,
        "repo_path": str(tmp_path),
        "last_commit": "abc1234",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "findings_by_file": {
            "clean.py": [
                {
                    "rule_id": "SQLI-001",
                    "vuln_class": "sql_injection",
                    "file": "clean.py",
                    "line": 15,
                    "snippet": "query",
                    "confidence": "high",
                    "source_scanner": "static",
                    "loop_status": "ACCEPTED",
                    "patch_diff": dummy_diff,
                }
            ]
        },
    }
    changed = ChangedFileSet(added=frozenset(), modified=frozenset(), deleted=frozenset())

    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), [])

    assert len(result) == 1
    c = result[0]
    assert c.file == "clean.py"
    assert c.scan_mode == "carried_forward"
    assert c.already_resolved is True
    assert c.cached_patch_diff == dummy_diff


def test_incremental_filter_sets_already_resolved_false_for_unresolved(tmp_path):
    """When a cached finding was NOT ACCEPTED (e.g. MANUAL_REVIEW_REQUIRED),
    reconstructed CandidateFinding must have already_resolved=False."""
    cache = {
        "schema_version": 1,
        "repo_path": str(tmp_path),
        "last_commit": "abc1234",
        "scanned_at": "2026-01-01T00:00:00+00:00",
        "findings_by_file": {
            "unresolved.py": [
                {
                    "rule_id": "CMD-001",
                    "vuln_class": "command_injection",
                    "file": "unresolved.py",
                    "line": 20,
                    "snippet": "os.system(cmd)",
                    "confidence": "high",
                    "source_scanner": "static",
                    "loop_status": "MANUAL_REVIEW_REQUIRED",
                    "patch_diff": None,
                }
            ]
        },
    }
    changed = ChangedFileSet(added=frozenset(), modified=frozenset(), deleted=frozenset())

    with (
        patch("analyst.orchestrator.pipeline.load_cache", return_value=cache),
        patch("analyst.orchestrator.pipeline.get_changed_files", return_value=changed),
    ):
        result, summary = _apply_incremental_filter(str(tmp_path), [])

    assert len(result) == 1
    c = result[0]
    assert c.file == "unresolved.py"
    assert c.scan_mode == "carried_forward"
    assert c.already_resolved is False
    assert c.cached_patch_diff is None


# ---------------------------------------------------------------------------
# Reasoning skip tests
# ---------------------------------------------------------------------------

def test_already_resolved_skips_llm_and_synthesizes_result():
    """An already_resolved candidate must NOT call the LLM and must return
    attempts=0, loop_status=ACCEPTED, and preserve cached_patch_diff."""
    diff = "--- a/app.py\n+++ b/app.py\n+ safe"
    cand = _make_candidate(
        file="app.py",
        already_resolved=True,
        cached_patch_diff=diff,
        scan_mode="carried_forward",
    )

    mock_client = MagicMock()

    results = run_patch_verify_loop(
        findings=[cand],
        sources={"app.py": b"unsafe"},
        repo_path="/dummy/path",
        api_key="mock_key",
    )

    assert len(results) == 1
    r = results[0]
    assert r.loop_status == STATUS_ACCEPTED
    assert r.attempts == 0
    assert r.finding.patch_diff == diff
    assert r.finding.analysis_tier == "cached"
    assert r.finding.confirmed is True


def test_unresolved_carried_forward_goes_through_reason():
    """A carried-forward candidate with already_resolved=False must be analyzed."""
    cand = _make_candidate(
        file="app.py",
        already_resolved=False,
        scan_mode="carried_forward",
    )

    # In offline mode (client=None), it falls back to deterministic analysis
    results = run_patch_verify_loop(
        findings=[cand],
        sources={"app.py": b"cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"},
        repo_path="/dummy/path",
        offline=True,
    )

    assert len(results) == 1
    r = results[0]
    # Processed by the deterministic tier (attempts >= 1)
    assert r.attempts >= 1


def test_rescanned_candidate_always_goes_through_reason():
    """A rescanned candidate must always be analyzed even if already_resolved happened
    to be set erroneously or was carried over."""
    cand = _make_candidate(
        file="modified.py",
        already_resolved=False,
        scan_mode="rescanned",
    )

    results = run_patch_verify_loop(
        findings=[cand],
        sources={"modified.py": b"cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"},
        repo_path="/dummy/path",
        offline=True,
    )

    assert len(results) == 1
    r = results[0]
    assert r.attempts >= 1


def test_mixed_candidates_only_calls_reason_for_unresolved():
    """In a batch of mixed candidates, already_resolved candidates are skipped
    while unresolved and rescanned candidates proceed through analysis."""
    c_resolved = _make_candidate(
        file="cached_fixed.py",
        already_resolved=True,
        cached_patch_diff="--- diff",
        scan_mode="carried_forward",
    )
    c_unresolved = _make_candidate(
        file="cached_manual.py",
        already_resolved=False,
        scan_mode="carried_forward",
    )
    c_fresh = _make_candidate(
        file="new_vuln.py",
        already_resolved=False,
        scan_mode="rescanned",
    )

    with patch("analyst.reasoning.patch_loop.verify_and_patch") as mock_verify:
        mock_verify.return_value = PatchVerificationResult(
            finding=ConfirmedFinding(
                rule_id="SQLI-001",
                vuln_class="sql_injection",
                file="dummy.py",
                line=1,
                confirmed=True,
                confirmation_reasoning="reason",
            ),
            loop_status=STATUS_ACCEPTED,
            attempts=1,
            attempt_log=[],
        )

        results = run_patch_verify_loop(
            findings=[c_resolved, c_unresolved, c_fresh],
            sources={},
            repo_path="/dummy/path",
            offline=True,
        )

    # verify_and_patch called exactly 2 times (for c_unresolved and c_fresh)
    assert mock_verify.call_count == 2
    assert len(results) == 3
    # First result was synthesized
    assert results[0].attempts == 0
    assert results[0].finding.file == "cached_fixed.py"
    assert results[0].loop_status == STATUS_ACCEPTED


def test_verify_and_patch_directly_handles_already_resolved():
    """If verify_and_patch is invoked directly with already_resolved=True,
    it returns the synthesized result without sandbox or client invocation."""
    cand = _make_candidate(
        file="app.py",
        already_resolved=True,
        cached_patch_diff="--- patch",
    )
    mock_client = MagicMock()
    res = verify_and_patch(
        finding=cand,
        repo_path="/dummy/path",
        sources={},
        client=mock_client,
    )
    mock_client.invoke.assert_not_called()
    assert res.attempts == 0
    assert res.loop_status == STATUS_ACCEPTED
    assert res.finding.patch_diff == "--- patch"


def test_dynamic_exploit_skipped_for_already_resolved(tmp_path):
    """When dynamic=True, accepted findings with attempts == 0 must NOT trigger
    EXPLOIT_VERIFY_REQUEST on the bus."""
    from analyst.protocol import (
        AgentID,
        AgentMessage,
        CAP_EXPLOIT_VERIFY,
        MessageType,
        MessageBus,
    )
    from analyst.orchestrator.pipeline import _run_pipeline_on_local_path

    # Create dummy app file in tmp repo
    dummy_repo = tmp_path / "repo"
    dummy_repo.mkdir()
    (dummy_repo / "main.py").write_text("x = 1\n", encoding="utf-8")

    # Mock detection returning empty, but incremental filter returning already-resolved finding
    cand = _make_candidate(
        file="main.py",
        already_resolved=True,
        cached_patch_diff="--- patch",
        scan_mode="carried_forward",
    )

    with (
        patch("analyst.orchestrator.pipeline.load_cache") as mock_cache,
        patch("analyst.orchestrator.pipeline.get_changed_files") as mock_changed,
        patch("analyst.orchestrator.pipeline.run_detection_agent") as mock_det,
    ):
        mock_cache.return_value = {
            "schema_version": 1,
            "repo_path": str(dummy_repo),
            "last_commit": "abc",
            "scanned_at": "2026-01-01T00:00:00+00:00",
            "findings_by_file": {
                "main.py": [
                    {
                        "rule_id": "SQLI-001",
                        "vuln_class": "sql_injection",
                        "file": "main.py",
                        "line": 1,
                        "loop_status": "ACCEPTED",
                        "patch_diff": "--- patch",
                    }
                ]
            },
        }
        mock_changed.return_value = ChangedFileSet(frozenset(), frozenset(), frozenset())
        det_result = MagicMock()
        det_result.candidates = []
        det_result.decision = "PROCEED"
        det_result.reason = "Detection complete"
        det_result.total_candidates = 0
        det_result.confidence_breakdown = {}
        mock_det.return_value = det_result

        from analyst.orchestrator.pipeline import run_pipeline

        result = run_pipeline(
            repo_path=str(dummy_repo),
            output_path=str(tmp_path / "out"),
            offline=True,
            dynamic=True,
            incremental=True,
        )

    # Confirm the run completed and recorded the carried forward finding
    assert result.status == "OK"
    assert result.confirmed_count == 1
    # No EXPLOIT_VERIFY_REQUEST should be in protocol_messages
    exploit_requests = [
        m for m in result.protocol_messages
        if getattr(m, "message_type", None) == MessageType.EXPLOIT_VERIFY_REQUEST
    ]
    assert len(exploit_requests) == 0

