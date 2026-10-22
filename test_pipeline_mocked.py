"""
Mocked end-to-end test of the rebuilt agentic pipeline (orchestrator +
all 4 agents). Mocks ChatGroq at the with_structured_output().invoke()
boundary so no real API calls or key are needed -- verifies the full
message-bus routing, patch loop control flow, and report generation work
together after the LangChain rewrite.

WHY MOCK AT with_structured_output().invoke() AND NOT LOWER:
engine.py's analyze_finding() calls client.with_structured_output(...).invoke(...)
and expects back a dict|BaseModel (LangChain's structured-output return
shape), not a raw Groq chat-completions response object. Mocking at this
boundary is what actually exercises _coerce_structured_response() and the
real analyze_finding() code path, rather than bypassing it.
"""

import json
from unittest.mock import patch, MagicMock

from analyst.orchestrator.pipeline import run_pipeline


def _fake_structured_payload(confirmed=True, severity="HIGH", with_patch=True):
    return {
        "confirmed": confirmed,
        "confirmation_reasoning": "Looks like a genuine tainted query." if confirmed else "False positive: test fixture.",
        "severity": severity if confirmed else "NONE",
        "explanation": "Query string is built via f-string interpolation of unsanitized input." if confirmed else "",
        # NOTE: this must match text that actually appears in demo_app/app.py
        # (the real seeded SQLI bug), or apply_patch_to_text's content-based
        # matching can never find an anchor -- every attempt would ESCALATE
        # instead of exercising the ACCEPT branch. Keep in sync with
        # demo_app/app.py's SEEDED BUG 2 line if that fixture ever changes.
        "patch_diff": (
            "--- a/demo_app/app.py\n+++ b/demo_app/app.py\n@@\n"
            "-    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n"
            "+    query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n"
        ) if (confirmed and with_patch) else "",
    }


def test_full_pipeline_mocked(tmp_path, original_demo_app):
    output_path = str(tmp_path / "report.md")
    artifact_dir = str(tmp_path / "artifacts")

    # fake_structured_client is what client.with_structured_output(...)
    # returns (a Runnable in real LangChain) -- only .invoke() is used by
    # analyze_finding(), so that's all this fake needs to implement.
    fake_structured_client = MagicMock()
    # SQLI-001's snippet matches demo_app/app.py's real seeded bug text, so
    # the fake patch_diff below (which targets that same text) should let
    # patch_loop's sandboxed re-detection ACCEPT it. XSS/SECRET findings
    # reuse this same canned SQL patch, which doesn't touch their lines, so
    # they should RETRY then ESCALATE -- that's the branch coverage this
    # test is asserting on below (1 accepted, 2 escalated).
    fake_structured_client.invoke.return_value = _fake_structured_payload()

    fake_client = MagicMock()
    fake_client.with_structured_output.return_value = fake_structured_client

    messages_seen = []

    with patch("analyst.reasoning.patch_loop.ChatGroq", return_value=fake_client):
        with patch.dict("os.environ", {"GROQ_API_KEY": "fake-key-for-test"}):
            result = run_pipeline(
                repo_path=str(original_demo_app),
                output_path=output_path,
                artifact_dir=artifact_dir,
                on_message=lambda m: messages_seen.append(m),
            )

    print("\n--- PIPELINE RESULT ---")
    print("status:", result.status)
    print("confirmed:", result.confirmed_count, "rejected:", result.rejected_count, "escalated:", result.escalated_count)
    print("\n--- MESSAGE BUS ---")
    for m in messages_seen:
        print(f"  [{m['agent']}] {m['decision']}: {m['reason']}")

    # Structural assertions -- proves the rewrite didn't break control flow
    assert result.status in ("OK", "PARTIAL")
    agents_that_posted = {m["agent"] for m in messages_seen}
    assert "INGEST" in agents_that_posted
    assert "DETECT" in agents_that_posted
    assert "REASON" in agents_that_posted
    assert "REPORT" in agents_that_posted

    ingest_msg = next(m for m in messages_seen if m["agent"] == "INGEST")
    assert ingest_msg["decision"] == "SUFFICIENT"

    detect_msg = next(m for m in messages_seen if m["agent"] == "DETECT")
    assert detect_msg["decision"] == "WORTH_ESCALATING"

    # Proves the patch loop's ACCEPT branch actually fires (not just RETRY/
    # ESCALATE) -- i.e. a correct patch that resolves the finding is
    # detected as such by re-running real detection against the sandbox.
    assert result.confirmed_count == 3
    assert result.escalated_count == 2, (
        "expected exactly 1 finding to ACCEPT (SQLI-001, whose fake patch "
        "matches demo_app's real seeded bug text) and 2 to ESCALATE "
        "(XSS/SECRET, untouched by the fake SQL patch)"
    )

    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "artifacts" / "ingestion_manifest.json").exists()
    assert (tmp_path / "artifacts" / "candidate_findings.json").exists()

    print("\nAll structural assertions passed.")


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        test_full_pipeline_mocked(Path(d))
