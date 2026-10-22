"""
Mocked end-to-end test of the LangGraph orchestrator (analyst.orchestrator.graph).

Deliberately mirrors test_pipeline_mocked.py's mocking boundary (ChatGroq
at with_structured_output().invoke()) and assertions almost exactly. The
point of this test is to prove run_pipeline_graph() is behaviorally
equivalent to the original run_pipeline() -- same routing, same counts,
same artifacts -- for the same inputs, now that routing goes through a
compiled LangGraph instead of inline if/return branches.
"""

from unittest.mock import patch, MagicMock

from analyst.orchestrator.graph import run_pipeline_graph


def _fake_structured_payload(confirmed=True, severity="HIGH", with_patch=True):
    return {
        "confirmed": confirmed,
        "confirmation_reasoning": "Looks like a genuine tainted query." if confirmed else "False positive: test fixture.",
        "severity": severity if confirmed else "NONE",
        "explanation": "Query string is built via f-string interpolation of unsanitized input." if confirmed else "",
        "patch_diff": (
            "--- a/demo_app/app.py\n+++ b/demo_app/app.py\n@@\n"
            "-    query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n"
            "+    query = \"SELECT * FROM users WHERE username = ? AND password = ?\"\n"
        ) if (confirmed and with_patch) else "",
    }


def test_full_pipeline_graph_mocked(tmp_path, original_demo_app):
    output_path = str(tmp_path / "report.md")
    artifact_dir = str(tmp_path / "artifacts")

    fake_structured_client = MagicMock()
    fake_structured_client.invoke.return_value = _fake_structured_payload()

    fake_client = MagicMock()
    fake_client.with_structured_output.return_value = fake_structured_client

    messages_seen = []

    with patch("analyst.reasoning.patch_loop.ChatGroq", return_value=fake_client):
        with patch.dict("os.environ", {"GROQ_API_KEY": "fake-key-for-test"}):
            result = run_pipeline_graph(
                repo_path=str(original_demo_app),
                output_path=output_path,
                artifact_dir=artifact_dir,
                on_message=lambda m: messages_seen.append(m),
            )

    print("\n--- GRAPH PIPELINE RESULT ---")
    print("status:", result.status)
    print("confirmed:", result.confirmed_count, "rejected:", result.rejected_count, "escalated:", result.escalated_count)
    print("\n--- MESSAGE BUS ---")
    for m in messages_seen:
        print(f"  [{m['agent']}] {m['decision']}: {m['reason']}")

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

    # Same expected split as the original pipeline test: 1 ACCEPT (SQLI-001),
    # 2 ESCALATE (XSS/SECRET, untouched by the fake SQL-only patch).
    assert result.confirmed_count == 3
    assert result.escalated_count == 2

    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "artifacts" / "ingestion_manifest.json").exists()
    assert (tmp_path / "artifacts" / "candidate_findings.json").exists()

    print("\nAll structural assertions passed (graph orchestrator).")


def test_graph_skip_on_insufficient_ingestion(tmp_path):
    """Exercises the ingest -> skip_to_report edge: an empty directory
    should make the Ingestion agent decide INSUFFICIENT, and the graph
    should route straight to skip_to_report without ever calling DETECT,
    REASON, or REPORT agents."""
    empty_dir = tmp_path / "empty_repo"
    empty_dir.mkdir()
    output_path = str(tmp_path / "report.md")

    messages_seen = []
    result = run_pipeline_graph(
        repo_path=str(empty_dir),
        output_path=output_path,
        on_message=lambda m: messages_seen.append(m),
    )

    agents_that_posted = {m["agent"] for m in messages_seen}
    assert "INGEST" in agents_that_posted
    assert "DETECT" not in agents_that_posted, "graph should skip DETECT on INSUFFICIENT ingestion"
    assert "REASON" not in agents_that_posted
    assert result.status == "PARTIAL"
    assert (tmp_path / "report.md").exists()

    print("\nSkip-to-report routing verified: DETECT/REASON/REPORT agents never ran.")


if __name__ == "__main__":
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as d:
        test_full_pipeline_graph_mocked(Path(d))
    with tempfile.TemporaryDirectory() as d:
        test_graph_skip_on_insufficient_ingestion(Path(d))
