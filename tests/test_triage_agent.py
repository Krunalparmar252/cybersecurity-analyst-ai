"""Task 10: TRIAGE agent (finding.triage) between REASON and REPORT."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from analyst.common.types import ConfirmedFinding
from analyst.orchestrator.graph import run_pipeline_graph
from analyst.orchestrator.pipeline import _build_bus, run_pipeline
from analyst.protocol import CAP_FINDING_TRIAGE, AgentID, MessageBus, SaltContext, TriageItem
from analyst.triage.agent import deterministic_triage, request_triage, triage_items

ROOT = Path(__file__).resolve().parent.parent


def item(i, sev, status, file="a.py", line=1):
    return TriageItem(index=i, rule_id="R-1", vuln_class="X", file=file, line=line,
                      severity=sev, loop_status=status)


def test_unverified_outranks_verified_at_same_severity():
    v = {x.index: x for x in deterministic_triage([
        item(0, "CRITICAL", "ACCEPTED"), item(1, "CRITICAL", "MANUAL_REVIEW_REQUIRED"),
        item(2, "MEDIUM", "ACCEPTED"), item(3, "LOW", "SKIPPED_NO_PATCH"),
    ])}
    assert (v[1].priority, v[0].priority) == ("P1", "P2")
    assert v[2].priority == "P4" and v[3].priority == "P4"
    assert v[1].rank < v[0].rank < v[2].rank
    assert sorted(x.rank for x in v.values()) == [1, 2, 3, 4]


def test_deterministic_and_unique_ranks():
    items = [item(i, "HIGH", None, file=f"f{i % 3}.py", line=i) for i in range(9)]
    assert deterministic_triage(items) == deterministic_triage(items)
    assert sorted(v.rank for v in deterministic_triage(items)) == list(range(1, 10))


def test_good_scorer_is_used():
    items = [item(0, "LOW", None), item(1, "HIGH", None)]
    scorer = lambda its: [{"index": 0, "priority": "P1", "rationale": "because"},  # noqa: E731
                          {"index": 1, "priority": "P3", "rationale": "because"}]
    verdicts, method, reason = triage_items(items, scorer)
    assert method == "scorer" and reason is None
    assert {v.index: v.priority for v in verdicts} == {0: "P1", 1: "P3"}


@pytest.mark.parametrize("scorer", [
    lambda its: (_ for _ in ()).throw(RuntimeError("model down")),
    lambda its: [{"index": 0, "priority": "P1", "rationale": "x"}],                       # incomplete
    lambda its: [{"index": 0, "priority": "P9", "rationale": "x"},
                 {"index": 1, "priority": "P1", "rationale": "x"}],                       # bad priority
    lambda its: "garbage",
])
def test_bad_scorer_falls_back_to_deterministic(scorer):
    items = [item(0, "LOW", None), item(1, "HIGH", None)]
    verdicts, method, reason = triage_items(items, scorer)
    assert method == "deterministic_fallback" and reason
    assert verdicts == deterministic_triage(items)


def test_capability_is_registered_on_the_pipeline_bus():
    bus, _ = _build_bus(SaltContext.generate(run_id="t"))
    assert bus.resolve(CAP_FINDING_TRIAGE) == AgentID.TRIAGE


def test_request_triage_never_fails_a_scan_when_no_provider():
    bus = MessageBus(SaltContext.generate(run_id="t"))
    bus.register(AgentID.ORCHESTRATOR, lambda m: None)
    f = ConfirmedFinding("R-1", "X", "a.py", 1, True, "ok", severity="HIGH")
    assert request_triage(bus, [SimpleNamespace(finding=f, loop_status="ACCEPTED")]) == {}


def test_triage_request_carries_no_source_or_patch_text():
    assert set(TriageItem.model_fields) == {
        "index", "rule_id", "vuln_class", "file", "line", "severity", "loop_status", "analysis_tier"}


def _run(engine, tmp_path):
    fn = run_pipeline if engine == "linear" else run_pipeline_graph
    return fn(repo_path=str(ROOT / "demo_app"), output_path=str(tmp_path / "r.md"),
              artifact_dir=str(tmp_path / "a"), offline=True)


@pytest.mark.parametrize("engine", ["linear", "graph"])
def test_triage_sits_between_reason_and_report_in_both_engines(tmp_path, engine):
    res = _run(engine, tmp_path)
    kinds = [(m["agent"], m["message_type"]) for m in res.messages]
    i_reason = max(i for i, k in enumerate(kinds) if k[0] == "REASON")
    i_triage = kinds.index(("TRIAGE", "TRIAGE_RESPONSE"))
    i_report = max(i for i, k in enumerate(kinds) if k[0] == "REPORT")
    assert i_reason < i_triage < i_report
    assert res.integrity["verified"] is True
    text = (tmp_path / "r.md").read_text(encoding="utf-8")
    assert "**Fix priority:** P1" in text
    # rank-1 finding is listed first in the report
    assert text.index("**Fix priority:** P1") < text.index("**Fix priority:** P3")


def test_both_engines_assign_identical_priorities(tmp_path):
    import re
    out = {}
    for engine in ("linear", "graph"):
        d = tmp_path / engine
        d.mkdir()
        _run(engine, d)
        out[engine] = re.findall(r"### \d+\. .*\n\n\*\*Rule:\*\* `([^`]+)`\n\n\*\*Fix priority:\*\* (P\d)",
                                 (d / "r.md").read_text(encoding="utf-8"))
    assert out["linear"] == out["graph"] and out["linear"]
