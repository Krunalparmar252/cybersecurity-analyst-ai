"""
LangGraph Orchestrator — the same four agents, the same A2A bus, the same
routing decisions as pipeline.py, expressed as an explicit graph instead of a
long function with if/return branches.

WHY THIS EXISTS
---------------
pipeline.py already does real DECIDE-driven routing. What it does not have is an
inspectable control-flow graph: the routing lives as Python `if` statements
inside a long function. Here the same routing is named nodes and named
conditional edges, introspectable via `get_graph().draw_mermaid()`, and the
natural place to add cycles if the system grows into one.

WHAT CHANGED IN THIS REVISION
-----------------------------
The graph now carries the protocol layer through its state:

  * `salt_ctx`, `bus` and `audit` are created once at the entry point and live
    in `PipelineState`, so every node seals and signs against ONE run salt.
  * Nodes publish sealed `AgentMessage` envelopes instead of appending dicts.
  * A new `negotiate` node sits between `detect` and `reason`. It is a real
    graph node, not a helper, because its outcome is a routing decision made by
    a PEER (the Reasoning agent answering a NEGOTIATION_REQUEST) rather than by
    the orchestrator. That is the clearest possible expression of "routing is
    not hardcoded": the edge taken after DETECT depends on a message another
    agent sends back at runtime.

WHAT DELIBERATELY DID NOT CHANGE
--------------------------------
- All four agent modules are called exactly as pipeline.py calls them. This
  module re-implements no agent logic.
- The legacy `{"agent", "decision", "reason", "timestamp"}` message shape still
  reaches `on_message`, so the existing dashboard and tests are unaffected.
- repo_fetcher's fetch_target() wrapping (clone / passthrough / cleanup) is
  unchanged and still wraps everything at the outer entry point.

SCOPE NOTE (unchanged, still worth stating in Q&A): patch_loop.py's internal
propose/act/observe/decide retry loop (MAX_ATTEMPTS=2) remains a plain Python
loop inside the REASON node. It is one agent's internal verification step, not
inter-agent routing — the graph's job is routing between agents. Promoting it
to graph-level cycles is a separate, separately-verifiable change.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional, TypedDict

from langgraph.graph import END, StateGraph

from analyst.detection.agent import DetectionAgentResult, run_detection_agent
from analyst.ingestion.agent import IngestionAgentResult, run_ingestion_agent
from analyst.triage import agent as triage_agent
from analyst.protocol import (
    AgentID,
    AgentMessage,
    DecisionPayload,
    FallbackNotice,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    SaltContext,
    StateHandoffPayload,
    write_verification_sidecar,
)
from analyst.orchestrator.pipeline import (
    PipelineResult,
    _apply_incremental_filter,
    _build_bus,
    _write_scan_cache,
)
from analyst.common.types import HUMAN_ATTENTION_STATUSES
from analyst.reasoning.patch_loop import run_patch_verify_loop
from analyst.reporting.agent import run_reporting_agent


class PipelineState(TypedDict, total=False):
    # --- inputs, set once before graph.invoke() ---
    repo_path: str  # resolved LOCAL path (post fetch_target)
    source: str  # original user-facing path/URL, for report/display text
    output_path: str
    artifact_dir: Optional[str]
    start_time: float
    offline: bool
    dynamic: bool
    incremental: bool  # C-3

    # --- protocol layer, created once per run ---
    salt_ctx: SaltContext
    bus: object  # MessageBus
    audit: object  # AuditLog

    # --- accumulated as nodes run ---
    ing: IngestionAgentResult
    det: DetectionAgentResult
    candidates_digest: str
    verify_results: list
    triage: dict
    report_text: str
    report_action: str
    escalated_count: int
    fallbacks: list
    incremental_summary: Optional[str]  # C-3

    stage_errors: dict
    routing_log: list
    messages: list

    # --- callbacks (LangGraph state must be a plain dict, so they ride along) ---
    on_stage_start: Optional[object]
    on_stage_done: Optional[object]
    on_route: Optional[object]
    on_message: Optional[object]


# ---------------------------------------------------------------------------
# Helpers — thin wrappers so nodes read as "agent decides, bus carries it"
# ---------------------------------------------------------------------------
def _decide(state: PipelineState, sender: AgentID, decision: str, reason: str, **metrics) -> None:
    state["bus"].send(
        sender=sender,
        receiver=AgentID.ORCHESTRATOR,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision=decision, reason=reason, metrics=metrics),
    )


def _handoff(
    state: PipelineState,
    sender: AgentID,
    receiver: AgentID,
    stage: str,
    summary: str,
    item_count: int,
    state_digest: str,
    manifest_digest: Optional[str] = None,
) -> None:
    state["bus"].send(
        sender=sender,
        receiver=receiver,
        message_type=MessageType.STATE_HANDOFF,
        payload=StateHandoffPayload(
            stage=stage,
            summary=summary,
            item_count=item_count,
            state_digest=state_digest,
            manifest_digest=manifest_digest,
        ),
    )


def _write_empty_report(state: PipelineState) -> str:
    from analyst.reporting.renderer import render_report

    return render_report(
        [],
        state["source"],
        time.time() - state["start_time"],
        incremental_summary=state.get("incremental_summary"),
    )


# ---------------------------------------------------------------------------
# Nodes — each wraps exactly one existing agent call, unchanged.
# ---------------------------------------------------------------------------
def ingest_node(state: PipelineState) -> PipelineState:
    if state.get("on_stage_start"):
        state["on_stage_start"]("INGEST")
    ing = run_ingestion_agent(state["repo_path"], salt_ctx=state["salt_ctx"])
    if state.get("artifact_dir"):
        artifact_path = Path(state["artifact_dir"])
        artifact_path.mkdir(parents=True, exist_ok=True)
        (artifact_path / "ingestion_manifest.json").write_text(ing.result.manifest.to_json())
    state["ing"] = ing
    _decide(
        state,
        AgentID.INGEST,
        ing.decision,
        ing.reason,
        total_files=ing.total_files,
        parsed_files=ing.parsed_files,
        parse_ratio=round(ing.parse_ratio, 3),
        manifest_digest=ing.manifest_digest,
        integrity_ok=ing.integrity_ok,
    )
    if state.get("on_stage_done"):
        state["on_stage_done"]("INGEST")
    return state


def detect_node(state: PipelineState) -> PipelineState:
    if state.get("on_stage_start"):
        state["on_stage_start"]("DETECT")
    ing = state["ing"]
    _handoff(
        state,
        AgentID.INGEST,
        AgentID.DETECT,
        stage="INGEST",
        summary=f"{ing.parsed_files}/{ing.total_files} files parsed, sealed at ingestion.",
        item_count=ing.total_files,
        state_digest=ing.manifest_digest,
        manifest_digest=ing.manifest_digest,
    )

    det = run_detection_agent(ing.result)

    # ------------------------------------------------- INCREMENTAL FILTER (C-3)
    if state.get("incremental", False):
        filtered, summary = _apply_incremental_filter(state["repo_path"], det.candidates)
        det.candidates = filtered
        state["incremental_summary"] = summary
        if summary and state.get("on_route"):
            state["on_route"](f"ORCHESTRATOR: Incremental scan: {summary}")

    candidate_payload = [c.to_dict() for c in det.candidates]
    if state.get("artifact_dir"):
        artifact_path = Path(state["artifact_dir"])
        (artifact_path / "candidate_findings.json").write_text(
            json.dumps(candidate_payload, indent=2)
        )
    digest = state["salt_ctx"].seal(candidate_payload)
    state["det"] = det
    state["candidates_digest"] = digest
    _decide(
        state,
        AgentID.DETECT,
        det.decision,
        det.reason,
        total_candidates=det.total_candidates,
        confidence_breakdown=det.confidence_breakdown,
        rule_families=det.rule_families,
        candidates_digest=digest,
    )
    if state.get("on_stage_done"):
        state["on_stage_done"]("DETECT")
    return state


def negotiate_node(state: PipelineState) -> PipelineState:
    """Ask the Reasoning agent whether it will take a LOW_SIGNAL candidate set.

    This node exists because the answer is not the orchestrator's to give.
    Reasoning pays the LLM cost, so Reasoning decides whether the set is worth
    it; the graph just routes on the reply. `negotiation_accepted` is written
    into state and read by the conditional edge below.
    """
    det = state["det"]
    response: AgentMessage = state["bus"].request(
        sender=AgentID.ORCHESTRATOR,
        receiver=AgentID.REASON,
        message_type=MessageType.NEGOTIATION_REQUEST,
        payload=NegotiationRequest(
            proposal="ANALYSE_LOW_SIGNAL_SET",
            rationale=det.reason,
            context={
                "candidate_count": det.total_candidates,
                "high_confidence": det.confidence_breakdown.get("high", 0),
                "llm_available": not state.get("offline", False),
            },
        ),
        expect=MessageType.NEGOTIATION_RESPONSE,
    )
    verdict: NegotiationResponse = response.payload_as(NegotiationResponse)
    state["negotiation_accepted"] = verdict.accepted
    if not verdict.accepted:
        _decide(
            state,
            AgentID.ORCHESTRATOR,
            "SKIP_TO_REPORT",
            f"Reasoning agent declined the low-signal set: {verdict.rationale}",
        )
    return state


def reason_node(state: PipelineState) -> PipelineState:
    if state.get("on_stage_start"):
        state["on_stage_start"]("REASON")
    det = state["det"]
    _handoff(
        state,
        AgentID.DETECT,
        AgentID.REASON,
        stage="DETECT",
        summary=(
            f"{det.total_candidates} candidate(s) across "
            f"{len(det.rule_families)} rule family/families."
        ),
        item_count=det.total_candidates,
        state_digest=state["candidates_digest"],
        manifest_digest=state["ing"].manifest_digest,
    )

    def on_fallback(outcome) -> None:
        state["fallbacks"].append(outcome.as_payload())
        state["bus"].send(
            sender=AgentID.REASON,
            receiver=AgentID.ORCHESTRATOR,
            message_type=MessageType.FALLBACK_NOTICE,
            payload=FallbackNotice(
                tier_from="T0_LLM",
                tier_to=outcome.tier,
                trigger=outcome.trigger,
                detail=outcome.detail,
                recoverable=outcome.trigger == "RECOVERED",
            ),
        )

    verify_results = []

    def on_single_result(res):
        state.setdefault("verify_results", []).append(res)
        if state.get("artifact_dir"):
            artifact_path = Path(state["artifact_dir"])
            try:
                (artifact_path / "confirmed_findings.json").write_text(
                    json.dumps([r.to_dict() for r in state["verify_results"]], indent=2)
                )
            except Exception:
                pass
        if state.get("on_finding_verified"):
            try:
                state["on_finding_verified"](res.to_dict())
            except Exception:
                pass

    try:
        verify_results = run_patch_verify_loop(
            det.candidates,
            state["ing"].result.sources,
            state["repo_path"],
            bus=state["bus"],
            on_fallback=on_fallback,
            offline=state.get("offline", False),
            on_result=on_single_result,
        )
        if state.get("artifact_dir"):
            artifact_path = Path(state["artifact_dir"])
            (artifact_path / "confirmed_findings.json").write_text(
                json.dumps([r.to_dict() for r in verify_results], indent=2)
            )

        needs_human = [r for r in verify_results if r.loop_status in HUMAN_ATTENTION_STATUSES]
        retried = [r for r in verify_results if r.attempts > 1]
        accepted = [r for r in verify_results if r.loop_status == "ACCEPTED"]

        # --- B-4: Send exploit.verify request for accepted patches ---
        if state.get("dynamic", False):
            from analyst.reasoning.patch_loop import _make_sandbox_copy, apply_patch_to_text
            import shutil
            from analyst.protocol import CAP_EXPLOIT_VERIFY, ExploitVerifyRequestPayload, ExploitVerifyResultPayload

            for r in accepted:
                if r.attempts == 0:
                    continue
                sandbox_root = _make_sandbox_copy(state["repo_path"])
                try:
                    if r.finding.patch_diff:
                        target_file = sandbox_root / r.finding.file
                        original_text = target_file.read_text(encoding="utf-8")
                        patched_text = apply_patch_to_text(original_text, r.finding.patch_diff)
                        target_file.write_text(patched_text, encoding="utf-8")
                    
                    finding_id = f"{r.finding.rule_id}:{r.finding.file}:{r.finding.line}"
                    req = ExploitVerifyRequestPayload(
                        finding_id=finding_id,
                        rule_id=r.finding.rule_id,
                        file=r.finding.file,
                        sandbox_root=str(sandbox_root),
                        attempt=r.attempts,
                    )
                    
                    response = state["bus"].request_capability(
                        sender=AgentID.ORCHESTRATOR,
                        capability=CAP_EXPLOIT_VERIFY,
                        message_type=MessageType.EXPLOIT_VERIFY_REQUEST,
                        payload=req,
                        expect=MessageType.EXPLOIT_VERIFY_RESPONSE,
                    )
                    
                    res = response.payload_as(ExploitVerifyResultPayload)
                    r.exploit_result = {
                        "verdict": res.verdict,
                        "payload_used": res.payload_used,
                        "evidence": res.evidence,
                        "elapsed_seconds": res.elapsed_seconds,
                        "tool_calls_used": res.tool_calls_used,
                    }
                except Exception as e:
                    # Failing to verify exploit should not fail the accepted patch.
                    pass
                finally:
                    shutil.rmtree(sandbox_root, ignore_errors=True)

        _decide(
            state,
            AgentID.REASON,
            "VERIFIED" if not needs_human else "PARTIALLY_VERIFIED",
            f"{len(accepted)} accepted, {len(retried)} retried, {len(needs_human)} "
            f"routed to manual review out of {len(verify_results)} candidate(s) processed.",
            accepted=len(accepted),
            manual_review=len(needs_human),
            tiers=sorted({r.finding.analysis_tier for r in verify_results}),
        )
    except Exception as exc:  # noqa: BLE001 - one bad agent run must not kill the pipeline
        state["stage_errors"]["REASON"] = str(exc)
        state["bus"].report_error(AgentID.REASON, type(exc).__name__, str(exc))

    state["verify_results"] = verify_results
    if state.get("on_stage_done"):
        state["on_stage_done"]("REASON")
    return state


def triage_node(state: PipelineState) -> PipelineState:
    state["triage"] = triage_agent.request_triage(state["bus"], state.get("verify_results", []))
    return state


def report_node(state: PipelineState) -> PipelineState:
    if state.get("on_stage_start"):
        state["on_stage_start"]("REPORT")
    verify_results = state.get("verify_results", [])
    confirmed = [r.finding for r in verify_results]
    duration = time.time() - state["start_time"]
    rep = run_reporting_agent(
        confirmed,
        state["source"],
        duration,
        verify_results=verify_results,
        triage=state.get("triage"),
        incremental_summary=state.get("incremental_summary"),
    )
    Path(state["output_path"]).write_text(rep.report_text, encoding="utf-8")
    state["report_text"] = rep.report_text
    state["report_action"] = rep.action
    state["escalated_count"] = rep.escalated_count
    _decide(
        state,
        AgentID.REPORT,
        rep.action,
        rep.reason,
        accepted=rep.accepted_count,
        escalated=rep.escalated_count,
        no_patch=rep.no_patch_count,
        report_digest=state["salt_ctx"].seal(rep.report_text),
    )
    if state.get("on_stage_done"):
        state["on_stage_done"]("REPORT")
    return state


def skip_to_report_node(state: PipelineState) -> PipelineState:
    """Reached when INGEST, DETECT or the negotiation decided the pipeline
    should not continue. Writes the same empty-report shape pipeline.py's
    early_exit() produces, but as its own node so the skip is a visible
    destination in the graph rather than an early return."""
    report_text = _write_empty_report(state)
    Path(state["output_path"]).write_text(report_text, encoding="utf-8")
    state["report_text"] = report_text
    state["verify_results"] = []
    state["escalated_count"] = 0
    return state


# ---------------------------------------------------------------------------
# Conditional edges — read the SAME decision strings pipeline.py branches on,
# plus the peer's negotiation verdict. No new judgement originates here.
# ---------------------------------------------------------------------------
def route_after_ingest(state: PipelineState) -> str:
    if state["ing"].decision == "INSUFFICIENT":
        _decide(
            state,
            AgentID.ORCHESTRATOR,
            "SKIP_TO_REPORT",
            "Ingestion agent judged its own output insufficient.",
        )
        state["stage_errors"]["INGEST"] = state["ing"].reason
        return "skip"
    return "continue"


def route_after_detect(state: PipelineState) -> str:
    decision = state["det"].decision
    if decision == "NONE_FOUND":
        _decide(
            state,
            AgentID.ORCHESTRATOR,
            "SKIP_TO_REPORT",
            "Detection agent found nothing to escalate.",
        )
        return "skip"
    if decision == "LOW_SIGNAL":
        # Do not decide here — hand it to the peer.
        return "negotiate"
    return "continue"


def route_after_negotiation(state: PipelineState) -> str:
    return "continue" if state.get("negotiation_accepted") else "skip"


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def build_graph():
    graph = StateGraph(PipelineState)

    graph.add_node("ingest", ingest_node)
    graph.add_node("detect", detect_node)
    graph.add_node("negotiate", negotiate_node)
    graph.add_node("reason", reason_node)
    graph.add_node("triage", triage_node)
    graph.add_node("report", report_node)
    graph.add_node("skip_to_report", skip_to_report_node)

    graph.set_entry_point("ingest")

    graph.add_conditional_edges(
        "ingest", route_after_ingest, {"continue": "detect", "skip": "skip_to_report"}
    )
    graph.add_conditional_edges(
        "detect",
        route_after_detect,
        {"continue": "reason", "negotiate": "negotiate", "skip": "skip_to_report"},
    )
    graph.add_conditional_edges(
        "negotiate",
        route_after_negotiation,
        {"continue": "reason", "skip": "skip_to_report"},
    )
    graph.add_edge("reason", "triage")
    graph.add_edge("triage", "report")
    graph.add_edge("report", END)
    graph.add_edge("skip_to_report", END)

    return graph.compile()


_COMPILED_GRAPH = None


def get_graph():
    """Lazily compile and cache the graph. `get_graph().get_graph().draw_mermaid()`
    renders the routing diagram used in the docs."""
    global _COMPILED_GRAPH
    if _COMPILED_GRAPH is None:
        _COMPILED_GRAPH = build_graph()
    return _COMPILED_GRAPH


def run_pipeline_graph(
    repo_path: str,
    output_path: str,
    artifact_dir: Optional[str] = None,
    on_stage_start=None,
    on_stage_done=None,
    on_route=None,
    on_message=None,
    on_finding_verified=None,
    run_id: Optional[str] = None,
    offline: bool = False,
    dynamic: bool = False,
    incremental: bool = False,
) -> PipelineResult:
    """Drop-in replacement for pipeline.run_pipeline() — same signature, same
    PipelineResult shape, same fetch_target() wrapping. Internally routes
    through the compiled LangGraph instead of pipeline.py's function body."""
    from analyst.ingestion.repo_fetcher import RepoFetchError, fetch_target

    try:
        with fetch_target(repo_path) as target:
            return _run_graph_on_local_path(
                source=target.source,
                local_path=target.local_path,
                output_path=output_path,
                artifact_dir=artifact_dir,
                on_stage_start=on_stage_start,
                on_stage_done=on_stage_done,
                on_route=on_route,
                on_message=on_message,
                on_finding_verified=on_finding_verified,
                run_id=run_id,
                offline=offline,
                dynamic=dynamic,
                incremental=incremental,
            )
    except RepoFetchError as exc:
        from analyst.reporting.renderer import render_report

        ctx = SaltContext.generate(run_id=run_id)
        report_text_local = render_report([], repo_path, 0.0)
        Path(output_path).write_text(report_text_local, encoding="utf-8")
        bus, _audit = _build_bus(ctx, on_message=on_message)
        bus.send(
            sender=AgentID.ORCHESTRATOR,
            receiver=AgentID.ORCHESTRATOR,
            message_type=MessageType.DECISION,
            payload=DecisionPayload(decision="FETCH_FAILED", reason=str(exc)),
        )
        return PipelineResult(
            status="PARTIAL",
            report_text=report_text_local,
            confirmed_count=0,
            rejected_count=0,
            escalated_count=0,
            duration_seconds=0.0,
            stage_errors={"FETCH": str(exc)},
            routing_log=[f"ORCHESTRATOR: FETCH_FAILED — {exc}"],
            messages=bus.legacy_messages(),
            run_id=ctx.run_id,
            integrity={"verified": True, **bus.stats()},
        )


def _run_graph_on_local_path(
    source: str,
    local_path: str,
    output_path: str,
    artifact_dir: Optional[str] = None,
    on_stage_start=None,
    on_stage_done=None,
    on_route=None,
    on_message=None,
    on_finding_verified=None,
    run_id: Optional[str] = None,
    offline: bool = False,
    dynamic: bool = False,
    incremental: bool = False,
) -> PipelineResult:
    start_time = time.time()
    ctx = SaltContext.generate(run_id=run_id)
    routing_log: list = []

    def relay(msg_dict: dict) -> None:
        line = (
            f"{msg_dict['agent']} -> {msg_dict['receiver']} "
            f"[{msg_dict['message_type']}] {msg_dict['decision']} — {msg_dict['reason']}"
        )
        routing_log.append(line)
        if on_route:
            on_route(line)
        if on_message:
            on_message(msg_dict)

    bus, audit = _build_bus(ctx, on_message=relay)
    audit.append(actor="ORCHESTRATOR", action="RUN_START", source=source, engine="graph")

    initial_state: PipelineState = {
        "repo_path": local_path,
        "source": source,
        "output_path": output_path,
        "artifact_dir": artifact_dir,
        "start_time": start_time,
        "offline": offline,
        "dynamic": dynamic,
        "incremental": incremental,  # C-3
        "salt_ctx": ctx,
        "bus": bus,
        "audit": audit,
        "stage_errors": {},
        "routing_log": routing_log,
        "messages": [],
        "verify_results": [],
        "fallbacks": [],
        "incremental_summary": None,  # C-3
        "on_stage_start": on_stage_start,
        "on_stage_done": on_stage_done,
        "on_route": on_route,
        "on_message": on_message,
        "on_finding_verified": on_finding_verified,
    }

    final_state = get_graph().invoke(initial_state)

    duration = time.time() - final_state["start_time"]
    verify_results = final_state.get("verify_results", [])
    confirmed = [r.finding for r in verify_results]
    stage_errors = final_state.get("stage_errors", {})

    audit.append(
        actor="ORCHESTRATOR",
        action="RUN_END",
        status="PARTIAL" if stage_errors else "OK",
        duration=round(duration, 3),
        findings=len(confirmed),
    )
    transcript_ok, transcript_note = bus.verify_transcript()
    if not transcript_ok:
        stage_errors["INTEGRITY"] = transcript_note

    integrity = {
        "verified": transcript_ok,
        "detail": transcript_note,
        "salt": ctx.descriptor(),
        "audit_head": audit.head(),
        "messages": len(bus.transcript),
        "rejected_messages": len(bus.rejected),
        "capabilities": bus.capabilities(),
    }

    report_file = Path(output_path)
    if report_file.exists():
        sidecar = write_verification_sidecar(report_file, ctx, audit=audit, extra={"target": source})
        integrity["report_checksum_file"] = str(sidecar)
    if artifact_dir:
        audit.write(Path(artifact_dir) / "audit_log.json")
        integrity["audit_log_file"] = str(Path(artifact_dir) / "audit_log.json")

    # C-5: Persist scan cache write-back (fail-safe)
    ing_obj = final_state.get("ing")
    scanned_files = (
        list(ing_obj.result.sources.keys())
        if ing_obj and hasattr(ing_obj, "result") and hasattr(ing_obj.result, "sources")
        else None
    )
    _write_scan_cache(local_path, verify_results, scanned_files=scanned_files)

    return PipelineResult(
        status="PARTIAL" if stage_errors else "OK",
        report_text=final_state.get("report_text", ""),
        confirmed_count=sum(1 for f in confirmed if f.confirmed),
        rejected_count=sum(1 for f in confirmed if not f.confirmed),
        escalated_count=final_state.get("escalated_count", 0),
        duration_seconds=duration,
        stage_errors=stage_errors,
        routing_log=routing_log,
        messages=bus.legacy_messages(),
        run_id=ctx.run_id,
        integrity=integrity,
        fallbacks=final_state.get("fallbacks", []),
        manual_review_count=sum(
            1 for r in verify_results if r.loop_status in HUMAN_ATTENTION_STATUSES
        ),
        protocol_messages=list(bus.transcript),
        incremental_summary=final_state.get("incremental_summary"),  # C-3
    )
