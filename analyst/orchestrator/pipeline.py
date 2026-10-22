"""
Orchestrator Agent — coordinates four autonomous agents over a formal A2A
message bus, routing on each agent's own DECISION and on peer-to-peer
negotiation, rather than on a fixed A->B->C->D sequence.

HISTORY (useful in Q&A)
-----------------------
Mid-1: a straight-line state machine. Every stage ran unconditionally.
Feedback: "this is an LLM-augmented pipeline, not an agentic system."

First fix: each stage was wrapped in an agent that performs its own
OBSERVE -> DECIDE and returns a decision label; the orchestrator routed on that
label instead of re-deriving judgements from raw data.

This revision — three structural changes:

1. A2A TRANSPORT. Stages no longer hand each other Python objects through the
   orchestrator's local variables. They exchange sealed `AgentMessage`
   envelopes (analyst/protocol/envelope.py) over a `MessageBus`
   (analyst/protocol/bus.py). Every handoff is addressed, typed, correlated
   and signed.

2. PEER-TO-PEER EDGES, NOT JUST ORCHESTRATOR EDGES. Two calls in this system
   were previously hardcoded imports and are now capability lookups:
     * REASON asks DETECT to re-check a rule after patching
       (`rule.recheck`) — it used to import run_detection and grade itself.
     * ORCHESTRATOR asks REASON whether it will accept a LOW_SIGNAL candidate
       set (`NEGOTIATION_REQUEST`) — the orchestrator used to make that budget
       decision on Reasoning's behalf.
   Routing after DETECT is therefore no longer a function of DETECT's decision
   alone; it depends on a negotiated answer from a peer, which is only known at
   runtime.

3. CHAIN OF CUSTODY. One `SaltContext` is created per run. Ingestion seals every
   file digest with it, every message is signed with it, every routing decision
   lands in a salted hash-chained `AuditLog`, and the rendered report gets a
   sealed checksum sidecar. At the end of the run the orchestrator re-verifies
   the whole transcript; a failure there downgrades the run to PARTIAL, because
   conclusions drawn over unverifiable state are not conclusions.

WHAT DELIBERATELY DID NOT CHANGE
--------------------------------
- Still a BOUNDED system: four fixed agents, no agent spawns arbitrary work.
- Still stateless: no database; artifacts are written per-stage to disk.
- `PipelineResult.messages` still contains dicts with "agent"/"decision"/
  "reason"/"timestamp" — the protocol fields are additive, so the existing CLI,
  dashboard and tests keep working unchanged.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from analyst.detection import agent as detection_agent
from analyst.detection.agent import run_detection_agent
from analyst.ingestion.agent import run_ingestion_agent
from analyst.ingestion.repo_fetcher import RepoFetchError, fetch_target
from analyst.protocol import (
    CAP_PATCH_REASONING,
    CAP_FINDING_TRIAGE,
    CAP_REPORT_RENDER,
    CAP_REPO_INGEST,
    CAP_RULE_RECHECK,
    CAP_RULE_SCAN,
    CAP_EXPLOIT_VERIFY,
    AgentID,
    AgentMessage,
    AuditLog,
    DecisionPayload,
    FallbackNotice,
    MessageBus,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    SaltContext,
    StateHandoffPayload,
    write_verification_sidecar,
)
from analyst.reasoning import patch_loop as reasoning_agent
from analyst.triage import agent as triage_agent
from analyst.exploitation import agent as exploitation_agent
from analyst.common.types import HUMAN_ATTENTION_STATUSES
from analyst.reasoning.patch_loop import run_patch_verify_loop
from analyst.reporting.agent import run_reporting_agent


@dataclass
class PipelineResult:
    status: str  # "OK" | "PARTIAL"
    report_text: str
    confirmed_count: int
    rejected_count: int
    escalated_count: int
    duration_seconds: float
    stage_errors: dict
    routing_log: list = field(default_factory=list)  # human-readable strings (back-compat)
    messages: list = field(default_factory=list)  # legacy dict projection of the transcript
    # --- added by the protocol/crypto revision ---
    run_id: str = ""
    integrity: dict = field(default_factory=dict)
    fallbacks: list = field(default_factory=list)
    manual_review_count: int = 0
    protocol_messages: list = field(default_factory=list)  # list[AgentMessage]


# ---------------------------------------------------------------------------
# Bus wiring
# ---------------------------------------------------------------------------
def _build_bus(ctx: SaltContext, on_message=None) -> tuple[MessageBus, AuditLog]:
    """Create the run's bus and register all four agents with the capabilities
    they provide.

    The orchestrator registers a sink for itself so decisions addressed to it
    are delivered rather than dead-lettered. Ingestion and Reporting expose
    capabilities but currently answer no inbound requests — registering them
    anyway is deliberate: it makes the capability map complete, so `bus.
    capabilities()` is an accurate picture of the system rather than a partial
    one.
    """
    audit = AuditLog(ctx, stream_id="pipeline")
    bus = MessageBus(ctx, audit=audit, on_message=on_message)

    bus.register(AgentID.ORCHESTRATOR, lambda msg: None)
    bus.register(AgentID.INGEST, lambda msg: None, capabilities=(CAP_REPO_INGEST,))
    bus.register(
        AgentID.DETECT,
        detection_agent.handle_message,
        capabilities=(CAP_RULE_SCAN, CAP_RULE_RECHECK),
    )
    bus.register(
        AgentID.REASON,
        reasoning_agent.handle_message,
        capabilities=(CAP_PATCH_REASONING,),
    )
    bus.register(AgentID.TRIAGE, triage_agent.handle_message, capabilities=(CAP_FINDING_TRIAGE,))
    bus.register(AgentID.REPORT, lambda msg: None, capabilities=(CAP_REPORT_RENDER,))
    bus.register(
        AgentID.EXPLOIT,
        exploitation_agent.handle_message,
        capabilities=(CAP_EXPLOIT_VERIFY,)
    )
    return bus, audit


def _decide(bus: MessageBus, sender: AgentID, decision: str, reason: str, **metrics) -> None:
    """Publish an agent's own decision to the orchestrator."""
    bus.send(
        sender=sender,
        receiver=AgentID.ORCHESTRATOR,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(decision=decision, reason=reason, metrics=metrics),
    )


def _handoff(
    bus: MessageBus,
    sender: AgentID,
    receiver: AgentID,
    stage: str,
    summary: str,
    item_count: int,
    state_digest: str,
    manifest_digest: Optional[str] = None,
) -> None:
    bus.send(
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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def run_pipeline(
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
) -> PipelineResult:
    """
    Run the full pipeline. `repo_path` accepts either a local directory path OR
    a git URL (https://, git://, git@) — resolution happens via
    analyst.ingestion.repo_fetcher.fetch_target(), which shallow-clones git URLs
    into a temp dir and cleans up automatically, or passes local paths through
    untouched. Reports and CLI output always show the original `repo_path` the
    user typed, never the opaque temp clone path.

    Callbacks:
      on_stage_start / on_stage_done (stage_name) — CLI progress display
      on_route (str)                             — one line per bus message
      on_message (dict)                          — full structured message

    `offline=True` skips the LLM tier entirely and scans with the deterministic
    engine only. `run_id` lets a caller (the FastAPI job manager) tie the run's
    salt and audit chain to its own job id.
    """
    try:
        with fetch_target(repo_path) as target:
            return _run_pipeline_on_local_path(
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
            )
    except RepoFetchError as exc:
        # Fetch failures (bad URL, missing git, clone timeout, nonexistent local
        # path) happen before any agent runs — surface as a PARTIAL result with
        # a report, same shape as any other stage failure, rather than letting
        # an unhandled exception crash the CLI/caller.
        from analyst.reporting.renderer import render_report

        ctx = SaltContext.generate(run_id=run_id)
        report_text_local = render_report([], repo_path, 0.0)
        Path(output_path).write_text(report_text_local, encoding="utf-8")
        bus, audit = _build_bus(ctx, on_message=on_message)
        _decide(bus, AgentID.ORCHESTRATOR, "FETCH_FAILED", str(exc))
        if on_route:
            on_route(f"ORCHESTRATOR: FETCH_FAILED — {exc}")
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


def _run_pipeline_on_local_path(
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
) -> PipelineResult:
    repo_path = local_path
    start_time = time.time()
    stage_errors: dict = {}
    fallbacks: list = []

    # --- one salt, one audit chain, one bus for the whole run ---
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
    audit.append(actor="ORCHESTRATOR", action="RUN_START", source=source, offline=offline)

    artifact_path = Path(artifact_dir) if artifact_dir else None
    if artifact_path:
        artifact_path.mkdir(parents=True, exist_ok=True)

    def on_fallback(outcome) -> None:
        """Every degradation becomes a visible, signed message — not a log line
        nobody reads."""
        fallbacks.append(outcome.as_payload())
        bus.send(
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

    def finish(
        status: str,
        report_text: str,
        confirmed: list,
        verify_results: list,
        escalated_count: int,
    ) -> PipelineResult:
        duration = time.time() - start_time
        audit.append(
            actor="ORCHESTRATOR",
            action="RUN_END",
            status=status,
            duration=round(duration, 3),
            findings=len(confirmed),
        )
        transcript_ok, transcript_note = bus.verify_transcript()
        if not transcript_ok:
            # Fail loudly: a run whose own message log does not verify cannot
            # vouch for its findings.
            stage_errors["INTEGRITY"] = transcript_note
            status = "PARTIAL"

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
            sidecar = write_verification_sidecar(
                report_file, ctx, audit=audit, extra={"target": source}
            )
            integrity["report_checksum_file"] = str(sidecar)
        if artifact_path:
            audit.write(artifact_path / "audit_log.json")
            integrity["audit_log_file"] = str(artifact_path / "audit_log.json")

        manual = sum(1 for r in verify_results if r.loop_status in HUMAN_ATTENTION_STATUSES)

        return PipelineResult(
            status=status,
            report_text=report_text,
            confirmed_count=sum(1 for f in confirmed if f.confirmed),
            rejected_count=sum(1 for f in confirmed if not f.confirmed),
            escalated_count=escalated_count,
            duration_seconds=duration,
            stage_errors=stage_errors,
            routing_log=routing_log,
            messages=bus.legacy_messages(),
            run_id=ctx.run_id,
            integrity=integrity,
            fallbacks=fallbacks,
            manual_review_count=manual,
            protocol_messages=list(bus.transcript),
        )

    def early_exit(status: str, error_key: Optional[str] = None, error_val: Optional[str] = None):
        from analyst.reporting.renderer import render_report

        report_text_local = render_report([], source, time.time() - start_time)
        Path(output_path).write_text(report_text_local, encoding="utf-8")
        if error_key:
            stage_errors[error_key] = error_val
        return finish(status, report_text_local, [], [], 0)

    # ---------------------------------------------------------------- INGEST
    if on_stage_start:
        on_stage_start("INGEST")
    ing = run_ingestion_agent(repo_path, salt_ctx=ctx)
    if artifact_path:
        (artifact_path / "ingestion_manifest.json").write_text(ing.result.manifest.to_json())
    _decide(
        bus,
        AgentID.INGEST,
        ing.decision,
        ing.reason,
        total_files=ing.total_files,
        parsed_files=ing.parsed_files,
        parse_ratio=round(ing.parse_ratio, 3),
        manifest_digest=ing.manifest_digest,
        integrity_ok=ing.integrity_ok,
    )
    if on_stage_done:
        on_stage_done("INGEST")

    if ing.decision == "INSUFFICIENT":
        # Decision OWNED by the Ingestion agent; the orchestrator respects it
        # rather than re-deriving it from a file count.
        _decide(
            bus,
            AgentID.ORCHESTRATOR,
            "SKIP_TO_REPORT",
            "Ingestion agent judged its own output insufficient.",
        )
        return early_exit("PARTIAL", "INGEST", ing.reason)

    _handoff(
        bus,
        AgentID.INGEST,
        AgentID.DETECT,
        stage="INGEST",
        summary=f"{ing.parsed_files}/{ing.total_files} files parsed, sealed at ingestion.",
        item_count=ing.total_files,
        state_digest=ing.manifest_digest,
        manifest_digest=ing.manifest_digest,
    )

    # ---------------------------------------------------------------- DETECT
    if on_stage_start:
        on_stage_start("DETECT")
    det = run_detection_agent(ing.result)
    candidate_payload = [c.to_dict() for c in det.candidates]
    if artifact_path:
        (artifact_path / "candidate_findings.json").write_text(
            json.dumps(candidate_payload, indent=2)
        )
    candidates_digest = ctx.seal(candidate_payload)
    _decide(
        bus,
        AgentID.DETECT,
        det.decision,
        det.reason,
        total_candidates=det.total_candidates,
        confidence_breakdown=det.confidence_breakdown,
        rule_families=det.rule_families,
        candidates_digest=candidates_digest,
    )
    if on_stage_done:
        on_stage_done("DETECT")

    if det.decision == "NONE_FOUND":
        _decide(
            bus,
            AgentID.ORCHESTRATOR,
            "SKIP_TO_REPORT",
            "Detection agent found nothing to escalate.",
        )
        return early_exit("OK")

    # --- A2A NEGOTIATION: only the Reasoning agent gets to decide whether a
    # thin candidate set is worth its budget. Previously this branch did not
    # exist and LOW_SIGNAL was escalated unconditionally.
    if det.decision == "LOW_SIGNAL":
        negotiation: AgentMessage = bus.request(
            sender=AgentID.ORCHESTRATOR,
            receiver=AgentID.REASON,
            message_type=MessageType.NEGOTIATION_REQUEST,
            payload=NegotiationRequest(
                proposal="ANALYSE_LOW_SIGNAL_SET",
                rationale=det.reason,
                context={
                    "candidate_count": det.total_candidates,
                    "high_confidence": det.confidence_breakdown.get("high", 0),
                    "llm_available": not offline,
                },
            ),
            expect=MessageType.NEGOTIATION_RESPONSE,
        )
        verdict: NegotiationResponse = negotiation.payload_as(NegotiationResponse)
        if not verdict.accepted:
            _decide(
                bus,
                AgentID.ORCHESTRATOR,
                "SKIP_TO_REPORT",
                f"Reasoning agent declined the low-signal set: {verdict.rationale}",
            )
            return early_exit("OK")

    _handoff(
        bus,
        AgentID.DETECT,
        AgentID.REASON,
        stage="DETECT",
        summary=f"{det.total_candidates} candidate(s) across {len(det.rule_families)} rule family/families.",
        item_count=det.total_candidates,
        state_digest=candidates_digest,
        manifest_digest=ing.manifest_digest,
    )

    # ------------------------------------------------- REASON / PATCH-VERIFY
    if on_stage_start:
        on_stage_start("REASON")
    verify_results: list = []

    def on_single_result(res):
        verify_results.append(res)
        if artifact_path:
            try:
                (artifact_path / "confirmed_findings.json").write_text(
                    json.dumps([r.to_dict() for r in verify_results], indent=2)
                )
            except Exception:
                pass
        if on_finding_verified:
            try:
                on_finding_verified(res.to_dict())
            except Exception:
                pass

    try:
        verify_results = run_patch_verify_loop(
            det.candidates,
            ing.result.sources,
            repo_path,
            bus=bus,
            on_fallback=on_fallback,
            offline=offline,
            on_result=on_single_result,
        )
        if artifact_path:
            (artifact_path / "confirmed_findings.json").write_text(
                json.dumps([r.to_dict() for r in verify_results], indent=2)
            )

        needs_human = [r for r in verify_results if r.loop_status in HUMAN_ATTENTION_STATUSES]
        retried = [r for r in verify_results if r.attempts > 1]
        accepted = [r for r in verify_results if r.loop_status == "ACCEPTED"]

        if dynamic:
            from analyst.reasoning.patch_loop import _make_sandbox_copy, apply_patch_to_text
            import shutil
            from analyst.protocol import CAP_EXPLOIT_VERIFY, ExploitVerifyRequestPayload, ExploitVerifyResultPayload

            for r in accepted:
                sandbox_root = _make_sandbox_copy(repo_path)
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
                    
                    response = bus.request_capability(
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
                    pass
                finally:
                    shutil.rmtree(sandbox_root, ignore_errors=True)

        _decide(
            bus,
            AgentID.REASON,
            "VERIFIED" if not needs_human else "PARTIALLY_VERIFIED",
            f"{len(accepted)} accepted, {len(retried)} retried, {len(needs_human)} "
            f"routed to manual review out of {len(verify_results)} candidate(s) processed.",
            accepted=len(accepted),
            manual_review=len(needs_human),
            tiers=sorted({r.finding.analysis_tier for r in verify_results}),
        )
    except Exception as exc:  # noqa: BLE001 - one bad agent run must not kill the pipeline
        stage_errors["REASON"] = str(exc)
        bus.report_error(AgentID.REASON, type(exc).__name__, str(exc))
    if on_stage_done:
        on_stage_done("REASON")

    # --------------------------------------------------------------- TRIAGE
    # (no CLI stage of its own: it is a bus exchange between REASON and REPORT)
    priorities = triage_agent.request_triage(bus, verify_results)

    # ---------------------------------------------------------------- REPORT
    if on_stage_start:
        on_stage_start("REPORT")
    confirmed = [r.finding for r in verify_results]
    duration = time.time() - start_time
    rep = run_reporting_agent(confirmed, source, duration, verify_results=verify_results, triage=priorities)
    Path(output_path).write_text(rep.report_text, encoding="utf-8")
    _decide(
        bus,
        AgentID.REPORT,
        rep.action,
        rep.reason,
        accepted=rep.accepted_count,
        escalated=rep.escalated_count,
        no_patch=rep.no_patch_count,
        report_digest=ctx.seal(rep.report_text),
    )
    if on_stage_done:
        on_stage_done("REPORT")

    status = "PARTIAL" if stage_errors else "OK"
    return finish(status, rep.report_text, confirmed, verify_results, rep.escalated_count)
