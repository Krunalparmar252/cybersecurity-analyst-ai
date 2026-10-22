"""TRIAGE agent (capability `finding.triage`), between REASON and REPORT.

Given the confirmed findings (severity, whether REASON produced a verified
fix), it assigns a fix priority P1..P4 and a unique rank (1 = fix first).

Scoring is DETERMINISTIC and is the default and the fallback:

    base     CRITICAL 4, HIGH 3, MEDIUM 2, LOW 1, unknown 1
    +1       when there is no verified fix (loop status needs human attention,
             or no patch was produced): nothing is ready to merge
    score    5 -> P1, 4 -> P2, 3 -> P3, <=2 -> P4

A verified fix ready to merge is lower urgency than an open problem of the same
severity, which is the only thing this agent adds over sorting by severity.

`scorer` is an optional seam (callable(items) -> list of dicts with index,
priority, rationale) for a model-based scorer. None is wired in: this agent
makes no LLM call today. If a scorer is supplied and raises, or returns
anything that is not exactly one valid verdict per item, the deterministic
scorer is used and the response says so in `method` / `fallback_reason`.
"""

from __future__ import annotations

from typing import Callable, Optional

from analyst.protocol import (
    CAP_FINDING_TRIAGE,
    AgentID,
    AgentMessage,
    DecisionPayload,
    MessageType,
    TriageItem,
    TriageRequest,
    TriageResponse,
    TriageVerdict,
)

PRIORITIES = ("P1", "P2", "P3", "P4")
_BASE = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

Scorer = Callable[[list[TriageItem]], list[dict]]


def _score(item: TriageItem) -> tuple[int, str]:
    base = _BASE.get((item.severity or "").upper(), 1)
    no_fix = item.loop_status != "ACCEPTED"  # manual review, no patch, or unknown
    score = base + (1 if no_fix else 0)
    why = f"{(item.severity or 'unrated').lower()} severity; " + (
        "no verified fix available" if no_fix else "verified fix ready to merge"
    )
    return score, why


def _priority(score: int) -> str:
    return "P1" if score >= 5 else "P2" if score == 4 else "P3" if score == 3 else "P4"


def deterministic_triage(items: list[TriageItem]) -> list[TriageVerdict]:
    scored = []
    for it in items:
        score, why = _score(it)
        scored.append((it, score, why))
    # Highest score first; ties broken by severity, then file, line, index: fully deterministic.
    order = sorted(
        scored,
        key=lambda t: (-t[1], _SEV_ORDER.get((t[0].severity or "").upper(), 4), t[0].file, t[0].line, t[0].index),
    )
    rank = {t[0].index: n for n, t in enumerate(order, start=1)}
    return [
        TriageVerdict(index=it.index, priority=_priority(score), rank=rank[it.index], rationale=why)
        for it, score, why in scored
    ]


def _valid(items: list[TriageItem], raw) -> Optional[list[TriageVerdict]]:
    """Accept scorer output only if it is exactly one well-formed verdict per item."""
    try:
        if len(raw) != len(items) or {r["index"] for r in raw} != {i.index for i in items}:
            return None
        if any(r["priority"] not in PRIORITIES or not str(r.get("rationale", "")).strip() for r in raw):
            return None
        ordered = sorted(raw, key=lambda r: (r["priority"], r["index"]))
        rank = {r["index"]: n for n, r in enumerate(ordered, start=1)}
        by_index = {r["index"]: r for r in raw}
        return [
            TriageVerdict(index=i.index, priority=by_index[i.index]["priority"],
                          rank=rank[i.index], rationale=str(by_index[i.index]["rationale"]))
            for i in items
        ]
    except Exception:  # noqa: BLE001 - malformed scorer output is a fallback trigger, not a crash
        return None


def triage_items(items: list[TriageItem], scorer: Optional[Scorer] = None):
    """Returns (verdicts, method, fallback_reason)."""
    if scorer is None:
        return deterministic_triage(items), "deterministic", None
    try:
        raw = scorer(items)
    except Exception as exc:  # noqa: BLE001
        return deterministic_triage(items), "deterministic_fallback", f"scorer raised {type(exc).__name__}: {exc}"
    verdicts = _valid(items, raw)
    if verdicts is None:
        return deterministic_triage(items), "deterministic_fallback", "scorer returned invalid or incomplete verdicts"
    return verdicts, "scorer", None


def make_handler(scorer: Optional[Scorer] = None):
    def handle_message(msg: AgentMessage) -> Optional[AgentMessage]:
        if msg.message_type != MessageType.TRIAGE_REQUEST:
            return None
        items = msg.payload_as(TriageRequest).items
        verdicts, method, reason = triage_items(items, scorer)
        counts = {p: sum(1 for v in verdicts if v.priority == p) for p in PRIORITIES}
        summary = ", ".join(f"{p}: {n}" for p, n in counts.items() if n) or "no findings to triage"
        return msg.reply(
            MessageType.TRIAGE_RESPONSE,
            TriageResponse(verdicts=verdicts, method=method, fallback_reason=reason, summary=summary),
            sender=AgentID.TRIAGE,
        )

    return handle_message


handle_message = make_handler()


# ---------------------------------------------------------------------------
# Orchestrator side (shared by pipeline.py and graph.py)
# ---------------------------------------------------------------------------
def request_triage(bus, verify_results: list) -> dict:
    """Ask whoever provides `finding.triage` to prioritise confirmed findings.

    Returns {(rule_id, file, line): {"priority", "rank", "rationale"}}. On any
    failure (no provider, bus error) returns {} and the report simply renders
    without priorities: triage must never be able to fail a scan.
    """
    results = [r for r in verify_results if r.finding.confirmed]
    if not results:
        return {}
    items = [
        TriageItem(
            index=n, rule_id=r.finding.rule_id, vuln_class=r.finding.vuln_class,
            file=r.finding.file, line=r.finding.line, severity=r.finding.severity,
            loop_status=r.loop_status, analysis_tier=r.finding.analysis_tier,
        )
        for n, r in enumerate(results)
    ]
    try:
        response = bus.request_capability(
            sender=AgentID.ORCHESTRATOR,
            capability=CAP_FINDING_TRIAGE,
            message_type=MessageType.TRIAGE_REQUEST,
            payload=TriageRequest(items=items),
            expect=MessageType.TRIAGE_RESPONSE,
        )
        body = response.payload_as(TriageResponse)
    except Exception as exc:  # noqa: BLE001
        bus.report_error(AgentID.TRIAGE, type(exc).__name__, f"triage unavailable: {exc}")
        return {}
    bus.send(
        sender=AgentID.TRIAGE,
        receiver=AgentID.ORCHESTRATOR,
        message_type=MessageType.DECISION,
        payload=DecisionPayload(
            decision="TRIAGED" if body.method != "deterministic_fallback" else "TRIAGED_FALLBACK",
            reason=f"{body.summary} ({body.method})",
            metrics={"findings": len(items), "method": body.method},
        ),
    )
    by_index = {v.index: v for v in body.verdicts}
    return {
        (r.finding.rule_id, r.finding.file, r.finding.line): {
            "priority": by_index[n].priority, "rank": by_index[n].rank, "rationale": by_index[n].rationale,
        }
        for n, r in enumerate(results) if n in by_index
    }
