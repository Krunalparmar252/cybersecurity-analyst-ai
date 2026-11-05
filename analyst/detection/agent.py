"""
Detection Agent — self-assessment DECIDE step on top of run_detection(), plus
the peer-validation endpoint it exposes to other agents.

    1. RUN      — call the existing run_detection() (untouched — the AST
                  taint-walk, XSS heuristic, and secrets regex are not redone)
    2. OBSERVE  — count, confidence mix, distinct rule families
    3. DECIDE   — WORTH_ESCALATING / LOW_SIGNAL / NONE_FOUND, with a reason

WHY THIS STAYS RULE-BASED (no LLM call):
"Is there enough signal here to justify the expensive Reasoning/Patch stage" is
countable (finding count, confidence labels already assigned by the rule
engine), not something that needs language understanding. The LLM budget is
reserved for Reasoning, where an actual semantic judgement is required.

A2A ADDITION — `rule.recheck`
-----------------------------
The Reasoning agent's patch loop needs to know "does this rule still fire after
my patch?". Previously it answered that itself by importing `run_detection` and
`ingest_repo` directly — which meant the Reasoning agent contained a private
copy of Detection's job, and the two could drift.

Detection now *publishes* that as a capability. Reasoning asks over the bus and
gets a signed PEER_VALIDATION_RESPONSE back. Two things this buys beyond tidy
layering:

  * The verdict is a signed, correlated message in the audit chain, so
    "the agent marked its own homework" is answerable with evidence.
  * Any future second opinion (a SAST binary, a second model) registers the
    same capability and Reasoning needs no change to consult it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from analyst.detection.adapters import get_available_adapters, merge_findings
from analyst.detection.engine import CandidateFinding, run_detection
from analyst.ingestion.manifest import IngestionResult, ingest_repo
from analyst.protocol import (
    AgentID,
    AgentMessage,
    MessageType,
    RuleRecheckRequest,
    RuleRecheckResponse,
)

# If every candidate is "low" confidence and there are very few of them,
# the agent flags this as low-signal rather than silently forwarding a
# thin, unreliable result set to the expensive Reasoning stage.
LOW_SIGNAL_MAX_COUNT = 2


@dataclass
class DetectionAgentResult:
    candidates: list  # list[CandidateFinding]
    decision: str  # "WORTH_ESCALATING" | "LOW_SIGNAL" | "NONE_FOUND"
    reason: str
    total_candidates: int
    confidence_breakdown: dict  # {"high": n, "medium": n, "low": n}
    rule_families: list  # distinct rule_ids that fired


def run_detection_agent(
    ingestion: IngestionResult,
    repo_path: Optional[str] = None,
    scanners: Optional[str] = None,
) -> DetectionAgentResult:
    """RUN -> OBSERVE -> DECIDE for the detection stage."""
    scanner_tokens = [
        s.strip().lower()
        for s in (scanners or "native,bandit,semgrep").split(",")
        if s.strip()
    ]

    # --- RUN (native engine + optional external adapters) ---
    candidates: list[CandidateFinding] = []
    if "native" in scanner_tokens:
        candidates = run_detection(ingestion)

    # Run available external adapters if target path is provided
    if repo_path:
        external_tokens = [s for s in scanner_tokens if s != "native"]
        if external_tokens:
            languages = list({f.language for f in ingestion.manifest.files if f.language})
            for adapter in get_available_adapters(external_tokens):
                ext_candidates = adapter.run(repo_path, languages=languages)
                if ext_candidates:
                    candidates = merge_findings(candidates, ext_candidates)

    # --- OBSERVE ---
    total = len(candidates)
    confidence_breakdown = {"high": 0, "medium": 0, "low": 0}
    for c in candidates:
        confidence_breakdown[c.confidence] = confidence_breakdown.get(c.confidence, 0) + 1
    rule_families = sorted({c.rule_id for c in candidates})

    # --- DECIDE ---
    if total == 0:
        decision = "NONE_FOUND"
        reason = "No candidate findings from any rule family — nothing to escalate."
    elif total <= LOW_SIGNAL_MAX_COUNT and confidence_breakdown["high"] == 0:
        decision = "LOW_SIGNAL"
        reason = (
            f"Only {total} candidate(s), none high-confidence — escalating "
            f"anyway but flagging as low-signal for the report."
        )
    else:
        decision = "WORTH_ESCALATING"
        reason = (
            f"{total} candidate(s) across {len(rule_families)} rule "
            f"family/families ({confidence_breakdown['high']} high-confidence) "
            f"— escalating to Reasoning/Patch agent."
        )

    return DetectionAgentResult(
        candidates=candidates,
        decision=decision,
        reason=reason,
        total_candidates=total,
        confidence_breakdown=confidence_breakdown,
        rule_families=rule_families,
    )


# ---------------------------------------------------------------------------
# Capability: rule.recheck
# ---------------------------------------------------------------------------
def recheck_rule(sandbox_root: str, rel_file: str, rule_id: str) -> tuple[bool, int]:
    """Re-run the REAL detection engine over a (patched) sandbox tree and report
    whether `rule_id` still fires for `rel_file`.

    Reusing run_detection rather than a bespoke check is deliberate: "did the
    patch fix it" must be answered by the same authority that found the bug.

    Returns (still_fires, total_candidates_seen).
    """
    ingestion = ingest_repo(str(sandbox_root))
    candidates = run_detection(ingestion)
    still_fires = any(c.rule_id == rule_id and c.file == rel_file for c in candidates)
    return still_fires, len(candidates)


def handle_message(msg: AgentMessage) -> Optional[AgentMessage]:
    """Bus endpoint for the Detection agent.

    Only PEER_VALIDATION_REQUEST carrying a rule_recheck payload is actionable;
    anything else is observed and ignored (returning None means "no reply",
    which the bus records as such rather than treating as an answer).
    """
    if msg.message_type != MessageType.PEER_VALIDATION_REQUEST:
        return None

    request = msg.payload_as(RuleRecheckRequest)
    try:
        still_fires, seen = recheck_rule(request.sandbox_root, request.file, request.rule_id)
    except Exception as exc:  # noqa: BLE001 — an unscannable sandbox is a verdict, not a crash
        return msg.reply(
            MessageType.PEER_VALIDATION_RESPONSE,
            RuleRecheckResponse(
                rule_id=request.rule_id,
                file=request.file,
                still_fires=True,  # fail CLOSED: unverifiable means unresolved
                verdict="INDETERMINATE",
                evidence=(
                    f"Re-scan of the patched sandbox failed ({type(exc).__name__}: {exc}). "
                    f"Treating the finding as unresolved rather than assuming success."
                ),
                candidates_seen=0,
            ),
            sender=AgentID.DETECT,
        )

    return msg.reply(
        MessageType.PEER_VALIDATION_RESPONSE,
        RuleRecheckResponse(
            rule_id=request.rule_id,
            file=request.file,
            still_fires=still_fires,
            verdict="STILL_VULNERABLE" if still_fires else "RESOLVED",
            evidence=(
                f"Attempt {request.attempt}: re-ran the full rule engine over the patched "
                f"sandbox; {seen} candidate(s) total, {request.rule_id} "
                f"{'still fires' if still_fires else 'no longer fires'} in {request.file}."
            ),
            candidates_seen=seen,
        ),
        sender=AgentID.DETECT,
    )
