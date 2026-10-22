"""
Patch-Verify Agent Loop — propose -> act -> observe -> decide.

    1. PROPOSE  — ask the Reasoning engine for a patch (analyze_finding, which
                  now carries its own LLM fallback tiers)
    2. ACT      — apply that patch to a SANDBOXED temp copy of the file
                  (never the real source tree)
    3. OBSERVE  — ask the DETECTION AGENT, over the A2A bus, whether its rule
                  still fires against the patched copy
    4. DECIDE   — rule no longer fires            -> ACCEPT
                  rule still fires, attempts left -> RETRY with feedback
                  rule still fires, out of attempts -> MANUAL_REVIEW_REQUIRED

Design choices worth defending in Q&A:
- Sandboxing to a temp dir (not the real repo) is a deliberate safety boundary:
  an autonomous loop that edits source code must never touch the original files
  it is supposed to be protecting.
- Re-verification is performed by the Detection agent, not by this module. It
  used to be a direct `from analyst.detection.engine import run_detection`
  import here, which made Reasoning its own examiner. Now it is a signed
  PEER_VALIDATION_REQUEST/RESPONSE pair on the bus, so the verdict is
  attributable, correlated and in the audit chain. When no bus is supplied
  (unit tests, library use) it degrades to a direct in-process call to the same
  Detection capability — same authority, one less moving part.
- MAX_ATTEMPTS = 2 (1 initial + 1 retry) is a deliberately small, demo-safe
  bound: bounded retries prevent runaway API usage and infinite loops.

TERMINAL FALLBACK (requirement 3b)
----------------------------------
When the loop runs out of attempts the finding is NOT silently shipped with an
unverified patch, and it is NOT dropped. It becomes:

    loop_status         = "MANUAL_REVIEW_REQUIRED"
    finding.patch_diff  = None            (nothing unverified is offered as a fix)
    finding.explanation = safe default remediation guidance for the vuln class
    remediation_advice  = the same guidance, surfaced structurally for the report

`ESCALATED` is retained as an accepted legacy value so older artifacts and any
external consumer of confirmed_findings.json keep parsing; everything the
pipeline produces from now on uses MANUAL_REVIEW_REQUIRED.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Callable, Optional

from langchain_groq import ChatGroq

from analyst.detection.engine import CandidateFinding
from analyst.protocol import (
    CAP_RULE_RECHECK,
    AgentID,
    AgentMessage,
    MessageType,
    NegotiationRequest,
    NegotiationResponse,
    RuleRecheckRequest,
    RuleRecheckResponse,
)
from analyst.reasoning.confidence import PatchConfidence, evaluate_patch_confidence
from analyst.reasoning.engine import (
    MODEL,
    TIER_DETERMINISTIC,
    ConfirmedFinding,
    analyze_finding,
    build_client,
)
from analyst.reasoning.fallback import (
    CircuitBreaker,
    FallbackOutcome,
    manual_review_advice,
    manual_review_finding,
)

MAX_ATTEMPTS = 2  # 1 initial proposal + 1 retry

# Status constants and HUMAN_ATTENTION_STATUSES live in analyst.common.types;
# re-exported here so existing imports keep working.
from analyst.common.types import (  # noqa: E402,F401
    HUMAN_ATTENTION_STATUSES,
    STATUS_ACCEPTED,
    STATUS_ESCALATED,
    STATUS_MANUAL_REVIEW,
    STATUS_SKIPPED_NO_PATCH,
    STATUS_SKIPPED_NOT_CONFIRMED,
)


@dataclass
class PatchVerificationResult:
    finding: ConfirmedFinding
    loop_status: str
    attempts: int
    attempt_log: list  # list of dicts: {attempt, applied, rule_still_fires, note}
    confidence: Optional[PatchConfidence] = None
    remediation_advice: Optional[str] = None
    validation_messages: list = field(default_factory=list)  # correlation ids of A2A checks
    exploit_result: Optional[dict] = None

    def to_dict(self):
        d = self.finding.to_dict()  # scrubbed serialisation
        d["loop_status"] = self.loop_status
        d["verify_attempts"] = self.attempts
        d["attempt_log"] = self.attempt_log
        if self.confidence:
            d["confidence"] = self.confidence.to_dict()
        if self.remediation_advice:
            d["remediation_advice"] = self.remediation_advice
        if self.validation_messages:
            d["peer_validations"] = self.validation_messages
        if self.exploit_result:
            d["exploit_result"] = self.exploit_result
        return d


# ---------------------------------------------------------------------------
# Lenient diff application.
#
# The LLM returns unified-diff-*shaped* text (---/+++/@@/-/+ lines) but the
# @@ hunk headers have no real line offsets. A strict `patch`/`git apply` will
# reject these. Instead we do a content-based apply: pull the contiguous block
# of "-" lines out of each hunk, find that exact text in the target file, and
# replace it with the block of "+" lines.
# ---------------------------------------------------------------------------
class PatchApplyError(Exception):
    pass


def _parse_hunks(diff_text: str) -> list[tuple[list[str], list[str]]]:
    """Split a unified diff into hunks, each as (old_lines, new_lines),
    ignoring the --- / +++ file headers and @@ markers."""
    hunks: list[tuple[list[str], list[str]]] = []
    old_lines: list[str] = []
    new_lines: list[str] = []
    in_hunk = False

    for raw_line in diff_text.splitlines():
        if raw_line.startswith("--- ") or raw_line.startswith("+++ "):
            continue
        if raw_line.startswith("@@"):
            if in_hunk and (old_lines or new_lines):
                hunks.append((old_lines, new_lines))
            old_lines, new_lines = [], []
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if raw_line.startswith("-"):
            old_lines.append(raw_line[1:])
        elif raw_line.startswith("+"):
            new_lines.append(raw_line[1:])
        elif raw_line.startswith(" "):
            # context line — belongs to both old and new
            old_lines.append(raw_line[1:])
            new_lines.append(raw_line[1:])
        # blank/other lines inside a hunk are ignored defensively

    if in_hunk and (old_lines or new_lines):
        hunks.append((old_lines, new_lines))
    return hunks


def apply_patch_to_text(original_text: str, diff_text: str) -> str:
    """Apply an LLM-generated unified diff to source text using content-based
    matching rather than line offsets. Raises PatchApplyError if a hunk's
    old-text block can't be located."""
    hunks = _parse_hunks(diff_text)
    if not hunks:
        raise PatchApplyError("No applicable hunks found in patch_diff.")

    result = original_text
    for old_lines, new_lines in hunks:
        old_block = "\n".join(old_lines)
        new_block = "\n".join(new_lines)
        if not old_block.strip():
            # Pure-addition hunk with no anchor text — append is unsafe to
            # guess at; treat as unapplyable rather than silently guessing.
            raise PatchApplyError("Hunk has no context/removed lines to anchor on.")
        if old_block not in result:
            raise PatchApplyError(
                f"Could not locate expected text in file (patch may not match "
                f"current source):\n{old_block[:200]}"
            )
        result = result.replace(old_block, new_block, 1)
    return result


# ---------------------------------------------------------------------------
# Sandbox helpers
# ---------------------------------------------------------------------------
def _make_sandbox_copy(repo_path: str) -> Path:
    """Copy the target repo into a fresh temp dir. All patch attempts are
    applied here — the real source tree is never touched."""
    sandbox_root = Path(tempfile.mkdtemp(prefix="analyst_patch_sandbox_"))
    src = Path(repo_path)
    for item in src.iterdir():
        dest = sandbox_root / item.name
        if item.is_dir():
            if item.name in {".git", "venv", "__pycache__", ".venv", "node_modules", "sandbox"}:
                continue
            shutil.copytree(item, dest)
        else:
            shutil.copy2(item, dest)
    return sandbox_root


def _local_bus():
    """Minimal bus for callers that did not supply one (unit tests, library
    use). Wiring is the orchestrator's job, so it is imported lazily here to
    avoid a circular import and to keep Reasoning free of any Detection import."""
    from analyst.orchestrator.pipeline import _build_bus
    from analyst.protocol import SaltContext

    bus, _audit = _build_bus(SaltContext.generate(run_id="local-peer-validation"))
    return bus


def _request_peer_validation(
    bus,
    sandbox_root: Path,
    rel_file: str,
    rule_id: str,
    attempt: int,
) -> tuple[bool, str, Optional[str]]:
    """Ask whoever provides `rule.recheck` whether the rule still fires.

    Returns (still_fires, evidence, correlation_id). Peer validation ALWAYS
    travels over the bus. A caller that supplies no bus gets a private one
    wired by the orchestrator (`_local_bus`), so there is no code path that
    reaches the Detection agent except via CAP_RULE_RECHECK.
    """
    if bus is None:
        bus = _local_bus()

    response: AgentMessage = bus.request_capability(
        sender=AgentID.REASON,
        capability=CAP_RULE_RECHECK,
        message_type=MessageType.PEER_VALIDATION_REQUEST,
        payload=RuleRecheckRequest(
            rule_id=rule_id,
            file=rel_file,
            sandbox_root=str(sandbox_root),
            attempt=attempt,
        ),
        expect=MessageType.PEER_VALIDATION_RESPONSE,
    )
    body: RuleRecheckResponse = response.payload_as(RuleRecheckResponse)
    return body.still_fires, body.evidence, response.correlation_id


# ---------------------------------------------------------------------------
# Retry prompt — reuses analyze_finding's schema/model, but with feedback about
# the previous failed attempt appended so the LLM isn't asked the same question
# twice.
# ---------------------------------------------------------------------------
def _finding_with_retry_context(
    finding: CandidateFinding, previous_patch: str, failure_note: str
) -> CandidateFinding:
    retry_snippet = (
        f"{finding.snippet}\n\n"
        f"[RETRY CONTEXT — your previous patch did not resolve this finding]\n"
        f"Previous patch attempt:\n{previous_patch}\n"
        f"Verification result: {failure_note}\n"
        f"Propose a DIFFERENT patch that actually removes the vulnerable pattern."
    )
    return CandidateFinding(
        rule_id=finding.rule_id,
        vuln_class=finding.vuln_class,
        file=finding.file,
        line=finding.line,
        snippet=retry_snippet,
        confidence=finding.confidence,
        source_scanner=finding.source_scanner,
    )


# ---------------------------------------------------------------------------
# Main agent loop
# ---------------------------------------------------------------------------
def verify_and_patch(
    finding: CandidateFinding,
    repo_path: str,
    sources: dict,
    client: Optional[ChatGroq],
    bus=None,
    breaker: Optional[CircuitBreaker] = None,
    on_fallback: Optional[Callable[[FallbackOutcome], None]] = None,
) -> PatchVerificationResult:
    """Run the propose -> act -> observe -> decide loop for one finding."""
    attempt_log: list[dict] = []
    validation_ids: list[str] = []
    current_finding = finding
    confirmed: Optional[ConfirmedFinding] = None
    breaker = breaker if breaker is not None else CircuitBreaker()

    for attempt_num in range(1, MAX_ATTEMPTS + 1):
        source = sources.get(finding.file, b"")

        if client is None:
            # Offline / no-key mode: skip T0-T2 entirely and go straight to the
            # deterministic tier. Same object shape, so the rest of the loop —
            # sandbox, peer validation, confidence — is unchanged.
            from analyst.reasoning.fallback import deterministic_analysis

            outcome = FallbackOutcome(
                tier=TIER_DETERMINISTIC,
                trigger="NO_LLM_CLIENT",
                detail="No LLM client available; deterministic analysis only.",
            )
            if on_fallback and attempt_num == 1:
                on_fallback(outcome)
            confirmed = deterministic_analysis(current_finding, source, outcome)
        else:
            confirmed = analyze_finding(
                current_finding, source, client, breaker=breaker, on_fallback=on_fallback
            )

        if not confirmed.confirmed:
            return PatchVerificationResult(
                finding=confirmed,
                loop_status=STATUS_SKIPPED_NOT_CONFIRMED,
                attempts=attempt_num,
                attempt_log=attempt_log,
                validation_messages=validation_ids,
            )

        if not confirmed.patch_diff:
            # Confirmed but unpatchable: still a human task, so give them the
            # safe default guidance rather than an empty section.
            return PatchVerificationResult(
                finding=confirmed,
                loop_status=STATUS_SKIPPED_NO_PATCH,
                attempts=attempt_num,
                attempt_log=attempt_log,
                remediation_advice=manual_review_advice(confirmed.vuln_class),
                validation_messages=validation_ids,
            )

        # --- ACT: apply to sandbox ---
        sandbox_root = _make_sandbox_copy(repo_path)
        try:
            target_file = sandbox_root / finding.file
            original_text = target_file.read_text(encoding="utf-8")
            patched_text = None
            try:
                patched_text = apply_patch_to_text(original_text, confirmed.patch_diff)
                target_file.write_text(patched_text, encoding="utf-8")
                apply_ok = True
                apply_note = "Patch applied cleanly."
            except PatchApplyError as exc:
                apply_ok = False
                apply_note = f"Patch failed to apply: {exc}"

            # --- OBSERVE: ask the Detection agent, do not self-assess ---
            if apply_ok:
                still_fires, evidence, corr = _request_peer_validation(
                    bus, sandbox_root, finding.file, finding.rule_id, attempt_num
                )
                if corr:
                    validation_ids.append(corr)
                apply_note = f"{apply_note} {evidence}"
            else:
                still_fires = True  # unverifiable patch is treated as unresolved

            attempt_log.append(
                {
                    "attempt": attempt_num,
                    "applied": apply_ok,
                    "rule_still_fires": still_fires,
                    "note": apply_note,
                    "analysis_tier": confirmed.analysis_tier,
                }
            )

            # --- DECIDE ---
            conf = evaluate_patch_confidence(
                original_source=original_text,
                patched_source=patched_text if apply_ok else None,
                diff_text=confirmed.patch_diff,
                finding_line=finding.line,
                rule_still_fires=still_fires,
                patch_applied=apply_ok,
                file_path=finding.file,
            )

            if apply_ok and not still_fires and conf.tier != "unverified":
                return PatchVerificationResult(
                    finding=confirmed,
                    loop_status=STATUS_ACCEPTED,
                    attempts=attempt_num,
                    attempt_log=attempt_log,
                    confidence=conf,
                    validation_messages=validation_ids,
                )

            if attempt_num < MAX_ATTEMPTS:
                failure_note = (
                    apply_note
                    if not apply_ok
                    else f"Rule {finding.rule_id} still fires or patch unverified ({conf.reason})."
                )
                current_finding = _finding_with_retry_context(
                    finding, confirmed.patch_diff, failure_note
                )
                continue  # retry

            # --- T4: out of attempts -> manual human review ---
            reason = (
                f"patch could not be applied ({apply_note})"
                if not apply_ok
                else f"rule {finding.rule_id} still fires after the patch ({conf.reason})"
            )
            reviewed = manual_review_finding(confirmed, reason, attempt_num)
            return PatchVerificationResult(
                finding=reviewed,
                loop_status=STATUS_MANUAL_REVIEW,
                attempts=attempt_num,
                attempt_log=attempt_log,
                confidence=conf,
                remediation_advice=manual_review_advice(confirmed.vuln_class),
                validation_messages=validation_ids,
            )
        finally:
            shutil.rmtree(sandbox_root, ignore_errors=True)

    # Defensive fallback (should not be reachable given the loop above)
    return PatchVerificationResult(
        finding=manual_review_finding(confirmed or finding, "loop exited unexpectedly", MAX_ATTEMPTS),
        loop_status=STATUS_MANUAL_REVIEW,
        attempts=MAX_ATTEMPTS,
        attempt_log=attempt_log,
        remediation_advice=manual_review_advice(getattr(finding, "vuln_class", "Unknown")),
        validation_messages=validation_ids,
    )


def run_patch_verify_loop(
    findings: list[CandidateFinding],
    sources: dict,
    repo_path: str,
    api_key: Optional[str] = None,
    bus=None,
    on_fallback: Optional[Callable[[FallbackOutcome], None]] = None,
    breaker: Optional[CircuitBreaker] = None,
    offline: bool = False,
    on_result: Optional[Callable[[PatchVerificationResult], None]] = None,
) -> list[PatchVerificationResult]:
    """Entry point used by the orchestrator in place of run_reasoning.

    A missing API key no longer raises. It degrades to the deterministic tier
    and says so through `on_fallback`, because "scan anyway, tell me it was
    degraded" is strictly more useful than "refuse to scan".
    """
    client = None
    if not offline:
        key = api_key or os.environ.get("GROQ_API_KEY")
        if key:
            # Constructed HERE, in patch_loop's namespace, rather than via
            # engine.build_client(): the existing mocked tests patch
            # `analyst.reasoning.patch_loop.ChatGroq`, and that seam is worth
            # preserving. build_client() remains the entry point for callers
            # that use run_reasoning() directly.
            client = ChatGroq(model=MODEL, api_key=key, max_tokens=1500)
        elif on_fallback:
            on_fallback(
                FallbackOutcome(
                    tier=TIER_DETERMINISTIC,
                    trigger="NO_API_KEY",
                    detail=(
                        "GROQ_API_KEY is not set — running the deterministic local tier "
                        "for every finding. Set the key for LLM-backed confirmation."
                    ),
                )
            )

    breaker = breaker if breaker is not None else CircuitBreaker()

    results = []
    for finding in findings:
        res = verify_and_patch(
            finding,
            repo_path,
            sources,
            client,
            bus=bus,
            breaker=breaker,
            on_fallback=on_fallback,
        )
        results.append(res)
        if on_result:
            try:
                on_result(res)
            except Exception:
                pass
    return results


# ---------------------------------------------------------------------------
# Capability: the Reasoning agent's bus endpoint
# ---------------------------------------------------------------------------
def handle_message(msg: AgentMessage) -> Optional[AgentMessage]:
    """Reasoning agent endpoint.

    Currently answers NEGOTIATION_REQUEST: the orchestrator asks whether
    Reasoning is willing to spend LLM budget on a candidate set Detection
    flagged as LOW_SIGNAL. Reasoning owns that call because it is the agent
    that pays the cost — the orchestrator should not decide another agent's
    budget for it.
    """
    if msg.message_type != MessageType.NEGOTIATION_REQUEST:
        return None

    request = msg.payload_as(NegotiationRequest)
    context = request.context or {}
    candidate_count = int(context.get("candidate_count", 0))
    high_confidence = int(context.get("high_confidence", 0))
    llm_available = bool(context.get("llm_available", True))

    if candidate_count == 0:
        accepted, rationale, counter = (
            False,
            "Nothing to analyse — declining rather than burning a call on an empty set.",
            "SKIP_TO_REPORT",
        )
    elif high_confidence == 0 and candidate_count <= 2 and not llm_available:
        accepted, rationale, counter = (
            False,
            (
                "Low-signal candidate set AND no LLM tier available: deterministic analysis "
                "on 2 low-confidence candidates would produce noise, not findings."
            ),
            "REPORT_AS_LOW_SIGNAL",
        )
    else:
        accepted, rationale, counter = (
            True,
            (
                f"Accepting {candidate_count} candidate(s) "
                f"({high_confidence} high-confidence); within per-run budget."
            ),
            None,
        )

    return msg.reply(
        MessageType.NEGOTIATION_RESPONSE,
        NegotiationResponse(
            accepted=accepted,
            rationale=rationale,
            counter_proposal=counter,
            conditions=[] if accepted else ["flag_low_signal_in_report"],
        ),
        sender=AgentID.REASON,
    )
