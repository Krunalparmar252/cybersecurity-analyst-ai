"""Cross-agent shared types.

Lives outside reasoning/ so Reporting and the orchestrator can depend on the
data contract without importing the Reasoning agent's implementation. Old
import paths (analyst.reasoning.engine / analyst.reasoning.patch_loop) still
work via re-exports.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

from analyst.common.redact import scrub_text

# Tier labels recorded on every ConfirmedFinding so the report can state how
# each conclusion was reached.
TIER_LLM = "T0_LLM"
TIER_RETRY = "T1_LLM_RETRY"
TIER_DETERMINISTIC = "T3_DETERMINISTIC"

# Patch-verification loop statuses.
STATUS_ACCEPTED = "ACCEPTED"
STATUS_MANUAL_REVIEW = "MANUAL_REVIEW_REQUIRED"
STATUS_ESCALATED = "ESCALATED"  # legacy alias, still recognised by consumers
STATUS_SKIPPED_NOT_CONFIRMED = "SKIPPED_NOT_CONFIRMED"
STATUS_SKIPPED_NO_PATCH = "SKIPPED_NO_PATCH"

# Statuses that mean "a human has to look at this".
HUMAN_ATTENTION_STATUSES = frozenset({STATUS_MANUAL_REVIEW, STATUS_ESCALATED})


@dataclass
class CandidateFinding:
    rule_id: str
    vuln_class: str
    file: str
    line: int  # 1-indexed, matches ground_truth.json convention
    snippet: str
    confidence: str  # high | medium | low
    source_scanner: str  # "static" | "secrets"
    # C-3: set by incremental scan logic. "rescanned" = analysed fresh this run;
    # "carried_forward" = pulled from a previous scan's cache unchanged.
    # Defaults to "rescanned" so all existing callers need no changes.
    scan_mode: str = "rescanned"
    # C-4: set by incremental scan logic when the finding was already patched and
    # verified (loop_status=="ACCEPTED") in the previous run's cache. When True,
    # run_patch_verify_loop skips REASON/EXPLOIT entirely and synthesises a result
    # from the cached data — this is the actual LLM-call-saving payoff of C-4.
    already_resolved: bool = False
    # The patch_diff from the previous run (only meaningful when already_resolved=True).
    cached_patch_diff: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ConfirmedFinding:
    rule_id: str
    vuln_class: str
    file: str
    line: int
    confirmed: bool
    confirmation_reasoning: str
    severity: Optional[str] = None
    explanation: Optional[str] = None
    patch_diff: Optional[str] = None
    # Provenance: which tier produced this conclusion (LLM vs regex fallback).
    analysis_tier: str = TIER_LLM
    fallback_trigger: Optional[str] = None

    def to_dict(self):
        """Serialisable form for artifacts/API. Free-text fields are scrubbed
        because a patch diff quotes the original (secret-bearing) line."""
        d = asdict(self)
        for k in ("patch_diff", "explanation", "confirmation_reasoning"):
            if d.get(k):
                d[k] = scrub_text(d[k])
        return d


__all__ = [
    "TIER_LLM", "TIER_RETRY", "TIER_DETERMINISTIC",
    "STATUS_ACCEPTED", "STATUS_MANUAL_REVIEW", "STATUS_ESCALATED",
    "STATUS_SKIPPED_NOT_CONFIRMED", "STATUS_SKIPPED_NO_PATCH",
    "HUMAN_ATTENTION_STATUSES", "CandidateFinding", "ConfirmedFinding",
]
