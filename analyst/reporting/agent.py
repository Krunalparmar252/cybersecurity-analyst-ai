"""
Reporting Agent — adds a triage-synthesis DECIDE step on top of the
existing render_report() Markdown renderer.

Same pattern as the Ingestion/Detection agents:

    1. RUN      — call the existing render_report() (untouched — the
                  Markdown structure/formatting is not being redone)
    2. OBSERVE  — look at what Reasoning/Patch actually produced: how
                  many findings were auto-verified, escalated, or have
                  no patch at all
    3. DECIDE   — the agent buckets the overall scan into one recommended
                  ACTION for the human operator: AUTO_RESOLVED (agent
                  handled everything), REVIEW_REQUIRED (some findings
                  need a human), or CLEAN (nothing confirmed).

WHY THIS STAYS RULE-BASED (no LLM call):
This is a deterministic re-summarization of data the Reasoning agent
already produced (severity, loop_status). Spending a second LLM call to
re-derive a priority label from information already computed would be
redundant cost with no new judgement added — the semantic work already
happened in analyze_finding(); this step is bookkeeping over its output,
not new reasoning.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from analyst.common.redact import scrub_text
from analyst.common.types import HUMAN_ATTENTION_STATUSES, ConfirmedFinding
from analyst.reporting.renderer import render_report


@dataclass
class ReportingAgentResult:
    report_text: str
    action: str  # "CLEAN" | "AUTO_RESOLVED" | "REVIEW_REQUIRED"
    reason: str
    accepted_count: int
    escalated_count: int
    no_patch_count: int


def run_reporting_agent(
    confirmed: list[ConfirmedFinding],
    repo_path: str,
    scan_duration_seconds: float,
    verify_results: Optional[list] = None,
    triage: Optional[dict] = None,
    incremental_summary: Optional[str] = None,
) -> ReportingAgentResult:
    """RUN -> OBSERVE -> DECIDE for the reporting stage."""
    # --- RUN (delegates entirely to the existing, unmodified renderer) ---
    # Final guard: patch diffs quote the original line, so scrub the rendered
    # text before it is written, checksummed, or exported.
    report_text = scrub_text(
        render_report(
            confirmed,
            repo_path,
            scan_duration_seconds,
            verify_results=verify_results,
            triage=triage,
            incremental_summary=incremental_summary,
        )
    )

    # --- OBSERVE ---
    confirmed_true = [f for f in confirmed if f.confirmed]
    accepted = escalated = no_patch = 0
    degraded_tiers: set = set()
    if verify_results:
        accepted = sum(1 for r in verify_results if r.loop_status == "ACCEPTED")
        # MANUAL_REVIEW_REQUIRED is the current terminal label for "the agent
        # could not verify a fix"; ESCALATED is its legacy name, still counted
        # so artifacts written by older runs keep summarising correctly.
        escalated = sum(
            1 for r in verify_results if r.loop_status in HUMAN_ATTENTION_STATUSES
        )
        no_patch = sum(1 for r in verify_results if r.loop_status == "SKIPPED_NO_PATCH")
        degraded_tiers = {
            r.finding.analysis_tier
            for r in verify_results
            if getattr(r.finding, "analysis_tier", "T0_LLM") != "T0_LLM"
        }

    # --- DECIDE ---
    if not confirmed_true:
        action = "CLEAN"
        reason = "No confirmed vulnerabilities in this scan."
    elif escalated == 0 and no_patch == 0 and accepted > 0:
        action = "AUTO_RESOLVED"
        reason = (
            f"All {accepted} confirmed finding(s) had patches proposed and "
            f"verified by the agent loop — no human action required to merge."
        )
    else:
        action = "REVIEW_REQUIRED"
        reason = (
            f"{escalated} routed to manual review + {no_patch} without an auto-patch, "
            f"out of {len(confirmed_true)} confirmed finding(s) — needs human review "
            f"before merge."
        )

    if degraded_tiers:
        # Never let a degraded run read like a healthy one. The tier list goes in
        # the decision text itself, so it shows up in the CLI, the message bus
        # and the report header, not just in a log file.
        reason += (
            f" NOTE: this run was DEGRADED — findings were produced by fallback "
            f"tier(s) {sorted(degraded_tiers)} rather than full LLM reasoning."
        )

    return ReportingAgentResult(
        report_text=report_text,
        action=action,
        reason=reason,
        accepted_count=accepted,
        escalated_count=escalated,
        no_patch_count=no_patch,
    )
