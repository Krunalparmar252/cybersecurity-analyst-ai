"""
Reporting Module — deterministic rendering of confirmed findings to Markdown.

Mid-1 scope: Markdown only (the "canonical" format per architecture.md §2.4).
HTML/PDF conversion is a Phase 4/7 polish step, not needed for the
presentation itself — a clean .md renders fine in any viewer/editor.

Re-examination addition: render_report now optionally accepts the
PatchVerificationResult list (loop_status/attempts/attempt_log per
finding) so the report visibly distinguishes findings whose patch was
verified by the agent loop (ACCEPTED) from ones it could not verify and
handed to a human (ESCALATED). Without this, the report would look
identical whether or not any agentic verification happened, which
undercuts the whole point of the loop in front of evaluators.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from analyst.common.types import ConfirmedFinding

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, None: 4}

_STATUS_LABEL = {
    "ACCEPTED": "✅ Patch verified by agent loop",
    "MANUAL_REVIEW_REQUIRED": "🚩 MANUAL HUMAN REVIEW REQUIRED — the agent could not verify a fix",
    "ESCALATED": "🚩 Escalated — agent could not verify a fix, needs human review",
    "SKIPPED_NOT_CONFIRMED": None,  # not shown, these are false positives
    "SKIPPED_NO_PATCH": "⚠️ No patch proposed — manual fix required",
}

# Statuses meaning a human has to act. Kept local (rather than imported from
# patch_loop) so the renderer stays importable without the reasoning stack —
# several tests render reports without ever constructing an LLM client.
_NEEDS_HUMAN = ("MANUAL_REVIEW_REQUIRED", "ESCALATED")

# How a finding's conclusion was reached. Shown only when it was NOT full LLM
# reasoning, so a degraded run is impossible to mistake for a healthy one.
_TIER_LABEL = {
    "T1_LLM_RETRY": "LLM (recovered after transient failure)",
    "T3_DETERMINISTIC": "deterministic local rules — LLM unavailable",
    "T4_MANUAL_REVIEW": "unresolved by automation",
}


def render_report(
    confirmed: list[ConfirmedFinding],
    repo_path: str,
    scan_duration_seconds: float,
    verify_results: Optional[list] = None,
    triage: Optional[dict] = None,
    incremental_summary: Optional[str] = None,
) -> str:
    confirmed_true = [f for f in confirmed if f.confirmed]
    rejected = [f for f in confirmed if not f.confirmed]

    triage = triage or {}
    # With triage, fix-first order (rank); without it, the original severity order.
    confirmed_true.sort(
        key=lambda f: (
            triage.get((f.rule_id, f.file, f.line), {}).get("rank", 0),
            _SEVERITY_ORDER.get(f.severity),
            f.file,
        )
    )

    # Map rule_id+file -> PatchVerificationResult for status/attempt lookup.
    # Falls back gracefully to "no loop data" when verify_results isn't
    # passed (keeps the renderer usable/testable without the full loop).
    status_by_key = {}
    if verify_results:
        for r in verify_results:
            status_by_key[(r.finding.rule_id, r.finding.file, r.finding.line)] = r

    lines: list[str] = []
    lines.append("# Autonomous Cybersecurity Analyst AI — Scan Report")
    lines.append("")
    lines.append(f"**Target:** `{repo_path}`  ")
    lines.append(f"**Scan time:** {datetime.now(timezone.utc).isoformat(timespec='seconds')}Z  ")
    lines.append(f"**Duration:** {scan_duration_seconds:.1f}s")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    if incremental_summary:
        lines.append(f"- **Incremental scan:** {incremental_summary}")
    lines.append(f"- **Confirmed findings:** {len(confirmed_true)}")
    lines.append(f"- **Candidates rejected as false positives:** {len(rejected)}")
    if verify_results:
        n_accepted = sum(1 for r in verify_results if r.loop_status == "ACCEPTED")
        n_escalated = sum(1 for r in verify_results if r.loop_status in _NEEDS_HUMAN)
        lines.append(f"- **Patches auto-verified by agent loop:** {n_accepted}")
        
        # B-5 aggregate line
        n_exploit_verified = sum(
            1 for r in verify_results 
            if getattr(r, "exploit_result", None) and r.exploit_result.get("verdict") == "CONFIRMED_VULNERABLE_THEN_FIXED"
        )
        n_static_only = sum(
            1 for r in verify_results
            if getattr(r, "exploit_result", None) and r.exploit_result.get("verdict") == "STATIC_CHECK_ONLY"
        )
        has_exploit_results = any(getattr(r, "exploit_result", None) is not None for r in verify_results)
        if has_exploit_results:
            lines.append(f"  - _(of which {n_exploit_verified}/{n_accepted} findings verified by exploit vs {n_static_only} static-only)_")
            
        lines.append(f"- **Requiring manual human review:** {n_escalated}")
        degraded = sorted(
            {
                getattr(r.finding, "analysis_tier", "T0_LLM")
                for r in verify_results
                if getattr(r.finding, "analysis_tier", "T0_LLM") != "T0_LLM"
            }
        )
        if degraded:
            lines.append("")
            lines.append(
                "> **Degraded run.** One or more findings were analysed by a fallback "
                "tier rather than full LLM reasoning "
                f"({', '.join(_TIER_LABEL.get(t, t) for t in degraded)}). "
                "Severity and remediation below are correspondingly less precise."
            )
    by_severity = {}
    for f in confirmed_true:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev in by_severity:
            lines.append(f"  - {sev}: {by_severity[sev]}")
    lines.append("")

    # Per-finding sections
    lines.append("## Findings")
    lines.append("")
    if not confirmed_true:
        lines.append("_No confirmed findings._")
    for i, f in enumerate(confirmed_true, start=1):
        lines.append(f"### {i}. [{f.severity}] {f.vuln_class} — `{f.file}:{f.line}`")
        lines.append("")
        lines.append(f"**Rule:** `{f.rule_id}`")
        lines.append("")
        tv = triage.get((f.rule_id, f.file, f.line))
        if tv:
            lines.append(f"**Fix priority:** {tv['priority']} — {tv['rationale']}")
            lines.append("")

        vr = status_by_key.get((f.rule_id, f.file, f.line))
        if vr:
            label = _STATUS_LABEL.get(vr.loop_status)
            if label:
                lines.append(f"**Verification status:** {label}  (attempts: {vr.attempts})")
                lines.append("")

        tier = getattr(f, "analysis_tier", "T0_LLM")
        if tier != "T0_LLM":
            lines.append(f"**Analysis tier:** {_TIER_LABEL.get(tier, tier)}")
            lines.append("")

        if vr and getattr(vr, "exploit_result", None):
            ev = vr.exploit_result
            lines.append(f"**Exploit Verification:** {ev.get('verdict')} (took {ev.get('elapsed_seconds', 0):.1f}s, {ev.get('tool_calls_used', 0)} tool calls)")
            if ev.get('evidence'):
                lines.append(f"> {ev.get('evidence')}")
            lines.append("")

        lines.append(f"**Why this was confirmed:** {f.confirmation_reasoning}")
        lines.append("")
        if f.explanation:
            lines.append(f"**Explanation:** {f.explanation}")
            lines.append("")
        if f.patch_diff:
            lines.append("**Suggested patch:**")
            lines.append("```diff")
            lines.append(f.patch_diff)
            lines.append("```")
        else:
            lines.append("_No automated patch generated — manual review required._")
            advice = getattr(vr, "remediation_advice", None) if vr else None
            if advice:
                lines.append("")
                lines.append(f"**Safe default remediation:** {advice}")

        if vr and vr.attempt_log:
            lines.append("")
            lines.append("<details><summary>Agent verification log</summary>")
            lines.append("")
            for entry in vr.attempt_log:
                lines.append(
                    f"- Attempt {entry['attempt']}: applied={entry['applied']}, "
                    f"still_fires={entry['rule_still_fires']} — {entry['note']}"
                )
            lines.append("")
            lines.append("</details>")
        lines.append("")

    # Appendix
    lines.append("## Appendix — Rejected Candidates (False Positives)")
    lines.append("")
    if not rejected:
        lines.append("_None._")
    for f in rejected:
        lines.append(f"- `{f.rule_id}` at `{f.file}:{f.line}` — {f.confirmation_reasoning}")

    return "\n".join(lines)
