"""Merge and deduplicate candidate findings from native and external scanners."""

from __future__ import annotations

from typing import Optional

from analyst.common.types import CandidateFinding


def _confidence_rank(conf: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(conf.lower(), 1)


def _rank_to_confidence(rank: int) -> str:
    if rank >= 3:
        return "high"
    if rank == 2:
        return "medium"
    return "low"


def merge_findings(
    primary_findings: list[CandidateFinding],
    external_findings: list[CandidateFinding],
) -> list[CandidateFinding]:
    """Merge findings from multiple scanners.

    Rules:
    - Findings on the same file, same vulnerability class, and lines within ±2 lines become ONE finding.
    - Native findings are kept as the primary finding.
    - Corroborating scanner names are recorded in `corroborated_by`.
    - Corroboration may raise confidence, but never lowers it.
    - Non-duplicate external findings are preserved as candidates.
    """
    merged: list[CandidateFinding] = list(primary_findings)

    for ext in external_findings:
        matched: Optional[CandidateFinding] = None
        for prim in merged:
            if prim.file == ext.file and prim.vuln_class == ext.vuln_class and abs(prim.line - ext.line) <= 2:
                matched = prim
                break

        if matched is not None:
            # Corroborate existing primary finding
            if ext.source_scanner and ext.source_scanner not in matched.corroborated_by:
                matched.corroborated_by.append(ext.source_scanner)

            # Corroboration may raise confidence
            prim_rank = _confidence_rank(matched.confidence)
            ext_rank = _confidence_rank(ext.confidence)
            # Raise confidence by 1 tier if corroborated, up to max(prim_rank, ext_rank, 2)
            new_rank = max(prim_rank, min(prim_rank + 1, 3), ext_rank)
            matched.confidence = _rank_to_confidence(new_rank)
        else:
            # New external finding with no native equivalent
            merged.append(ext)

    return merged

