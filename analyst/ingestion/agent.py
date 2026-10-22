"""
Ingestion Agent — adds a self-assessment DECIDE step on top of the
existing ingest_repo() parser.

RE-EXAMINATION CONTEXT:
Mid-1's ingestion stage was pure data transformation: walk the repo,
parse what you can, hand the manifest to whoever's next. It never
evaluated its own output. This module gives it the same shape as
patch_loop.py's agent (observe -> decide), scoped to what Ingestion can
actually judge about itself:

    1. RUN      — call the existing ingest_repo() (untouched — the
                  parsing/hashing/tree-sitter logic is not being redone)
    2. OBSERVE  — compute structural facts about the manifest: parse
                  ratio, language coverage, file count
    3. DECIDE   — the agent classifies its own output as SUFFICIENT or
                  INSUFFICIENT for the pipeline to continue, and produces
                  a short human-readable reason. This decision is what
                  the orchestrator now consults instead of re-deriving
                  the same judgement itself.

WHY THIS STAYS RULE-BASED (no LLM call):
"Did enough files parse to proceed" is a structural/countable fact, not
a judgement requiring language understanding. Spending a Groq call here
would be a worse engineering decision, not a more agentic one -- the
autonomy that matters is that the AGENT decides and the orchestrator
acts on that decision, not which underlying compute produced it. Compare
to patch_loop.py, where "does this patch semantically fix the bug" does
require judgement an LLM can make and a rule-based check can't -- that's
the actual dividing line for where LLM calls belong in this system, and
it's worth stating plainly if asked.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from pathlib import PurePosixPath

from analyst.ingestion.manifest import LANGUAGE_BY_EXTENSION, IngestionResult, ingest_repo

# Below this parse ratio, the agent judges itself INSUFFICIENT even if
# some files parsed -- a repo that's 90% unparseable isn't a reliable
# basis for the rest of the pipeline to reason about.
MIN_PARSE_RATIO = 0.2


@dataclass
class IngestionAgentResult:
    result: IngestionResult
    decision: str  # "SUFFICIENT" | "INSUFFICIENT"
    reason: str
    total_files: int
    parsed_files: int
    parse_ratio: float
    languages_seen: list
    manifest_digest: str = ""
    integrity_ok: bool = True


def _unsupported_language_reason(result: IngestionResult) -> str:
    """
    Build a diagnostic tail for the zero-parsed case: what extensions were
    actually present vs. what the pipeline currently supports. This is a
    pure OBSERVE-layer add -- it doesn't change the SUFFICIENT/INSUFFICIENT
    decision, only makes the reason string actionable instead of opaque.
    """
    ext_counts = Counter(
        PurePosixPath(f.path).suffix.lower() or "(no extension)"
        for f in result.manifest.files
    )
    found = ", ".join(f"{ext} x{n}" for ext, n in ext_counts.most_common())
    supported = ", ".join(sorted(LANGUAGE_BY_EXTENSION)) or "none configured"
    return f"Found extensions: {found or 'none'}. Pipeline currently supports: {supported}."


def run_ingestion_agent(repo_path: str, salt_ctx=None) -> IngestionAgentResult:
    """RUN -> OBSERVE -> DECIDE for the ingestion stage.

    `salt_ctx` is the run's SaltContext. Ingestion is where the chain of custody
    starts: every file it reads is sealed here, and every later agent's claim
    about "the code" is a claim about these digests.
    """
    # --- RUN (delegates entirely to the existing, unmodified parser) ---
    result = ingest_repo(repo_path, salt_ctx=salt_ctx)

    # --- OBSERVE ---
    total = len(result.manifest.files)
    parsed = sum(1 for f in result.manifest.files if f.parsed)
    ratio = (parsed / total) if total else 0.0
    languages = sorted({f.language for f in result.manifest.files if f.language})

    # Self-check: the agent verifies the manifest it just sealed before handing
    # it on. Cheap, and it catches a whole class of bug (a mutation between
    # sealing and handoff) at the point where it is still diagnosable.
    integrity_ok, integrity_note = result.manifest.verify(result.salt_ctx)

    # --- DECIDE ---
    if not integrity_ok and total > 0:
        # Fail CLOSED. If the manifest cannot be trusted, nothing built on it
        # can be either — better to stop than to publish a report over data of
        # unknown provenance.
        decision = "INSUFFICIENT"
        reason = f"Manifest integrity check failed: {integrity_note}"
    elif total == 0:
        decision = "INSUFFICIENT"
        reason = "No files found under the target path."
    elif parsed == 0:
        decision = "INSUFFICIENT"
        reason = f"{total} file(s) found but none parsed successfully. {_unsupported_language_reason(result)}"
    elif ratio < MIN_PARSE_RATIO:
        decision = "INSUFFICIENT"
        reason = (
            f"Only {parsed}/{total} files parsed ({ratio:.0%}) -- below the "
            f"{MIN_PARSE_RATIO:.0%} confidence threshold to proceed with analysis."
        )
    else:
        decision = "SUFFICIENT"
        reason = f"{parsed}/{total} files parsed ({ratio:.0%}); proceeding to Detection."

    return IngestionAgentResult(
        result=result,
        decision=decision,
        reason=reason,
        total_files=total,
        parsed_files=parsed,
        parse_ratio=ratio,
        languages_seen=languages,
        manifest_digest=result.manifest.manifest_digest or "",
        integrity_ok=integrity_ok,
    )
