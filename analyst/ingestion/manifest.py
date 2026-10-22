"""
Ingestion Module — turns an arbitrary local repo into a structured manifest.

Scope for Mid-1 (see DOc/phases.md Phase 1):
- RepoFetcher: local path only (no git clone yet — that's a Phase 1 stretch goal)
- LanguageDetector: extension-based, Python-first
- ASTBuilder: tree-sitter parsing, Python grammar only for now
- FileIndex: flat file list with metadata, used by the secrets scanner

Deliberately NOT built yet (per architecture.md, deferred to later phases):
- SymbolMapper's full route/DB/auth maps — we do a *minimal* version inline
  here (just enough for the 3 demo vulnerability classes) rather than the
  full generalized symbol mapper described in architecture.md §2.1
- JS/TS grammar support
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from tree_sitter_languages import get_parser

from analyst.common.parallel import parallel_chunks
from analyst.protocol.crypto import SaltContext, manifest_digest

# Extensions we currently understand. Anything else falls back to
# "unparsed" and detection will skip AST-based rules for that file
# (regex-based rules can still run — see detection/engine.py).
LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
}

# Files/dirs we never want to walk into.
IGNORED_DIR_NAMES = {".git", "venv", "__pycache__", "node_modules", ".venv", "sandbox"}


@dataclass
class FileEntry:
    path: str  # relative to repo root, forward-slash normalized
    language: Optional[str]
    size_bytes: int
    sha256: str
    parsed: bool
    parse_error: Optional[str] = None
    # Salted, tagged digest of the same bytes: "v1:<mode>:<epoch>:<hex>".
    # `sha256` above is retained for interoperability with external tools that
    # expect a plain content hash; `salted_digest` is the value the pipeline
    # actually trusts, because it is only reproducible by a holder of this
    # run's salt. See analyst/protocol/crypto.py for why the bare hash is not
    # sufficient for state that crosses agent boundaries.
    salted_digest: Optional[str] = None


@dataclass
class IngestionManifest:
    repo_root: str
    files: list[FileEntry] = field(default_factory=list)
    # Single digest over every file's salted digest — one value that changes if
    # any file is added, removed or altered. This is what downstream agents put
    # in their StateHandoff payloads so a swapped manifest is detectable.
    manifest_digest: Optional[str] = None
    # Non-secret salt metadata (mode, epoch, fingerprint) so a verifier knows
    # which construction produced the digests above.
    salt: Optional[dict] = None
    # file path -> tree-sitter Tree object is kept OUT of the JSON-serializable
    # manifest (trees aren't JSON-serializable and shouldn't leave this stage).
    # Detection reads asts via IngestionResult.asts, not via this dataclass.

    def to_json(self) -> str:
        return json.dumps(
            {
                "repo_root": self.repo_root,
                "manifest_digest": self.manifest_digest,
                "salt": self.salt,
                "files": [asdict(f) for f in self.files],
            },
            indent=2,
        )

    def verify(self, ctx: SaltContext) -> tuple[bool, str]:
        """Recompute the manifest digest from the per-file digests and compare.

        Detects: a file entry added or removed after ingestion, a digest edited
        in the artifact, or a manifest carried over from a different run (whose
        digests were sealed under a different salt)."""
        entries = [f"{f.path}:{f.salted_digest}" for f in self.files]
        if not self.manifest_digest:
            return False, "Manifest carries no digest — it was not sealed at ingestion."
        if ctx.verify(sorted(entries), self.manifest_digest):
            return True, f"Manifest digest verified over {len(self.files)} file(s)."
        return False, (
            "Manifest digest MISMATCH — the file list or a per-file digest changed "
            "after ingestion sealed it, or this manifest belongs to another run."
        )


@dataclass
class IngestionResult:
    manifest: IngestionManifest
    # relative path -> parsed tree-sitter Tree (only for files that parsed OK)
    asts: dict
    # relative path -> raw source bytes (needed by detection for regex fallback
    # and by reasoning for context-window extraction)
    sources: dict
    # The salt this result was sealed with. Travels with the data so any
    # downstream agent can verify the manifest without reaching for a global.
    salt_ctx: Optional[SaltContext] = None


def _sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _detect_language(path: Path) -> Optional[str]:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower())


def ingest_repo(
    repo_path: str, salt_ctx: Optional[SaltContext] = None, workers: Optional[int] = None
) -> IngestionResult:
    """
    Walk repo_path, parse every recognized source file with tree-sitter,
    and return a structured IngestionResult.

    Per-file parse failures do NOT halt the pipeline (architecture.md §2.1
    'Failure handling') — the file is recorded with parsed=False and the
    error message, and detection will fall back to regex-only for it.

    `salt_ctx` is the run's salt. Pass the orchestrator's context so every
    artifact in a run seals under one salt; omit it (library/test use, or the
    patch loop's sandbox re-scan) and a throwaway context is generated, which
    is correct because those digests are never compared across runs.

    `workers` = thread count for per-file work (None = auto, 1 = sequential).
    Output is identical for every value.
    """
    ctx = salt_ctx or SaltContext.generate()
    root = Path(repo_path).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target repository path does not exist: {root}")

    paths = [
        fp for fp in sorted(root.rglob("*"))
        if fp.is_file() and not any(part in IGNORED_DIR_NAMES for part in fp.parts)
    ]

    def _ingest_chunk(chunk):
        # One parser cache per worker: tree-sitter parsers are not shared
        # across threads.
        parsers = {}
        out = []
        for file_path in chunk:
            rel_path = file_path.relative_to(root).as_posix()
            raw = file_path.read_bytes()
            language = _detect_language(file_path)

            entry = FileEntry(
                path=rel_path,
                language=language,
                size_bytes=len(raw),
                sha256=_sha256_of(raw),
                parsed=False,
                # Bind the digest to BOTH the content and the path: hashing content
                # alone would let an attacker move a benign file's digest onto a
                # malicious path and keep the manifest self-consistent.
                salted_digest=ctx.seal({"path": rel_path, "content": raw.hex()}),
            )
            tree = None
            if language:
                try:
                    if language not in parsers:
                        parsers[language] = get_parser(language)
                    tree = parsers[language].parse(raw)
                    entry.parsed = True
                except Exception as exc:  # noqa: BLE001 - deliberately broad, see docstring
                    entry.parse_error = str(exc)
            out.append((entry, raw if language else None, tree))
        return out

    files: list[FileEntry] = []
    asts = {}
    sources = {}
    # Chunks are contiguous slices of the sorted path list and are merged in
    # order, so the manifest/dicts are identical for any worker count.
    for entry, raw, tree in parallel_chunks(paths, _ingest_chunk, workers):
        files.append(entry)
        if raw is not None:
            sources[entry.path] = raw
        if tree is not None:
            asts[entry.path] = tree

    manifest = IngestionManifest(
        repo_root=str(root),
        files=files,
        manifest_digest=manifest_digest(
            [f"{f.path}:{f.salted_digest}" for f in files], ctx
        ),
        salt=ctx.descriptor(),
    )
    return IngestionResult(manifest=manifest, asts=asts, sources=sources, salt_ctx=ctx)
