"""Order-preserving chunked parallel map.

INGEST and DETECT both work per-file with no cross-file state, so they split
their file list into contiguous chunks, run chunks on a thread pool and
concatenate results IN CHUNK ORDER. That makes parallel output byte-identical
to sequential output (workers=1), which the tests assert.
"""

from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Optional, Sequence, TypeVar

T = TypeVar("T")
R = TypeVar("R")

DEFAULT_MAX_WORKERS = 4


def resolve_workers(workers: Optional[int]) -> int:
    if workers is None:
        workers = min(DEFAULT_MAX_WORKERS, os.cpu_count() or 1)
    return max(1, int(workers))


def chunked(items: Sequence[T], n: int) -> list[list[T]]:
    """Split into at most n contiguous, near-equal, non-empty chunks."""
    n = max(1, min(n, len(items) or 1))
    size, extra = divmod(len(items), n)
    out, start = [], 0
    for i in range(n):
        end = start + size + (1 if i < extra else 0)
        if end > start:
            out.append(list(items[start:end]))
        start = end
    return out


def parallel_chunks(
    items: Sequence[T], fn: Callable[[list[T]], list[R]], workers: Optional[int]
) -> list[R]:
    """Apply fn to each chunk (in parallel when workers > 1); flatten in order."""
    w = resolve_workers(workers)
    chunks = chunked(items, w)
    if w == 1 or len(chunks) <= 1:
        return [r for c in chunks for r in fn(c)]
    with ThreadPoolExecutor(max_workers=len(chunks), thread_name_prefix="analyst") as pool:
        results = list(pool.map(fn, chunks))  # map() preserves submission order
    return [r for part in results for r in part]
