"""External scanner adapters and multi-scanner deduplication."""

from __future__ import annotations

import logging
from typing import Optional

from analyst.detection.adapters.base import ScannerAdapter
from analyst.detection.adapters.bandit_adapter import BanditAdapter
from analyst.detection.adapters.semgrep_adapter import SemgrepAdapter
from analyst.detection.adapters.merge import merge_findings

logger = logging.getLogger(__name__)

__all__ = [
    "ScannerAdapter",
    "BanditAdapter",
    "SemgrepAdapter",
    "merge_findings",
    "get_available_adapters",
]


def get_available_adapters(scanners_filter: Optional[list[str]] = None) -> list[ScannerAdapter]:
    """Return initialized instances of available external scanner adapters.

    Args:
        scanners_filter: Optional list of scanner names (e.g., ['bandit', 'semgrep']).
                         If None, checks all known external adapters.
    """
    known_adapters: list[ScannerAdapter] = [
        BanditAdapter(),
        SemgrepAdapter(),
    ]

    selected: list[ScannerAdapter] = []
    for adapter in known_adapters:
        if scanners_filter is not None and adapter.name not in scanners_filter:
            continue
        if adapter.is_available():
            selected.append(adapter)
        else:
            logger.info("Scanner '%s' is not available in environment; skipping.", adapter.name)

    return selected

