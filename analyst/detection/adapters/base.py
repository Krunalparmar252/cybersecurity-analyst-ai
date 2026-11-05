"""Base adapter interface for external security scanners (Bandit, Semgrep)."""

from __future__ import annotations

import abc
import logging
from typing import Optional

from analyst.common.types import CandidateFinding

logger = logging.getLogger(__name__)


class ScannerAdapter(abc.ABC):
    """Abstract interface that wraps an external static analysis tool."""

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Name identifier of the scanner (e.g., 'bandit', 'semgrep')."""
        pass

    @abc.abstractmethod
    def is_available(self) -> bool:
        """Return True if the scanner binary or runtime is installed and accessible on PATH."""
        pass

    @abc.abstractmethod
    def run(self, repo_path: str, languages: Optional[list[str]] = None) -> list[CandidateFinding]:
        """Execute the scanner against `repo_path` and return normalized CandidateFinding instances.

        Must never raise on tool absence or parse failures; should log an info/debug
        message and gracefully return an empty list.
        """
        pass

