"""Bandit adapter for Python static security analysis."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

import yaml

from analyst.common.redact import scrub_text
from analyst.common.types import CandidateFinding
from analyst.detection.adapters.base import ScannerAdapter

logger = logging.getLogger(__name__)

MAPPING_PATH = Path(__file__).resolve().parent / "mapping.yaml"


class BanditAdapter(ScannerAdapter):
    """Adapter for running Bandit on Python repositories."""

    def __init__(self, mapping_path: Optional[Path] = None):
        self._mapping_path = mapping_path or MAPPING_PATH
        self._mappings: dict = {}
        self._load_mappings()

    def _load_mappings(self) -> None:
        if self._mapping_path.exists():
            try:
                data = yaml.safe_load(self._mapping_path.read_text(encoding="utf-8")) or {}
                self._mappings = data.get("bandit", {})
            except Exception as exc:
                logger.warning("Failed to load Bandit mappings from %s: %s", self._mapping_path, exc)

    @property
    def name(self) -> str:
        return "bandit"

    def _find_binary(self) -> Optional[list[str]]:
        # 1. Direct bandit binary on PATH
        which_bandit = shutil.which("bandit")
        if which_bandit:
            return [which_bandit]
        # 2. Python module execution
        try:
            res = subprocess.run(
                [sys.executable, "-m", "bandit", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            if res.returncode == 0:
                return [sys.executable, "-m", "bandit"]
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        return self._find_binary() is not None

    def run(self, repo_path: str, languages: Optional[list[str]] = None) -> list[CandidateFinding]:
        if languages is not None and "python" not in languages:
            return []

        binary = self._find_binary()
        if not binary:
            logger.info("Bandit binary not found on PATH; skipping Bandit adapter.")
            return []

        cmd = [*binary, "-r", repo_path, "-f", "json", "-q"]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
            )
            # Bandit returns exit code 0 when clean, 1 when issues found
            stdout = proc.stdout.strip()
            if not stdout:
                return []
            raw_data = json.loads(stdout)
        except subprocess.TimeoutExpired:
            logger.warning("Bandit scan timed out after 60s on %s", repo_path)
            return []
        except Exception as exc:
            logger.info("Bandit execution failed on %s: %s", repo_path, exc)
            return []

        return self.parse_results(raw_data, repo_path)

    def parse_results(self, raw_data: dict, repo_path: str) -> list[CandidateFinding]:
        findings: list[CandidateFinding] = []
        raw_results = raw_data.get("results", [])

        for item in raw_results:
            test_id = item.get("test_id")
            if not test_id or test_id not in self._mappings:
                continue

            rule_info = self._mappings[test_id]
            filename = item.get("filename", "")
            try:
                rel_file = os.path.relpath(filename, repo_path).replace("\\", "/")
            except ValueError:
                rel_file = Path(filename).name

            line = item.get("line_number", 1)
            raw_code = item.get("code", "")
            cleaned_snippet = scrub_text(raw_code.strip()[:200])

            confidence_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            conf = confidence_map.get(str(item.get("issue_confidence", "")).upper(), "medium")

            findings.append(
                CandidateFinding(
                    rule_id=rule_info["rule_id"],
                    vuln_class=rule_info["class"],
                    file=rel_file,
                    line=line,
                    snippet=cleaned_snippet,
                    confidence=conf,
                    source_scanner="bandit",
                )
            )

        return findings
