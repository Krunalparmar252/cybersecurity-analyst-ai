"""Semgrep adapter for multi-language static security analysis."""

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
RULES_PATH = Path(__file__).resolve().parent.parent / "semgrep_rules" / "rules.yaml"


class SemgrepAdapter(ScannerAdapter):
    """Adapter for running Semgrep offline using pinned local rules."""

    def __init__(self, mapping_path: Optional[Path] = None, rules_path: Optional[Path] = None):
        self._mapping_path = mapping_path or MAPPING_PATH
        self._rules_path = rules_path or RULES_PATH
        self._mappings: dict = {}
        self._load_mappings()

    def _load_mappings(self) -> None:
        if self._mapping_path.exists():
            try:
                data = yaml.safe_load(self._mapping_path.read_text(encoding="utf-8")) or {}
                self._mappings = data.get("semgrep", {})
            except Exception as exc:
                logger.warning("Failed to load Semgrep mappings from %s: %s", self._mapping_path, exc)

    @property
    def name(self) -> str:
        return "semgrep"

    def _find_binary(self) -> Optional[list[str]]:
        # 1. Direct semgrep binary on PATH
        which_semgrep = shutil.which("semgrep")
        if which_semgrep:
            return [which_semgrep]

        # 2. Python module execution
        try:
            res = subprocess.run(
                [sys.executable, "-m", "semgrep", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
            )
            if res.returncode == 0:
                return [sys.executable, "-m", "semgrep"]
        except Exception:
            pass

        # 3. Windows WSL fallback if semgrep installed in WSL
        if sys.platform == "win32":
            wsl_bin = shutil.which("wsl")
            if wsl_bin:
                try:
                    res = subprocess.run(
                        [wsl_bin, "which", "semgrep"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                        shell=False,
                    )
                    if res.returncode == 0 and res.stdout.strip():
                        return [wsl_bin, "semgrep"]
                except Exception:
                    pass

        return None

    def is_available(self) -> bool:
        return self._find_binary() is not None

    def run(self, repo_path: str, languages: Optional[list[str]] = None) -> list[CandidateFinding]:
        binary = self._find_binary()
        if not binary:
            logger.info("Semgrep binary not found on PATH; skipping Semgrep adapter.")
            return []

        if not self._rules_path.exists():
            logger.warning("Semgrep rules file not found at %s", self._rules_path)
            return []

        cmd = [*binary, "scan", "--config", str(self._rules_path), "--json", "-q", repo_path]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                shell=False,
            )
            stdout = proc.stdout.strip()
            if not stdout:
                return []
            raw_data = json.loads(stdout)
        except subprocess.TimeoutExpired:
            logger.warning("Semgrep scan timed out after 60s on %s", repo_path)
            return []
        except Exception as exc:
            logger.info("Semgrep execution failed on %s: %s", repo_path, exc)
            return []

        return self.parse_results(raw_data, repo_path)

    def parse_results(self, raw_data: dict, repo_path: str) -> list[CandidateFinding]:
        findings: list[CandidateFinding] = []
        raw_results = raw_data.get("results", [])

        for item in raw_results:
            check_id = item.get("check_id")
            if not check_id or check_id not in self._mappings:
                continue

            rule_info = self._mappings[check_id]
            path_str = item.get("path", "")
            try:
                rel_file = os.path.relpath(path_str, repo_path).replace("\\", "/")
            except ValueError:
                rel_file = Path(path_str).name

            start = item.get("start", {})
            line = start.get("line", 1)

            extra = item.get("extra", {})
            lines_snippet = extra.get("lines", "")
            cleaned_snippet = scrub_text(lines_snippet.strip()[:200])

            severity = str(extra.get("severity", "")).upper()
            conf_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
            conf = conf_map.get(severity, "medium")

            findings.append(
                CandidateFinding(
                    rule_id=rule_info["rule_id"],
                    vuln_class=rule_info["class"],
                    file=rel_file,
                    line=line,
                    snippet=cleaned_snippet,
                    confidence=conf,
                    source_scanner="semgrep",
                )
            )

        return findings

