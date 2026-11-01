"""
Job manager for executing background review scans asynchronously.
Tracks job status, stores output in api_runs/<job_id>/, and manages
WebSocket progress broadcasting.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import WebSocket


@dataclass
class Job:
    job_id: str
    target_repo: str
    engine: str
    status: str  # "pending" | "running" | "completed" | "failed"
    created_at: float
    output_dir: str
    completed_at: Optional[float] = None
    result_summary: Optional[dict] = None
    error: Optional[str] = None
    messages: List[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class JobManager:
    def __init__(self, base_output_dir: str = "api_runs"):
        self.base_output_dir = Path(base_output_dir)
        self.base_output_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: Dict[str, Job] = {}
        self._websockets: Dict[str, List[WebSocket]] = {}
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        self._loop = loop

    def _get_loop(self) -> Optional[asyncio.AbstractEventLoop]:
        if self._loop and self._loop.is_running():
            return self._loop
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                self._loop = loop
                return loop
        except RuntimeError:
            pass
        return self._loop

    def create_job(self, target_repo: str, engine: str = "graph") -> Job:
        job_id = f"job_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        job_dir = self.base_output_dir / job_id
        job_dir.mkdir(parents=True, exist_ok=True)

        job = Job(
            job_id=job_id,
            target_repo=target_repo,
            engine=engine if engine in {"linear", "graph"} else "graph",
            status="pending",
            created_at=time.time(),
            output_dir=str(job_dir),
        )
        self._jobs[job_id] = job
        self._websockets[job_id] = []

        # Submit task to background thread pool
        self._executor.submit(self._run_job_bg, job_id)
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_jobs(self) -> List[dict]:
        return [j.to_dict() for j in self._jobs.values()]

    def register_websocket(self, job_id: str, ws: WebSocket):
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        if job_id not in self._websockets:
            self._websockets[job_id] = []
        self._websockets[job_id].append(ws)

    def unregister_websocket(self, job_id: str, ws: WebSocket):
        if job_id in self._websockets and ws in self._websockets[job_id]:
            self._websockets[job_id].remove(ws)

    def _broadcast_to_ws(self, job_id: str, data: dict):
        sockets = list(self._websockets.get(job_id, []))
        if not sockets:
            return

        loop = self._get_loop()
        if not loop or not loop.is_running():
            return

        message_text = json.dumps(data)

        async def _send_all():
            dead = []
            for ws in sockets:
                try:
                    await ws.send_text(message_text)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                self.unregister_websocket(job_id, ws)

        try:
            asyncio.run_coroutine_threadsafe(_send_all(), loop)
        except Exception:
            pass

    def _run_job_bg(self, job_id: str):
        job = self._jobs.get(job_id)
        if not job:
            return

        job.status = "running"
        self._broadcast_to_ws(job_id, {"event": "status_change", "status": "running"})

        output_report = Path(job.output_dir) / "report.md"
        artifact_dir = Path(job.output_dir) / "artifacts"
        artifact_dir.mkdir(parents=True, exist_ok=True)

        def on_stage_start(stage_name: str):
            self._broadcast_to_ws(
                job_id,
                {"event": "stage_start", "stage": stage_name}
            )

        def on_stage_done(stage_name: str):
            self._broadcast_to_ws(
                job_id,
                {"event": "stage_done", "stage": stage_name}
            )

        def on_message(msg_dict: dict):
            job.messages.append(msg_dict)
            self._broadcast_to_ws(job_id, {"event": "progress", "message": msg_dict})

        def on_finding_verified(res_dict: dict):
            self._broadcast_to_ws(
                job_id,
                {"event": "finding_verified", "finding": res_dict}
            )

        try:
            if job.engine == "graph":
                from analyst.orchestrator.graph import run_pipeline_graph
                res = run_pipeline_graph(
                    repo_path=job.target_repo,
                    output_path=str(output_report),
                    artifact_dir=str(artifact_dir),
                    on_stage_start=on_stage_start,
                    on_stage_done=on_stage_done,
                    on_message=on_message,
                    on_finding_verified=on_finding_verified,
                )
            else:
                from analyst.orchestrator.pipeline import run_pipeline
                res = run_pipeline(
                    repo_path=job.target_repo,
                    output_path=str(output_report),
                    artifact_dir=str(artifact_dir),
                    on_stage_start=on_stage_start,
                    on_stage_done=on_stage_done,
                    on_message=on_message,
                    on_finding_verified=on_finding_verified,
                )

            job.status = "completed"
            job.completed_at = time.time()
            job.result_summary = {
                "status": res.status,
                "confirmed_count": res.confirmed_count,
                "rejected_count": res.rejected_count,
                "escalated_count": res.escalated_count,
                "duration_seconds": res.duration_seconds,
            }
            self._broadcast_to_ws(
                job_id,
                {
                    "event": "status_change",
                    "status": "completed",
                    "summary": job.result_summary,
                },
            )
        except Exception as exc:
            job.status = "failed"
            job.completed_at = time.time()
            job.error = str(exc)
            self._broadcast_to_ws(
                job_id,
                {"event": "status_change", "status": "failed", "error": str(exc)},
            )

    def get_findings(self, job_id: str) -> dict:
        job = self.get_job(job_id)
        if not job:
            return {}

        artifacts_dir = Path(job.output_dir) / "artifacts"
        confirmed_path = artifacts_dir / "confirmed_findings.json"
        candidate_path = artifacts_dir / "candidate_findings.json"

        confirmed = []
        candidates = []

        if confirmed_path.exists():
            try:
                with open(confirmed_path, "r", encoding="utf-8") as f:
                    confirmed = json.load(f)
            except Exception:
                pass

        if candidate_path.exists():
            try:
                with open(candidate_path, "r", encoding="utf-8") as f:
                    candidates = json.load(f)
            except Exception:
                pass

        return {"confirmed": confirmed, "candidates": candidates}

    def get_fixes(self, job_id: str) -> List[dict]:
        findings_data = self.get_findings(job_id)
        confirmed = findings_data.get("confirmed", [])
        fixes = []
        for f in confirmed:
            if f.get("confirmed") and f.get("patch_diff"):
                fixes.append(
                    {
                        "rule_id": f.get("rule_id"),
                        "vuln_class": f.get("vuln_class"),
                        "file": f.get("file"),
                        "line": f.get("line"),
                        "severity": f.get("severity"),
                        "explanation": f.get("explanation"),
                        "patch_diff": f.get("patch_diff"),
                        "loop_status": f.get("loop_status"),
                        "confidence": f.get("confidence"),
                    }
                )
        return fixes

    def apply_fixes(self, job_id: str, target_dir: Optional[str] = None) -> dict:
        from analyst.reasoning.patch_loop import apply_patch_to_text
        job = self.get_job(job_id)
        if not job:
            return {"success": False, "error": "Job not found"}

        target_path_str = target_dir or job.target_repo
        target = Path(target_path_str)
        if not target.exists() or not target.is_dir():
            return {
                "success": False,
                "error": f"Target repository '{target}' is not an accessible local directory. "
                         "For remote git URLs, clone locally before applying or download the unified diff.",
            }

        fixes = self.get_fixes(job_id)
        applied = []
        failed = []

        for fix in fixes:
            diff = fix.get("patch_diff")
            rel_file = fix.get("file")
            if not diff or not rel_file:
                continue

            file_path = target / rel_file
            if not file_path.exists():
                failed.append({"file": rel_file, "reason": "Target file does not exist on disk"})
                continue

            try:
                original = file_path.read_text(encoding="utf-8")
                patched = apply_patch_to_text(original, diff)
                bak_path = file_path.with_suffix(file_path.suffix + ".orig")
                if not bak_path.exists():
                    bak_path.write_text(original, encoding="utf-8")
                file_path.write_text(patched, encoding="utf-8")
                applied.append({
                    "file": rel_file,
                    "rule_id": fix.get("rule_id"),
                    "vuln_class": fix.get("vuln_class"),
                    "backup": str(bak_path.name),
                })
            except Exception as e:
                failed.append({"file": rel_file, "reason": str(e)})

        return {
            "success": len(applied) > 0,
            "target": str(target),
            "applied_count": len(applied),
            "failed_count": len(failed),
            "applied": applied,
            "failed": failed,
        }

    def get_report(self, job_id: str) -> str:
        job = self.get_job(job_id)
        if not job:
            return ""
        report_file = Path(job.output_dir) / "report.md"
        if report_file.exists():
            return report_file.read_text(encoding="utf-8")
        return ""

    def get_diagram(self, job_id: str) -> str:
        try:
            from analyst.orchestrator.graph import get_graph
            g = get_graph()
            if hasattr(g, "get_graph"):
                return g.get_graph().draw_mermaid()
            elif hasattr(g, "draw_mermaid"):
                return g.draw_mermaid()
            return "graph TD\n  INGEST --> DETECT\n  DETECT --> REASON\n  REASON --> REPORT"
        except Exception:
            return "graph TD\n  INGEST --> DETECT\n  DETECT --> REASON\n  REASON --> REPORT"


GLOBAL_JOB_MANAGER = JobManager()
