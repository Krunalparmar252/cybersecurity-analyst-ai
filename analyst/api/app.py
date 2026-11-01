import os
"""
FastAPI application for the cybersecurity analyst web interface.
Exposes REST endpoints, WebSockets, and static frontend dashboard.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware

from analyst.api.manager import GLOBAL_JOB_MANAGER, JobManager


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        GLOBAL_JOB_MANAGER.set_loop(asyncio.get_running_loop())
    except Exception:
        pass
    yield


app = FastAPI(
    title="Cybersecurity Analyst API",
    description="REST & WebSocket API for Static Code Security Scanning & Remediation",
    version="1.0.0",
    lifespan=lifespan,
)

allowed_origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
env_origins = os.environ.get("ALLOWED_ORIGINS")
if env_origins:
    allowed_origins.extend([o.strip() for o in env_origins.split(",") if o.strip()])

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)



class JobSubmitRequest(BaseModel):
    target_repo: str
    engine: str = "graph"  # "graph" or "linear"


@app.get("/api/health")
def health():
    return {
        "service": "Cybersecurity Analyst API",
        "status": "operational",
        "docs_url": "/docs",
    }


@app.post("/api/jobs")
async def submit_job(req: JobSubmitRequest):
    try:
        GLOBAL_JOB_MANAGER.set_loop(asyncio.get_running_loop())
    except Exception:
        pass

    if not req.target_repo:
        raise HTTPException(status_code=400, detail="target_repo is required.")
    if req.engine not in {"graph", "linear"}:
        raise HTTPException(
            status_code=400, detail="engine must be either 'graph' or 'linear'."
        )

    job = GLOBAL_JOB_MANAGER.create_job(
        target_repo=req.target_repo, engine=req.engine
    )
    return job.to_dict()


@app.get("/api/jobs")
def list_jobs():
    return GLOBAL_JOB_MANAGER.list_jobs()


@app.get("/api/jobs/{job_id}")
def get_job_status(job_id: str):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return job.to_dict()


@app.get("/api/jobs/{job_id}/findings")
def get_job_findings(job_id: str):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return GLOBAL_JOB_MANAGER.get_findings(job_id)



@app.post("/api/jobs/{job_id}/apply")
def apply_job_fixes(job_id: str, target_dir: Optional[str] = None):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    result = GLOBAL_JOB_MANAGER.apply_fixes(job_id, target_dir=target_dir)
    return result

@app.get("/api/jobs/{job_id}/fixes")
def get_job_fixes(job_id: str):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return GLOBAL_JOB_MANAGER.get_fixes(job_id)


@app.get("/api/jobs/{job_id}/report")
def get_job_report(job_id: str):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    report_text = GLOBAL_JOB_MANAGER.get_report(job_id)
    return {"job_id": job_id, "report": report_text}


@app.get("/api/jobs/{job_id}/diagram")
def get_job_diagram(job_id: str):
    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    diagram_text = GLOBAL_JOB_MANAGER.get_diagram(job_id)
    return {"job_id": job_id, "diagram": diagram_text}


@app.websocket("/api/jobs/{job_id}/ws")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    await websocket.accept()
    try:
        GLOBAL_JOB_MANAGER.set_loop(asyncio.get_running_loop())
    except Exception:
        pass

    job = GLOBAL_JOB_MANAGER.get_job(job_id)
    if not job:
        await websocket.send_json({"error": "Job not found"})
        await websocket.close()
        return

    GLOBAL_JOB_MANAGER.register_websocket(job_id, websocket)

    # Send initial state, all past messages, and result summary if available
    await websocket.send_json(
        {
            "event": "initial_state",
            "job_id": job.job_id,
            "status": job.status,
            "messages": job.messages,
            "summary": job.result_summary,
        }
    )

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        GLOBAL_JOB_MANAGER.unregister_websocket(job_id, websocket)


# Mount static frontend at root /
static_dir = Path(__file__).parent / "static"
if static_dir.exists():
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
