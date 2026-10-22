"""
Pytest suite for the FastAPI backend layer (analyst.api).
Smoke-tests job submission, polling, findings, fixes, report, diagram,
and WebSocket events against the demo_app fixture.
"""

import time
from pathlib import Path
import pytest
from fastapi.testclient import TestClient

from analyst.api.app import app
from analyst.api.manager import GLOBAL_JOB_MANAGER

client = TestClient(app)
DEMO_APP_PATH = str(Path(__file__).parent / "demo_app")


def test_root_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "operational"


def test_submit_invalid_job():
    response = client.post("/api/jobs", json={"target_repo": "", "engine": "invalid"})
    assert response.status_code == 400


def test_api_scan_lifecycle_against_demo_app():
    # 1. Submit job
    response = client.post(
        "/api/jobs", json={"target_repo": DEMO_APP_PATH, "engine": "graph"}
    )
    assert response.status_code == 200
    job_data = response.json()
    job_id = job_data["job_id"]
    assert job_id.startswith("job_")
    assert job_data["status"] in {"pending", "running"}

    # 2. Poll until completed (timeout 60s)
    start = time.time()
    completed = False
    while time.time() - start < 60:
        res = client.get(f"/api/jobs/{job_id}")
        assert res.status_code == 200
        st = res.json()["status"]
        if st == "completed":
            completed = True
            break
        if st == "failed":
            pytest.fail(f"Job failed unexpectedly: {res.json().get('error')}")
        time.sleep(0.5)

    assert completed is True, "Job did not complete within timeout."

    # 3. Fetch Findings
    res_findings = client.get(f"/api/jobs/{job_id}/findings")
    assert res_findings.status_code == 200
    findings_json = res_findings.json()
    assert "confirmed" in findings_json
    assert "candidates" in findings_json

    # 4. Fetch Fixes & Confidence Tiers
    res_fixes = client.get(f"/api/jobs/{job_id}/fixes")
    assert res_fixes.status_code == 200
    fixes = res_fixes.json()
    assert isinstance(fixes, list)

    # 5. Fetch Report
    res_report = client.get(f"/api/jobs/{job_id}/report")
    assert res_report.status_code == 200
    assert "report" in res_report.json()
    assert len(res_report.json()["report"]) > 0

    # 6. Fetch Diagram
    res_diagram = client.get(f"/api/jobs/{job_id}/diagram")
    assert res_diagram.status_code == 200
    assert "diagram" in res_diagram.json()
    assert "graph" in res_diagram.json()["diagram"].lower()


def test_websocket_connection():
    # Submit a job
    res = client.post(
        "/api/jobs", json={"target_repo": DEMO_APP_PATH, "engine": "graph"}
    )
    job_id = res.json()["job_id"]

    # Connect to WS and verify initial_state structure
    with client.websocket_connect(f"/api/jobs/{job_id}/ws") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "initial_state"
        assert data["job_id"] == job_id
        assert "messages" in data
        assert isinstance(data["messages"], list)

    # Wait for completion and verify messages capture all orchestration components
    start = time.time()
    while time.time() - start < 30:
        res = client.get(f"/api/jobs/{job_id}")
        data = res.json()
        if data["status"] == "completed":
            break
        time.sleep(0.5)

    assert data["status"] == "completed"
    assert "messages" in data and len(data["messages"]) > 0
    agents = {m["agent"] for m in data["messages"]}
    assert {"INGEST", "DETECT", "REASON", "REPORT"}.issubset(agents)
    assert data.get("result_summary") is not None
    assert "confirmed_count" in data["result_summary"]
    assert "duration_seconds" in data["result_summary"]

    # Re-connect to WS when completed and ensure initial_state has all messages and summary
    with client.websocket_connect(f"/api/jobs/{job_id}/ws") as websocket:
        data = websocket.receive_json()
        assert data["event"] == "initial_state"
        assert data["status"] == "completed"
        assert len(data["messages"]) >= 4
        assert data["summary"] is not None
