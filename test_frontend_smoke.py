"""
Smoke test suite for Phase 5 frontend dashboard static files & DOM structure.
"""

from fastapi.testclient import TestClient
from analyst.api.app import app

client = TestClient(app)


def test_frontend_index_serving():
    response = client.get("/")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
    html = response.text
    assert "Code Quality & Remediation Assistant" in html
    assert 'id="target-repo"' in html
    assert 'id="engine-select"' in html
    assert 'id="btn-start"' in html


def test_frontend_static_assets_serving():
    res_css = client.get("/styles.css")
    assert res_css.status_code == 200
    assert "text/css" in res_css.headers["content-type"]
    assert "--bg-main" in res_css.text

    res_js = client.get("/dashboard.js")
    assert res_js.status_code == 200
    assert "javascript" in res_js.headers["content-type"]
    assert "fetchFinalArtifacts" in res_js.text


def test_frontend_component_lifecycle_dom_elements():
    response = client.get("/")
    html = response.text
    assert "card-ingest" in html
    assert "card-detect" in html
    assert "card-reason" in html
    assert "card-report" in html
    assert "1. RUN" in html
    assert "2. OBSERVE" in html
    assert "3. DECIDE" in html
