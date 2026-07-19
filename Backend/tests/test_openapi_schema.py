from fastapi.testclient import TestClient

from app.main import create_app

client = TestClient(create_app())


def test_openapi_contains_new_routes() -> None:
    r = client.get("/openapi.json")
    assert r.status_code == 200
    data = r.json()
    paths = data.get("paths", {})

    # Core existing routes
    assert "/api/v1/status" in paths
    assert "/api/v1/ai/analyze" in paths
    assert any(p.startswith("/api/v1/reports") for p in paths.keys())

    # New endpoints (subset)
    assert "/api/v1/logs/upload" in paths
    assert "/api/v1/dashboard/summary" in paths
    assert "/api/v1/alerts" in paths
    assert "/api/v1/threats" in paths
    assert "/api/v1/ai/explanations/{analysis_id}" in paths
    assert "/api/v1/settings/application" in paths

