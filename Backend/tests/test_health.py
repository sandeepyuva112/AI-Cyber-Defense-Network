from fastapi.testclient import TestClient

from app.main import create_app


def test_health_endpoint_returns_ok() -> None:
    client = TestClient(create_app())

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_status_endpoint_lists_mvp_capabilities() -> None:
    client = TestClient(create_app())

    response = client.get("/api/v1/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["name"] == "AI Cyber Defense Network API"
    assert any(item["name"] == "AI Threat Analysis" for item in payload["capabilities"])

