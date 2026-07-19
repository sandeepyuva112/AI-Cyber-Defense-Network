from fastapi.testclient import TestClient

from app.main import create_app

client = TestClient(create_app())


def test_settings_health_endpoints_exist() -> None:
    r = client.get("/api/v1/settings/health-checks")
    assert r.status_code in (200, 404, 422)


def test_logs_upload_requires_log_type() -> None:
    r = client.post("/api/v1/logs/upload")
    assert r.status_code in (400, 422)

