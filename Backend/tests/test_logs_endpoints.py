import sys
from pathlib import Path

from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
# Ensure package root (Backend/) is on sys.path so `import app.*` works.
sys.path.insert(0, str(ROOT))

from app.main import create_app



client = TestClient(create_app())


def test_settings_health_endpoints_exist() -> None:
    r = client.get("/api/v1/settings/health-checks")
    assert r.status_code in (200, 404, 422)


def test_logs_upload_requires_file() -> None:
    # multipart upload without file should fail validation
    r = client.post("/api/v1/logs/upload")
    assert r.status_code in (400, 422)


def test_logs_upload_accepts_multipart_and_parses() -> None:
    # Minimal JSON log input that JsonLogsParser can parse.
    payload = '{"timestamp":"2020-01-01T00:00:00Z","message":"login success user=alice ip=1.2.3.4"}'
    files = {"file": ("test.json", payload, "application/json")}
    r = client.post("/api/v1/logs/upload", files=files)
    assert r.status_code in (200, 201)
    data = r.json()
    assert "log_id" in data
    assert "log_type" in data



