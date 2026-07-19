from __future__ import annotations

from datetime import datetime

from fastapi.testclient import TestClient

from app.main import create_app


client = TestClient(create_app())


def test_health() -> None:
    r = client.get("/health")
    assert r.status_code == 200


def test_reports_endpoints_basic() -> None:
    # Generate requires logs; use empty should fail with 400.
    r = client.post(
        "/api/v1/reports/generate",


        json={"correlation_id": "c1", "log_type": "linux_syslog", "max_output_tokens": 128},
    )
    assert r.status_code in (400, 422)


