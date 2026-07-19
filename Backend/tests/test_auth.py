import sys
from pathlib import Path
from fastapi.testclient import TestClient

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.main import create_app

client = TestClient(create_app())

def test_auth_flow() -> None:
    # 1. Register new user
    import uuid
    email = f"user_{uuid.uuid4().hex[:6]}@test.com"
    req = {
        "email": email,
        "password": "testpassword",
        "name": "Test User",
        "role": "analyst"
    }
    r = client.post("/api/v1/auth/register", json=req)
    assert r.status_code == 201
    data = r.json()
    assert data["email"] == email
    assert data["name"] == "Test User"
    assert data["role"] == "analyst"
    assert "id" in data
    
    # 2. Login with registered user
    login_req = {
        "email": email,
        "password": "testpassword"
    }
    r2 = client.post("/api/v1/auth/login", json=login_req)
    assert r2.status_code == 200
    token_data = r2.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["user"]["email"] == email
    
    # 3. Access /me endpoint with token
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    r3 = client.get("/api/v1/auth/me", headers=headers)
    assert r3.status_code == 200
    me_data = r3.json()
    assert me_data["email"] == email
    assert me_data["name"] == "Test User"
