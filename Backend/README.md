# AI Cyber Defense Network Backend

FastAPI backend for the AI Cyber Defense Network MVP.

## Local Setup

```powershell
cd Backend
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

Linux/macOS:

```bash
cd Backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-dev.txt
uvicorn app.main:app --reload
```

The API is served at `http://127.0.0.1:8000`.

## Initial Endpoints

- `GET /health` - liveness probe
- `GET /api/v1/status` - service status and supported MVP capabilities

