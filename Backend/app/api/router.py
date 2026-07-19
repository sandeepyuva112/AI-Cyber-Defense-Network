from fastapi import APIRouter

from app.api.v1 import status
from app.api.v1 import ai_analyze
from app.api.v1 import reports
from app.api.v1 import logs
from app.api.v1 import dashboard
from app.api.v1 import alerts
from app.api.v1 import threats
from app.api.v1 import ai
from app.api.v1 import settings

api_router = APIRouter()
api_router.include_router(status.router, tags=["Status"])
api_router.include_router(ai_analyze.router, tags=["AI Analyze"])
api_router.include_router(reports.router, tags=["Reports"])
api_router.include_router(logs.router, tags=["Logs"])
api_router.include_router(dashboard.router, tags=["Dashboard"])
api_router.include_router(alerts.router, tags=["Alerts"])
api_router.include_router(threats.router, tags=["Threats"])
api_router.include_router(ai.router, tags=["AI"])
api_router.include_router(settings.router, tags=["Settings"])






