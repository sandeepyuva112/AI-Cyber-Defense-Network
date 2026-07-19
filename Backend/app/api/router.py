from fastapi import APIRouter

from app.api.v1 import status
from app.api.v1 import ai_analyze

api_router = APIRouter()
api_router.include_router(status.router, tags=["Status"])
api_router.include_router(ai_analyze.router, tags=["AI Analyze"])


