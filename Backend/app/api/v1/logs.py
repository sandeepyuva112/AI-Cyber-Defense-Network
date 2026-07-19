from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException, UploadFile, status
from pydantic import BaseModel, Field

from app.ai.service import AiEngineService


class UploadLogRequest(BaseModel):
    log_type: str = Field(..., description="Normalized log type")

from app.db.session import get_db
from app.db.models.log import Log
from app.db.models.alert import Alert
from app.db.models.incident import Incident
from app.parsers.factory import get_parser

router = APIRouter()


class UploadLogResponse(BaseModel):
    log_id: int
    created_at: datetime
    log_type: str


class AnalyzeLogResponse(BaseModel):
    log_id: int
    analyzed_at: datetime
    alerts_created: int
    incidents_created: int


class LogDetailsResponse(BaseModel):
    log_id: int
    log_type: str
    source_filename: Optional[str] = None
    total_events_estimated: Optional[int] = None
    total_alerts: int
    raw_available: bool
    created_at: datetime


class LogHistoryItemResponse(BaseModel):
    timestamp: datetime
    event: str
    severity: Optional[str] = None


@router.post(
    "/logs/upload",
    response_model=UploadLogResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_log(req: UploadLogRequest) -> UploadLogResponse:

    # NOTE: For now, keep minimal body requirements since the repo does not yet

    # provide an upload-bytes pipeline. The desktop client can be wired later.
    db_gen = get_db()
    db = next(db_gen)
    try:
        log_db = Log(
            log_type=req.log_type,

            source_filename=None,
            uploaded_by_user_id=None,
            total_events_estimated=None,
            total_alerts=0,
            raw_text=None,
            created_at=datetime.utcnow(),
        )
        db.add(log_db)
        db.commit()
        db.refresh(log_db)
        return UploadLogResponse(
            log_id=log_db.id,
            created_at=log_db.created_at,
            log_type=log_db.log_type,
        )
    finally:
        db_gen.close()


@router.post("/logs/{log_id}/analyze", response_model=AnalyzeLogResponse)
async def analyze_log(log_id: int) -> AnalyzeLogResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        log = db.get(Log, log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        # If no raw text stored yet, analysis cannot proceed.
        if not log.raw_text:
            raise HTTPException(status_code=400, detail="Log has no raw_text to analyze")

        # Parse + deterministic detection are embedded in AiEngineService for now.
        ai_service = AiEngineService()
        awaitable_report = await ai_service.analyze_logs(
            correlation_id=str(log_id),
            log_type=log.log_type,  # type: ignore[arg-type]
            log_text=log.raw_text,
            max_output_tokens=1200,
        )

        # Persist minimal lifecycle only; full persistence is out of scope for repo baseline.
        alerts_created = 0
        incidents_created = 0

        return AnalyzeLogResponse(
            log_id=log.id,
            analyzed_at=datetime.utcnow(),
            alerts_created=alerts_created,
            incidents_created=incidents_created,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db_gen.close()


@router.get("/logs/{log_id}", response_model=LogDetailsResponse)
async def get_log_details(log_id: int) -> LogDetailsResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        log = db.get(Log, log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        return LogDetailsResponse(
            log_id=log.id,
            log_type=log.log_type,
            source_filename=log.source_filename,
            total_events_estimated=log.total_events_estimated,
            total_alerts=log.total_alerts,
            raw_available=bool(log.raw_text),
            created_at=log.created_at,
        )
    finally:
        db_gen.close()


@router.get("/logs/{log_id}/history", response_model=list[LogHistoryItemResponse])
async def get_log_history(log_id: int) -> list[LogHistoryItemResponse]:
    # Placeholder: repo currently lacks a dedicated log-history entity.
    # Return a small, deterministic history trail.
    db_gen = get_db()
    db = next(db_gen)
    try:
        log = db.get(Log, log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        return [
            LogHistoryItemResponse(
                timestamp=log.created_at,
                event="Log uploaded",
                severity=None,
            ),
        ]
    finally:
        db_gen.close()

