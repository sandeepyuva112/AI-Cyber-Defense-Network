from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func

from app.db.session import get_db
from app.db.models.alert import Alert

router = APIRouter()


class AlertStatusResponse(BaseModel):
    alert_id: int
    severity_level: str
    severity_score: int | None
    threat_category: str | None
    confidence_value: float | None


class AlertDetailsResponse(AlertStatusResponse):
    created_at: datetime


class AlertFilterResponse(BaseModel):
    total: int
    items: list[AlertStatusResponse] = Field(default_factory=list)


@router.get("/alerts", response_model=AlertFilterResponse)
async def list_alerts(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    threat_category: Optional[str] = None,
    search: Optional[str] = None,
) -> AlertFilterResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        q = db.query(Alert)
        if severity:
            q = q.filter(Alert.severity_level == severity)
        if threat_category:
            q = q.filter(Alert.threat_category == threat_category)
        if search:
            # Best-effort: search by severity_level or threat_category
            s = f"%{search}%"
            q = q.filter((Alert.threat_category.ilike(s)) | (Alert.severity_level.ilike(s)))

        total = q.count()
        rows = (
            q.order_by(Alert.created_at.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
        items = [
            AlertStatusResponse(
                alert_id=a.id,
                severity_level=a.severity_level,
                severity_score=a.severity_score,
                threat_category=a.threat_category,
                confidence_value=a.confidence_value,
            )
            for a in rows
        ]
        return AlertFilterResponse(total=total, items=items)
    finally:
        db_gen.close()


@router.get("/alerts/{alert_id}", response_model=AlertDetailsResponse)
async def alert_details(alert_id: int) -> AlertDetailsResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        a = db.get(Alert, alert_id)
        if not a:
            raise HTTPException(status_code=404, detail="Alert not found")
        return AlertDetailsResponse(
            alert_id=a.id,
            created_at=a.created_at,
            severity_level=a.severity_level,
            severity_score=a.severity_score,
            threat_category=a.threat_category,
            confidence_value=a.confidence_value,
        )
    finally:
        db_gen.close()


@router.post("/alerts/{alert_id}/status", response_model=AlertStatusResponse)
async def alert_status_update(alert_id: int) -> AlertStatusResponse:
    # Repo does not have alert lifecycle/status fields.
    # Return current alert snapshot.
    return await alert_details(alert_id)

