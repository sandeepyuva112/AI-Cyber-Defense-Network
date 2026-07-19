from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.db.models.incident import Incident
from app.db.models.alert import Alert
from app.db.models.ai_analysis import AIAnalysis
from sqlalchemy import func

router = APIRouter()


class DashboardSummaryResponse(BaseModel):
    as_of: datetime
    open_alerts: int
    total_incidents: int
    analyzed_ai_count: int


class MetricsResponse(BaseModel):
    open_alerts: int
    total_incidents: int
    ai_analyses: int


class ThreatTimelinePoint(BaseModel):
    timestamp: datetime
    event: str
    count: int = Field(default=0, ge=0)


class TimelineResponse(BaseModel):
    items: list[ThreatTimelinePoint] = Field(default_factory=list)


class RiskDistributionBucket(BaseModel):
    severity: str
    count: int


class RiskDistributionResponse(BaseModel):
    buckets: list[RiskDistributionBucket]


class RecentActivityItem(BaseModel):
    timestamp: datetime
    type: str
    ref_id: Optional[int] = None


class RecentActivityResponse(BaseModel):
    items: list[RecentActivityItem]


@router.get("/dashboard/summary", response_model=DashboardSummaryResponse)
async def dashboard_summary() -> DashboardSummaryResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        open_alerts = db.query(func.count(Alert.id)).scalar() or 0
        total_incidents = db.query(func.count(Incident.id)).scalar() or 0
        analyzed_ai_count = db.query(func.count(AIAnalysis.id)).scalar() or 0

        return DashboardSummaryResponse(
            as_of=datetime.utcnow(),
            open_alerts=int(open_alerts),
            total_incidents=int(total_incidents),
            analyzed_ai_count=int(analyzed_ai_count),
        )
    finally:
        db_gen.close()


@router.get("/dashboard/metrics", response_model=MetricsResponse)
async def dashboard_metrics() -> MetricsResponse:
    s = await dashboard_summary()
    return MetricsResponse(
        open_alerts=s.open_alerts,
        total_incidents=s.total_incidents,
        ai_analyses=s.analyzed_ai_count,
    )


@router.get("/dashboard/threat-timeline", response_model=TimelineResponse)
async def threat_timeline(limit: int = 20) -> TimelineResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        # Group by day
        rows = (
            db.query(func.date(Incident.created_at), func.count(Incident.id))
            .group_by(func.date(Incident.created_at))
            .order_by(func.date(Incident.created_at).desc())
            .limit(limit)
            .all()
        )
        items = []
        for r in rows:
            if r and r[0] is not None:
                try:
                    ts = datetime.strptime(str(r[0]), "%Y-%m-%d")
                except ValueError:
                    ts = datetime.utcnow()
                items.append(ThreatTimelinePoint(timestamp=ts, event="Incident Created", count=int(r[1] or 0)))
        return TimelineResponse(items=items)
    finally:
        db_gen.close()


@router.get("/dashboard/risk-distribution", response_model=RiskDistributionResponse)
async def risk_distribution() -> RiskDistributionResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        # Best-effort distribution by Incident.severity_level.
        rows = (
            db.query(Incident.severity_level, func.count(Incident.id))
            .group_by(Incident.severity_level)
            .all()
        )
        buckets = [
            RiskDistributionBucket(severity=str(sev), count=int(cnt or 0))
            for sev, cnt in rows
        ]
        return RiskDistributionResponse(buckets=buckets)
    finally:
        db_gen.close()


@router.get("/dashboard/recent-activity", response_model=RecentActivityResponse)
async def recent_activity(limit: int = 10) -> RecentActivityResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        from app.db.models.log import Log

        # Get recent logs
        logs = db.query(Log).order_by(Log.created_at.desc()).limit(limit).all()
        # Get recent incidents
        incs = db.query(Incident).order_by(Incident.created_at.desc()).limit(limit).all()
        # Get recent alerts
        alts = db.query(Alert).order_by(Alert.created_at.desc()).limit(limit).all()

        combined = []
        for l in logs:
            combined.append(RecentActivityItem(timestamp=l.created_at, type="log", ref_id=l.id))
        for i in incs:
            combined.append(RecentActivityItem(timestamp=i.created_at, type="incident", ref_id=i.id))
        for a in alts:
            combined.append(RecentActivityItem(timestamp=a.created_at, type="alert", ref_id=a.id))

        combined.sort(key=lambda x: x.timestamp, reverse=True)
        return RecentActivityResponse(items=combined[:limit])
    finally:
        db_gen.close()


@router.get("/dashboard/trends", response_model=MetricsResponse)
async def trend_analytics() -> MetricsResponse:
    return await dashboard_metrics()

