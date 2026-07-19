from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import func

from app.db.session import get_db
from app.db.models.threat import Threat

router = APIRouter()


class MITRETechniqueMappingResponse(BaseModel):
    technique_id: Optional[str] = None
    technique_name: Optional[str] = None
    tactics: list[str] = Field(default_factory=list)


class IOCDetailsResponse(BaseModel):
    ioc_id: Optional[int] = None
    ioc_value: str
    ioc_type: Optional[str] = None


class RiskAssessmentResponse(BaseModel):
    severity_level: Optional[str]
    confidence_value: Optional[float]


class ThreatDetailsResponse(BaseModel):
    threat_id: int
    threat_category: str
    incident_id: int | None
    severity_level: str | None
    confidence_value: float | None
    created_at: datetime


@router.get("/threats/{threat_id}", response_model=ThreatDetailsResponse)
async def threat_details(threat_id: int) -> ThreatDetailsResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        t = db.get(Threat, threat_id)
        if not t:
            raise HTTPException(status_code=404, detail="Threat not found")
        return ThreatDetailsResponse(
            threat_id=t.id,
            threat_category=t.threat_category,
            incident_id=t.incident_id,
            severity_level=t.severity_level,
            confidence_value=t.confidence_value,
            created_at=t.created_at,
        )
    finally:
        db_gen.close()


@router.get("/threats/{threat_id}/mitre", response_model=list[MITRETechniqueMappingResponse])
async def mitre_mapping(threat_id: int) -> list[MITRETechniqueMappingResponse]:
    # Placeholder: repo has MITRE mappings linked to alerts/incidents, not directly threats.
    return []


@router.get("/threats/{threat_id}/iocs", response_model=list[IOCDetailsResponse])
async def ioc_details(threat_id: int) -> list[IOCDetailsResponse]:
    # Placeholder: IOC model is linked to alerts/incidents, not directly threats.
    return []


@router.get("/threats", response_model=list[ThreatDetailsResponse])
async def threat_list(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> list[ThreatDetailsResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        rows = db.query(Threat).order_by(Threat.created_at.desc()).offset(offset).limit(limit).all()
        return [
            ThreatDetailsResponse(
                threat_id=t.id,
                threat_category=t.threat_category,
                incident_id=t.incident_id,
                severity_level=t.severity_level,
                confidence_value=t.confidence_value,
                created_at=t.created_at,
            )
            for t in rows
        ]
    finally:
        db_gen.close()


@router.get("/threats/{threat_id}/risk", response_model=RiskAssessmentResponse)
async def risk_assessment(threat_id: int) -> RiskAssessmentResponse:
    t = await threat_details(threat_id)
    return RiskAssessmentResponse(severity_level=t.severity_level, confidence_value=t.confidence_value)

