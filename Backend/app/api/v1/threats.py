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
    db_gen = get_db()
    db = next(db_gen)
    try:
        t = db.get(Threat, threat_id)
        if not t:
            raise HTTPException(status_code=404, detail="Threat not found")

        if not t.incident_id:
            return []

        from app.db.models.mitre_attack_mapping import MITREAttackMapping
        import json

        rows = db.query(MITREAttackMapping).filter(MITREAttackMapping.incident_id == t.incident_id).all()
        res = []
        for r in rows:
            tactics = []
            if r.tactics_json:
                try:
                    tactics = json.loads(r.tactics_json)
                    if not isinstance(tactics, list):
                        tactics = [tactics]
                except Exception:
                    tactics = []
            res.append(
                MITRETechniqueMappingResponse(
                    technique_id=r.technique_id,
                    technique_name=r.technique_name,
                    tactics=tactics
                )
            )
        return res
    finally:
        db_gen.close()


@router.get("/threats/{threat_id}/iocs", response_model=list[IOCDetailsResponse])
async def ioc_details(threat_id: int) -> list[IOCDetailsResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        t = db.get(Threat, threat_id)
        if not t:
            raise HTTPException(status_code=404, detail="Threat not found")

        if not t.incident_id:
            return []

        from app.db.models.ioc import IOC

        rows = db.query(IOC).filter(IOC.incident_id == t.incident_id).all()
        return [
            IOCDetailsResponse(
                ioc_id=i.id,
                ioc_value=i.ioc_value,
                ioc_type=i.ioc_type
            )
            for i in rows
        ]
    finally:
        db_gen.close()


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


@router.get("/threats/iocs/all", response_model=list[IOCDetailsResponse])
async def list_all_iocs(limit: int = 100) -> list[IOCDetailsResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        from app.db.models.ioc import IOC
        rows = db.query(IOC).order_by(IOC.created_at.desc()).limit(limit).all()
        return [
            IOCDetailsResponse(
                ioc_id=i.id,
                ioc_value=i.ioc_value,
                ioc_type=i.ioc_type
            )
            for i in rows
        ]
    finally:
        db_gen.close()


@router.get("/threats/mitre/all", response_model=list[MITRETechniqueMappingResponse])
async def list_all_mitre_mappings(limit: int = 100) -> list[MITRETechniqueMappingResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        from app.db.models.mitre_attack_mapping import MITREAttackMapping
        import json
        rows = db.query(MITREAttackMapping).order_by(MITREAttackMapping.id.desc()).limit(limit).all()
        res = []
        for r in rows:
            tactics = []
            if r.tactics_json:
                try:
                    tactics = json.loads(r.tactics_json)
                    if not isinstance(tactics, list):
                        tactics = [tactics]
                except Exception:
                    tactics = []
            res.append(
                MITRETechniqueMappingResponse(
                    technique_id=r.technique_id,
                    technique_name=r.technique_name,
                    tactics=tactics
                )
            )
        return res
    finally:
        db_gen.close()

