from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.db.session import get_db
from app.db.models.ai_analysis import AIAnalysis

router = APIRouter()


class AIExplanationResponse(BaseModel):
    analysis_id: int
    correlation_id: str | None
    reasoning_explanation: str | None
    executive_summary: str | None
    recommended_response_actions: str | None
    status: str
    error_details: str | None


class AIReanalysisRequest(BaseModel):
    max_output_tokens: int = Field(1200, ge=128, le=4096)


class AIReanalysisResponse(AIExplanationResponse):
    updated_at: datetime


class AIExecutiveSummaryResponse(BaseModel):
    analysis_id: int
    executive_summary: str | None
    threat_classification: str | None


class RecommendedResponseActionsResponse(BaseModel):
    analysis_id: int
    recommended_response_actions: str | None


@router.get("/ai/explanations/{analysis_id}", response_model=AIExplanationResponse)
async def ai_explanation(analysis_id: int) -> AIExplanationResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        a = db.get(AIAnalysis, analysis_id)
        if not a:
            raise HTTPException(status_code=404, detail="AIAnalysis not found")
        return AIExplanationResponse(
            analysis_id=a.id,
            correlation_id=a.correlation_id,
            reasoning_explanation=a.reasoning_explanation,
            executive_summary=a.executive_summary,
            recommended_response_actions=a.recommended_response_actions,
            status=a.status,
            error_details=a.error_details,
        )
    finally:
        db_gen.close()


@router.post("/ai/{analysis_id}/reanalysis", response_model=AIReanalysisResponse)
async def ai_reanalysis(analysis_id: int, req: AIReanalysisRequest) -> AIReanalysisResponse:
    # Repo does not yet implement re-analysis persistence; return current snapshot.
    base = await ai_explanation(analysis_id)
    db_gen = get_db()
    db = next(db_gen)
    try:
        a = db.get(AIAnalysis, analysis_id)
        if not a:
            raise HTTPException(status_code=404, detail="AIAnalysis not found")
        return AIReanalysisResponse(**base.model_dump(), updated_at=a.updated_at)
    finally:
        db_gen.close()


@router.get("/ai/{analysis_id}/executive-summary", response_model=AIExecutiveSummaryResponse)
async def ai_executive_summary(analysis_id: int) -> AIExecutiveSummaryResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        a = db.get(AIAnalysis, analysis_id)
        if not a:
            raise HTTPException(status_code=404, detail="AIAnalysis not found")
        return AIExecutiveSummaryResponse(
            analysis_id=a.id,
            executive_summary=a.executive_summary,
            threat_classification=a.threat_classification,
        )
    finally:
        db_gen.close()


@router.get("/ai/{analysis_id}/recommended-response", response_model=RecommendedResponseActionsResponse)
async def ai_recommended_response(analysis_id: int) -> RecommendedResponseActionsResponse:
    expl = await ai_explanation(analysis_id)
    return RecommendedResponseActionsResponse(
        analysis_id=expl.analysis_id,
        recommended_response_actions=expl.recommended_response_actions,
    )


class AIHistoryItemResponse(BaseModel):
    analysis_id: int
    correlation_id: str | None
    created_at: datetime
    status: str


@router.get("/ai/history", response_model=list[AIHistoryItemResponse])
async def ai_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    correlation_id: Optional[str] = None,
) -> list[AIHistoryItemResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        q = db.query(AIAnalysis)
        if correlation_id:
            q = q.filter(AIAnalysis.correlation_id == correlation_id)
        rows = q.order_by(AIAnalysis.created_at.desc()).offset(offset).limit(limit).all()
        return [
            AIHistoryItemResponse(
                analysis_id=a.id,
                correlation_id=a.correlation_id,
                created_at=a.created_at,
                status=a.status,
            )
            for a in rows
        ]
    finally:
        db_gen.close()

