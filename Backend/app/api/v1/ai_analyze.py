from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.ai.service import AiEngineService
from app.schemas.ai_request import AnalyzeLogsRequest

router = APIRouter()

ai_service = AiEngineService()


@router.post("/ai/analyze", response_model=dict)
async def analyze_logs(req: AnalyzeLogsRequest) -> dict:
    # Build log_text
    if req.log_text:
        log_text = req.log_text
    elif req.log_lines:
        log_text = "\n".join(req.log_lines)
    else:
        raise HTTPException(status_code=400, detail="Provide log_text or log_lines")

    try:
        report = await ai_service.analyze_logs(
            correlation_id=req.correlation_id,
            log_type=req.log_type,
            log_text=log_text,
            max_output_tokens=req.max_output_tokens or 1200,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    return {"report": report.model_dump(mode="json")}

