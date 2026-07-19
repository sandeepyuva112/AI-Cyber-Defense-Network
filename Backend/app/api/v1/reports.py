from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from fastapi import APIRouter, HTTPException

from app.ai.service import AiEngineService
from app.db.session import get_db
from app.db.models.report import Report
from app.reports.exporters import HTMLExporter, JSONExporter, PDFExporter, export_to_base64
from app.reports.report_builder import IncidentReportBuilder, ReportBuildContext
from app.schemas.ai_request import LogType
from app.schemas.ai_incident import AiIncidentReport
from pydantic import BaseModel, Field


router = APIRouter()


class GenerateReportRequest(BaseModel):
    correlation_id: str
    log_type: LogType
    log_text: Optional[str] = None
    log_lines: Optional[list[str]] = None
    max_output_tokens: int = Field(1200, ge=128, le=4096)
    report_version: str = "1.0"


class GenerateReportResponse(BaseModel):
    report_metadata: dict[str, Any]
    report_json: dict[str, Any]


class ExportReportRequest(BaseModel):
    report_id: int
    format: Literal["pdf", "html", "json"]


@router.post("/reports/generate", response_model=GenerateReportResponse)
async def generate_report(req: GenerateReportRequest) -> GenerateReportResponse:
    # Build log_text
    if req.log_text:
        log_text = req.log_text
    elif req.log_lines:
        log_text = "\n".join(req.log_lines)
    else:
        raise HTTPException(status_code=400, detail="Provide log_text or log_lines")

    ai_service = AiEngineService()
    try:
        ai_report = await ai_service.analyze_logs(
            correlation_id=req.correlation_id,
            log_type=req.log_type,
            log_text=log_text,
            max_output_tokens=req.max_output_tokens,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    builder = IncidentReportBuilder()
    ctx = ReportBuildContext(
        report_id=req.correlation_id,
        report_type="incident",
        generated_at=datetime.utcnow(),
        version=req.report_version,
    )
    full_report = builder.build_full_report(ai_report=ai_report, ctx=ctx)

    # Persist
    db_gen = get_db()
    db = next(db_gen)
    try:
        from app.db.models.incident import Incident
        
        # Link to actual incident matching correlation_id
        incident = db.query(Incident).filter(Incident.incident_id == req.correlation_id).first()
        if incident:
            incident_db_id = incident.id
        else:
            # Fallback mock incident to ensure foreign key integrity
            mock_inc = Incident(
                log_id=1,
                incident_id=req.correlation_id,
                log_type=str(req.log_type),
                classification_type="unknown",
                severity_level="low",
                created_at=datetime.utcnow()
            )
            db.add(mock_inc)
            db.flush()
            incident_db_id = mock_inc.id

        import json
        report_db = Report(
            incident_id=incident_db_id,
            created_at=datetime.utcnow(),
            report_type="incident",
            content_json=json.dumps(full_report.model_dump(mode="json")),
        )

        db.add(report_db)
        db.commit()
        db.refresh(report_db)
    finally:
        db_gen.close()

    return GenerateReportResponse(
        report_metadata={
            "report_db_id": report_db.id,
            "report_id": req.correlation_id,
            "generated_at": report_db.created_at,
        },
        report_json=full_report.model_dump(mode="json"),
    )


@router.get("/reports/{report_db_id}")
async def retrieve_report(report_db_id: int) -> dict[str, Any]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        report = db.get(Report, report_db_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        return {"id": report.id, "report_type": report.report_type, "content": report.content_json}
    finally:
        db_gen.close()


@router.get("/reports")
async def list_reports(limit: int = 20, offset: int = 0) -> dict[str, Any]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        q = db.query(Report).order_by(Report.created_at.desc()).offset(offset).limit(limit)
        items = q.all()
        return {
            "items": [
                {"id": r.id, "report_type": r.report_type, "created_at": r.created_at}
                for r in items
            ]
        }
    finally:
        db_gen.close()


@router.delete("/reports/{report_db_id}")
async def delete_report(report_db_id: int) -> dict[str, Any]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        report = db.get(Report, report_db_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        db.delete(report)
        db.commit()
        return {"deleted": report_db_id}
    finally:
        db_gen.close()


@router.post("/reports/export")
async def export_report(req: ExportReportRequest) -> dict[str, Any]:
    if req.format == "pdf":
        exporter = PDFExporter()
    elif req.format == "html":
        exporter = HTMLExporter()
    else:
        exporter = JSONExporter()

    db_gen = get_db()
    db = next(db_gen)
    try:
        report = db.get(Report, req.report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")

        content = report.content_json
        if content is None:
            raise HTTPException(status_code=400, detail="Report has no content")

        if req.format == "json":
            exported = exporter.export(content)
            return {"format": "json", "content": exported}

        if req.format == "html":
            exported = exporter.export(content)
            return {"format": "html", "content": exported}

        # pdf
        pdf_bytes = exporter.export(content)
        return {"format": "pdf", "content_base64": export_to_base64(pdf_bytes), "filename": f"report_{report.id}.pdf"}
    finally:
        db_gen.close()

