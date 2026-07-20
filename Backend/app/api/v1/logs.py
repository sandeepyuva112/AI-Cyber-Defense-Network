from __future__ import annotations

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, UploadFile, status, BackgroundTasks, Query, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai.service import AiEngineService
from app.api.v1.logs_upload_utils import best_effort_events_count, parse_uploaded_log, sha256_bytes
from app.db.session import get_db
from app.db.models.log import Log
from app.db.models.log import LogEvent as LogEventModel
from app.api._common.security import validate_uploaded_file
from app.core.config import settings
from app.db.models.ai_analysis import AIAnalysis




router = APIRouter()


class UploadLogRequest(BaseModel):
    log_type: str = Field(..., description="Normalized log type")



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
    size: Optional[int] = None
    mime: Optional[str] = None
    sha256: Optional[str] = None
    parser: Optional[str] = None


class LogEventResponse(BaseModel):
    id: int
    log_id: int
    timestamp: Optional[datetime] = None
    source: Optional[str] = None
    ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    process: Optional[str] = None
    severity: Optional[str] = None
    event_type: str
    message: Optional[str] = None
    threat_score: Optional[float] = None
    ioc: Optional[list[str]] = None
    raw: Optional[dict] = None


class LogHistoryItemResponse(BaseModel):
    timestamp: datetime
    event: str
    severity: Optional[str] = None


async def perform_log_analysis_task(log_id: int, db_session_factory) -> None:
    db = db_session_factory()
    try:
        log = db.get(Log, log_id)
        if not log or not log.raw_text:
            return

        # Check if already running or completed
        analysis_db = db.query(AIAnalysis).filter(
            AIAnalysis.log_id == log_id
        ).first()

        if not analysis_db:
            analysis_db = AIAnalysis(
                log_id=log.id,
                ai_provider="openai" if settings.openai_api_key else "local",
                model_name="gpt-4.1-mini",
                status="running",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(analysis_db)
            db.flush()
        else:
            analysis_db.status = "running"
            analysis_db.error_details = None
            analysis_db.updated_at = datetime.utcnow()
            db.add(analysis_db)
            db.flush()

        # Call AI Engine
        ai_service = AiEngineService()
        ai_report = await ai_service.analyze_logs(
            correlation_id=str(log_id),
            log_type=log.log_type,
            log_text=log.raw_text,
            max_output_tokens=1200,
        )

        # 1. Create Incident
        from app.db.models.incident import Incident
        from app.db.models.alert import Alert
        from app.db.models.threat import Threat
        from app.db.models.mitre_attack_mapping import MITREAttackMapping
        from app.db.models.ioc import IOC
        from app.db.models.report import Report
        from app.reports.report_builder import IncidentReportBuilder, ReportBuildContext
        import json
        import re
        from app.detection.ioc_patterns import IOC_REGEXES

        incident_db = Incident(
            log_id=log.id,
            incident_id=ai_report.incident_id or f"INC-{log.id}",
            log_type=log.log_type,
            classification_type=ai_report.classification.incident_type,
            classification_description=ai_report.classification.description,
            severity_level=ai_report.severity.level,
            severity_score=ai_report.severity.score,
            confidence_value=ai_report.confidence.value,
            confidence_rationale=ai_report.confidence.rationale,
            plain_english_attack_explanation=ai_report.plain_english_attack_explanation,
            created_at=datetime.utcnow()
        )
        db.add(incident_db)
        db.flush()

        # 2. Create Alerts
        alerts_created = 0
        for act in ai_report.suspicious_activities:
            alert_db = Alert(
                log_id=log.id,
                incident_id=incident_db.id,
                created_at=datetime.utcnow(),
                severity_level=ai_report.severity.level,
                severity_score=ai_report.severity.score,
                threat_category=ai_report.classification.incident_type,
                confidence_value=ai_report.confidence.value,
                status="Open"
            )
            db.add(alert_db)
            alerts_created += 1
            
        if alerts_created == 0:
            alert_db = Alert(
                log_id=log.id,
                incident_id=incident_db.id,
                created_at=datetime.utcnow(),
                severity_level=ai_report.severity.level,
                severity_score=ai_report.severity.score,
                threat_category=ai_report.classification.incident_type,
                confidence_value=ai_report.confidence.value,
                status="Open"
            )
            db.add(alert_db)
            alerts_created = 1

        # 3. Create Threat
        threat_db = Threat(
            log_id=log.id,
            incident_id=incident_db.id,
            threat_category=ai_report.classification.incident_type,
            confidence_value=ai_report.confidence.value,
            severity_level=ai_report.severity.level,
            created_at=datetime.utcnow()
        )
        db.add(threat_db)

        # 4. Create MITRE mappings
        for tech in ai_report.mitre_attack:
            mapping_db = MITREAttackMapping(
                alert_id=None,
                incident_id=incident_db.id,
                technique_id=tech.technique_id,
                technique_name=tech.technique_name,
                tactics_json=json.dumps(tech.tactics),
                created_at=datetime.utcnow()
            )
            db.add(mapping_db)

        # 5. Extract and Create IOCs
        ips = set(re.findall(IOC_REGEXES["ip_v4"], log.raw_text or ""))
        for ip in ips:
            if ip not in ("127.0.0.1", "0.0.0.0"):
                ioc_db = IOC(
                    alert_id=None,
                    incident_id=incident_db.id,
                    ioc_value=ip,
                    ioc_type="ip",
                    created_at=datetime.utcnow()
                )
                db.add(ioc_db)

        hashes = set(re.findall(IOC_REGEXES["sha256"], log.raw_text or ""))
        for h in hashes:
            ioc_db = IOC(
                alert_id=None,
                incident_id=incident_db.id,
                ioc_value=h,
                ioc_type="sha256",
                created_at=datetime.utcnow()
            )
            db.add(ioc_db)

        # 6. Update AIAnalysis record
        analysis_db.incident_id = incident_db.id
        analysis_db.structured_findings_json = json.dumps(ai_report.model_dump(mode="json"))
        analysis_db.executive_summary = ai_report.executive_summary.overview
        analysis_db.threat_classification = ai_report.classification.incident_type
        analysis_db.severity = ai_report.severity.level
        analysis_db.severity_score = ai_report.severity.score
        analysis_db.risk_score = float(ai_report.severity.score)
        analysis_db.confidence_score = ai_report.confidence.value
        analysis_db.classification_type = ai_report.classification.incident_type
        analysis_db.confidence_value = ai_report.confidence.value
        analysis_db.mitre_attack_mapping_json = json.dumps([m.model_dump(mode="json") for m in ai_report.mitre_attack])
        analysis_db.recommended_response_actions = json.dumps(ai_report.remediation.model_dump(mode="json"))
        analysis_db.reasoning_explanation = ai_report.plain_english_attack_explanation
        analysis_db.status = "completed"
        analysis_db.updated_at = datetime.utcnow()
        db.add(analysis_db)

        # 7. Create Report
        builder = IncidentReportBuilder()
        ctx = ReportBuildContext(
            report_id=incident_db.incident_id,
            report_type="incident",
            generated_at=datetime.utcnow(),
            version="1.0"
        )
        full_report = builder.build_full_report(ai_report=ai_report, ctx=ctx)
        
        report_db = Report(
            incident_id=incident_db.id,
            created_at=datetime.utcnow(),
            report_type="incident",
            content_json=json.dumps(full_report.model_dump(mode="json"))
        )
        db.add(report_db)

        # Update log totals
        log.total_alerts = alerts_created
        db.add(log)

        db.commit()
    except Exception as e:
        db.rollback()
        # Update AIAnalysis status to failed
        db2 = db_session_factory()
        try:
            analysis_db = db2.query(AIAnalysis).filter(
                AIAnalysis.log_id == log_id
            ).first()
            if analysis_db:
                analysis_db.status = "failed"
                analysis_db.error_details = str(e)
                analysis_db.updated_at = datetime.utcnow()
                db2.add(analysis_db)
                db2.commit()
        except Exception:
            db2.rollback()
        finally:
            db2.close()
    finally:
        db.close()


@router.post(
    "/logs/upload",
    response_model=UploadLogResponse,
    status_code=status.HTTP_201_CREATED,
)
async def upload_log(
    file: UploadFile,
    log_type: str | None = None,
) -> UploadLogResponse:
    """Upload a log file (multipart) and parse it into LogEvent rows."""
    db_gen = get_db()
    db = next(db_gen)
    try:
        raw_bytes = await file.read()
        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")

        source_filename = file.filename or "unknown.log"

        # File validation (size & extension check)
        validate_uploaded_file(source_filename, file.content_type, len(raw_bytes))

        # Best-effort parse based on provided log_type or filename.
        resolved_type = log_type or "unknown"
        if resolved_type == "unknown":
            from app.api.v1.logs_upload_utils import detect_log_type_from_filename
            resolved_type = detect_log_type_from_filename(source_filename) or "unknown"
        try:
            text, events_payload = parse_uploaded_log(
                raw_bytes=raw_bytes,
                log_type=resolved_type if resolved_type != "unknown" else None,
                source_filename=source_filename,
                metadata={"filename": source_filename},
            )
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to parse uploaded log: {e}")

        events_count = best_effort_events_count(events_payload)
        checksum = sha256_bytes(raw_bytes)

        # Persistent upload storage on disk
        settings.upload_storage_path.mkdir(parents=True, exist_ok=True)
        file_path = settings.upload_storage_path / f"{checksum}_{source_filename}"
        with open(file_path, "wb") as f:
            f.write(raw_bytes)

        log_db = Log(
            log_type=resolved_type,
            source_filename=source_filename,
            uploaded_by_user_id=None,
            total_events_estimated=events_count,
            total_alerts=0,
            raw_text=text,
            created_at=datetime.utcnow(),
            size=len(raw_bytes),
            mime=file.content_type or "text/plain",
            sha256=checksum,
            parser=resolved_type
        )

        import json

        # Persist Log + LogEvents in a single transaction.
        db.add(log_db)
        db.flush()  # get log_db.id without committing

        for ev in events_payload:
            ts = ev.get("timestamp")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                except ValueError:
                    ts = None

            ioc_val = ev.get("ioc")
            ioc_str = json.dumps(ioc_val) if ioc_val is not None else None
            raw_val = ev.get("raw")
            raw_str = json.dumps(raw_val) if raw_val is not None else None

            db.add(
                LogEventModel(
                    log_id=log_db.id,
                    timestamp=ts,
                    source=ev.get("source"),
                    ip=ev.get("ip"),
                    destination_ip=ev.get("destination_ip"),
                    username=ev.get("username"),
                    process=ev.get("process"),
                    severity=ev.get("severity"),
                    event_type=ev.get("event_type") or "unknown",
                    message=ev.get("message"),
                    threat_score=ev.get("threat_score"),
                    ioc_json=ioc_str,
                    raw_json=raw_str,
                )
            )

        db.commit()
        db.refresh(log_db)

        return UploadLogResponse(
            log_id=log_db.id,
            created_at=log_db.created_at,
            log_type=log_db.log_type,
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db_gen.close()


@router.post("/logs/{log_id}/analyze", response_model=AnalyzeLogResponse)
async def analyze_log(log_id: int, background_tasks: BackgroundTasks) -> AnalyzeLogResponse:
    db_gen = get_db()
    db = next(db_gen)
    try:
        log = db.get(Log, log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        if not log.raw_text:
            raise HTTPException(status_code=400, detail="Log has no raw_text to analyze")

        # Check if already running or completed
        existing = db.query(AIAnalysis).filter(
            AIAnalysis.log_id == log_id,
            AIAnalysis.status.in_(["running", "completed"])
        ).first()

        if existing and existing.status == "running":
            raise HTTPException(status_code=400, detail="Log analysis is already running in background")

        # Create or update AIAnalysis row
        analysis_db = db.query(AIAnalysis).filter(AIAnalysis.log_id == log_id).first()
        if not analysis_db:
            analysis_db = AIAnalysis(
                log_id=log.id,
                ai_provider="openai" if settings.openai_api_key else "local",
                model_name="gpt-4.1-mini",
                status="running",
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            db.add(analysis_db)
        else:
            analysis_db.status = "running"
            analysis_db.error_details = None
            analysis_db.updated_at = datetime.utcnow()
            db.add(analysis_db)
        db.commit()

        # Dispatch background analysis task
        from app.db.session import SessionLocal
        background_tasks.add_task(perform_log_analysis_task, log.id, SessionLocal)

        return AnalyzeLogResponse(
            log_id=log.id,
            analyzed_at=datetime.utcnow(),
            alerts_created=0,
            incidents_created=0,
        )
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
            size=log.size,
            mime=log.mime,
            sha256=log.sha256,
            parser=log.parser
        )
    finally:
        db_gen.close()


@router.get("/logs/{log_id}/history", response_model=list[LogHistoryItemResponse])
async def get_log_history(log_id: int) -> list[LogHistoryItemResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        log = db.get(Log, log_id)
        if not log:
            raise HTTPException(status_code=404, detail="Log not found")

        history = [
            LogHistoryItemResponse(
                timestamp=log.created_at,
                event="Log uploaded",
                severity=None,
            ),
        ]

        from app.db.models.ai_analysis import AIAnalysis
        analysis = db.query(AIAnalysis).filter(AIAnalysis.log_id == log_id).first()
        if analysis:
            history.append(
                LogHistoryItemResponse(
                    timestamp=analysis.updated_at,
                    event=f"AI Analysis status: {analysis.status}",
                    severity=analysis.severity,
                )
            )

        return history
    finally:
        db_gen.close()


@router.get("/logs", response_model=list[LogDetailsResponse])
async def list_logs(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0)) -> list[LogDetailsResponse]:
    db_gen = get_db()
    db = next(db_gen)
    try:
        rows = db.query(Log).order_by(Log.created_at.desc()).offset(offset).limit(limit).all()
        return [
            LogDetailsResponse(
                log_id=log.id,
                log_type=log.log_type,
                source_filename=log.source_filename,
                total_events_estimated=log.total_events_estimated,
                total_alerts=log.total_alerts,
                raw_available=bool(log.raw_text),
                created_at=log.created_at,
                size=log.size,
                mime=log.mime,
                sha256=log.sha256,
                parser=log.parser
            )
            for log in rows
        ]
    finally:
        db_gen.close()


@router.get("/logs/{log_id}/events", response_model=list[LogEventResponse])
async def list_log_events(log_id: int, db: Session = Depends(get_db)) -> list[LogEventResponse]:
    log = db.get(Log, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    import json
    res = []
    for ev in log.events:
        ioc = []
        if ev.ioc_json:
            try:
                ioc = json.loads(ev.ioc_json)
                if not isinstance(ioc, list):
                    ioc = [ioc]
            except Exception:
                ioc = []

        raw_val = {}
        if ev.raw_json:
            try:
                raw_val = json.loads(ev.raw_json)
            except Exception:
                raw_val = {}

        res.append(
            LogEventResponse(
                id=ev.id,
                log_id=ev.log_id,
                timestamp=ev.timestamp,
                source=ev.source,
                ip=ev.ip,
                destination_ip=ev.destination_ip,
                username=ev.username,
                process=ev.process,
                severity=ev.severity,
                event_type=ev.event_type,
                message=ev.message,
                threat_score=ev.threat_score,
                ioc=ioc,
                raw=raw_val
            )
        )
    return res


@router.get("/logs/events/all", response_model=list[LogEventResponse])
async def list_all_events(limit: int = 100, db: Session = Depends(get_db)) -> list[LogEventResponse]:
    import json
    import os
    import subprocess
    import datetime

    # Get DB events
    rows = db.query(LogEventModel).order_by(LogEventModel.timestamp.desc()).limit(limit).all()
    res = []
    for ev in rows:
        ioc = []
        if ev.ioc_json:
            try:
                ioc = json.loads(ev.ioc_json)
                if not isinstance(ioc, list):
                    ioc = [ioc]
            except Exception:
                ioc = []

        raw_val = {}
        if ev.raw_json:
            try:
                raw_val = json.loads(ev.raw_json)
            except Exception:
                raw_val = {}

        res.append(
            LogEventResponse(
                id=ev.id,
                log_id=ev.log_id,
                timestamp=ev.timestamp,
                source=ev.source,
                ip=ev.ip,
                destination_ip=ev.destination_ip,
                username=ev.username,
                process=ev.process,
                severity=ev.severity,
                event_type=ev.event_type,
                message=ev.message,
                threat_score=ev.threat_score,
                ioc=ioc,
                raw=raw_val
            )
        )

    # Fetch live Windows logs if on Windows
    if os.name == 'nt':
        try:
            # Select Application log (available without admin rights)
            cmd = ["powershell", "-NoProfile", "-Command", 
                   f"Get-EventLog -LogName Application -Newest {limit} | Select-Object TimeGenerated, EntryType, Source, EventID, Message | ConvertTo-Json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if proc.returncode == 0 and proc.stdout.strip():
                data = json.loads(proc.stdout)
                if not isinstance(data, list):
                    data = [data]
                
                for i, item in enumerate(data):
                    tg_str = item.get("TimeGenerated")
                    dt = None
                    if tg_str:
                        if "Date(" in tg_str:
                            try:
                                ms = int(tg_str.split("(")[1].split(")")[0])
                                dt = datetime.datetime.fromtimestamp(ms / 1000.0)
                            except Exception:
                                dt = datetime.datetime.utcnow()
                        else:
                            try:
                                # Parse powershell datetime string
                                dt = datetime.datetime.strptime(tg_str, "%m/%d/%Y %I:%M:%S %p")
                            except Exception:
                                try:
                                    dt = datetime.datetime.fromisoformat(tg_str)
                                except Exception:
                                    dt = datetime.datetime.utcnow()
                    else:
                        dt = datetime.datetime.utcnow()

                    entry_type = str(item.get("EntryType") or "Information").lower()
                    severity = "low"
                    if "error" in entry_type:
                        severity = "high"
                    elif "warning" in entry_type:
                        severity = "medium"

                    msg = item.get("Message") or ""
                    if len(msg) > 300:
                        msg = msg[:300] + "..."

                    if dt.tzinfo is not None:
                        dt = dt.replace(tzinfo=None)

                    # Check threat signatures
                    threat_score = 0.0
                    from app.detection.rules import match_rules
                    matches, _ = match_rules(msg)
                    if matches:
                        threat_score = float(max(m.weight for m in matches) * 10)

                    res.append(
                        LogEventResponse(
                            id=-999 - i,
                            log_id=-999,
                            timestamp=dt,
                            source=item.get("Source") or "Windows",
                            ip="127.0.0.1",
                            destination_ip=None,
                            username="SYSTEM",
                            process=item.get("Source") or "EventLog",
                            severity=severity,
                            event_type=f"WinEvent-{item.get('EventID')}",
                            message=msg,
                            threat_score=threat_score,
                            ioc=[],
                            raw=item
                        )
                    )
        except Exception:
            pass

    # Sort merged result by timestamp desc
    res.sort(key=lambda x: x.timestamp or datetime.datetime.min, reverse=True)
    return res[:limit]

