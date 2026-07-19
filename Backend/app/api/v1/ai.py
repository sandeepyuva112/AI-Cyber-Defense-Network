from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Query, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models.ai_analysis import AIAnalysis
from app.core.config import settings

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


class AICopilotRequest(BaseModel):
    prompt: str = Field(..., description="The query prompt for the Security Copilot")
    conversation_id: Optional[str] = Field(None, description="Optional conversation UUID to retrieve chat context")


class AICopilotResponse(BaseModel):
    response: str
    conversation_id: str


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
    db_gen = get_db()
    db = next(db_gen)
    try:
        a = db.get(AIAnalysis, analysis_id)
        if not a:
            raise HTTPException(status_code=404, detail="AIAnalysis not found")

        from app.db.models.log import Log
        log = db.get(Log, a.log_id)
        if not log or not log.raw_text:
            raise HTTPException(status_code=400, detail="Associated log text is not available for re-analysis")

        from app.ai.service import AiEngineService
        import json

        ai_service = AiEngineService()
        ai_report = await ai_service.analyze_logs(
            correlation_id=a.correlation_id or str(log.id),
            log_type=log.log_type,
            log_text=log.raw_text,
            max_output_tokens=req.max_output_tokens,
        )

        a.structured_findings_json = json.dumps(ai_report.model_dump(mode="json"))
        a.executive_summary = ai_report.executive_summary.overview
        a.threat_classification = ai_report.classification.incident_type
        a.severity = ai_report.severity.level
        a.severity_score = ai_report.severity.score
        a.confidence_score = ai_report.confidence.value
        a.mitre_attack_mapping_json = json.dumps([m.model_dump(mode="json") for m in ai_report.mitre_attack])
        a.recommended_response_actions = json.dumps(ai_report.remediation.model_dump(mode="json"))
        a.reasoning_explanation = ai_report.plain_english_attack_explanation
        a.updated_at = datetime.utcnow()

        db.add(a)
        db.commit()
        db.refresh(a)

        return AIReanalysisResponse(
            analysis_id=a.id,
            correlation_id=a.correlation_id,
            reasoning_explanation=a.reasoning_explanation,
            executive_summary=a.executive_summary,
            recommended_response_actions=a.recommended_response_actions,
            status=a.status,
            error_details=a.error_details,
            updated_at=a.updated_at,
        )
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


@router.post("/ai/copilot", response_model=AICopilotResponse)
async def ai_copilot(req: AICopilotRequest, db: Session = Depends(get_db)) -> AICopilotResponse:
    import uuid

    conversation_id = req.conversation_id or str(uuid.uuid4())

    # Retrieve history
    history_rows = (
        db.query(AIAnalysis)
        .filter(AIAnalysis.correlation_id == conversation_id, AIAnalysis.analysis_type == "copilot_chat")
        .order_by(AIAnalysis.created_at.asc())
        .all()
    )

    prompt_context = ""
    for r in history_rows:
        prompt_context += f"User: {r.input_summary}\nCopilot: {r.reasoning_explanation}\n\n"
    prompt_context += f"User: {req.prompt}"

    if not settings.openai_api_key:
        p = req.prompt.lower()
        if "malware" in p or "ransomware" in p or "beacon" in p:
            response_text = (
                "**Local Rule Containment Playbook (Ransomware/Malware Beaconing)**:\n\n"
                "1. **Host Isolation**: Disconnect the host from the network switch or disable its wireless adapter.\n"
                "2. **Process Termination**: Stop the beaconing process and record its executable hash.\n"
                "3. **Indicator Block**: Block all destination IP addresses and domains in the edge firewall rules.\n"
                "4. **Telemetry Scan**: Run a full disk antivirus scan and check for registry persistence keys (Run/RunOnce)."
            )
        elif "privilege" in p or "escalation" in p:
            response_text = (
                "**Local Rule Containment Playbook (Privilege Escalation)**:\n\n"
                "1. **Session Termination**: Log out all active sessions of the compromised account.\n"
                "2. **Privilege Revocation**: Temporarily downgrade the account's group memberships (e.g., Domain Admins).\n"
                "3. **Credential Rotation**: Rotate the passwords of the compromised account and parent administrative handles.\n"
                "4. **Audit Logs**: Inspect Sysmon Event ID 1 (Process Creation) and security log logon attempts (Event ID 4624)."
            )
        elif "tactic" in p or "mitre" in p or "execution" in p:
            response_text = (
                "**Local Rule Detection Guide (MITRE ATT&CK Execution)**:\n\n"
                "1. **Command Line Monitoring**: Audit command execution arguments (e.g., powershell -ep bypass, cmd /c).\n"
                "2. **Script Execution Restrictions**: Enforce AppLocker or Software Restriction Policies (SRP) to block scripts.\n"
                "3. **Scheduled Tasks**: Audit system scheduled tasks for unsigned binaries launching from Temp directories."
            )
        else:
            response_text = (
                "**Local Rule Fallback Response**:\n\n"
                "No OpenAI API key is configured. To enable full conversational AI features, please set a valid key in the Settings page.\n\n"
                "**General Security Recommendations**:\n"
                "- Triage all alerts marked as *Critical* or *High* in the Alerts Console.\n"
                "- Check the Live Monitor for anomalies in network connections (e.g., untrusted outbound ports)."
            )
    else:
        from app.ai.openai_responses_client import OpenAIResponsesClient
        system_prompt = (
            "You are an expert Cybersecurity Copilot. You analyze security logs, threats, malware, and network scans. "
            "Provide concise, professional, and actionable cybersecurity summaries, classifications, and advice."
        )
        try:
            client = OpenAIResponsesClient()
            raw = await client.analyze(system=system_prompt, prompt=prompt_context, max_output_tokens=1000)

            # Extract text from raw response
            response_text = None
            if isinstance(raw, dict):
                out = raw.get("output")
                if isinstance(out, list) and out:
                    for item in out:
                        if not isinstance(item, dict):
                            continue
                        content = item.get("content")
                        if isinstance(content, list) and content:
                            for c in content:
                                if isinstance(c, dict) and "text" in c:
                                    response_text = c["text"]
                                    break
                        if response_text:
                            break
                if not response_text and "text" in raw:
                    response_text = raw["text"]
            if not response_text:
                response_text = str(raw)
        except Exception as e:
            p = req.prompt.lower()
            if "malware" in p or "ransomware" in p or "beacon" in p:
                response_text = (
                    "**Local Rule Containment Playbook (Ransomware/Malware Beaconing)**:\n\n"
                    "1. **Host Isolation**: Disconnect the host from the network switch or disable its wireless adapter.\n"
                    "2. **Process Termination**: Stop the beaconing process and record its executable hash.\n"
                    "3. **Indicator Block**: Block all destination IP addresses and domains in the edge firewall rules.\n"
                    "4. **Telemetry Scan**: Run a full disk antivirus scan and check for registry persistence keys (Run/RunOnce)."
                )
            elif "privilege" in p or "escalation" in p:
                response_text = (
                    "**Local Rule Containment Playbook (Privilege Escalation)**:\n\n"
                    "1. **Session Termination**: Log out all active sessions of the compromised account.\n"
                    "2. **Privilege Revocation**: Temporarily downgrade the account's group memberships (e.g., Domain Admins).\n"
                    "3. **Credential Rotation**: Rotate the passwords of the compromised account and parent administrative handles.\n"
                    "4. **Audit Logs**: Inspect Sysmon Event ID 1 (Process Creation) and security log logon attempts (Event ID 4624)."
                )
            elif "tactic" in p or "mitre" in p or "execution" in p:
                response_text = (
                    "**Local Rule Detection Guide (MITRE ATT&CK Execution)**:\n\n"
                    "1. **Command Line Monitoring**: Audit command execution arguments (e.g., powershell -ep bypass, cmd /c).\n"
                    "2. **Script Execution Restrictions**: Enforce AppLocker or Software Restriction Policies (SRP) to block scripts.\n"
                    "3. **Scheduled Tasks**: Audit system scheduled tasks for unsigned binaries launching from Temp directories."
                )
            else:
                response_text = (
                    f"**Local Rule Fallback Response (AI engine connection failed: {e})**:\n\n"
                    "We are operating in Offline / Local Rules mode.\n\n"
                    "**General Security Recommendations**:\n"
                    "- Triage all alerts marked as *Critical* or *High* in the Alerts Console.\n"
                    "- Check the Live Monitor for anomalies in network connections (e.g., untrusted outbound ports)."
                )

    # Persist conversation message
    chat_entry = AIAnalysis(
        log_id=1,
        ai_provider="openai" if settings.openai_api_key else "local",
        model_name="gpt-4.1-mini",
        prompt_version="1.0",
        analysis_type="copilot_chat",
        input_summary=req.prompt,
        reasoning_explanation=response_text,
        correlation_id=conversation_id,
        status="completed",
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
    )
    db.add(chat_entry)
    db.commit()

    return AICopilotResponse(
        response=response_text,
        conversation_id=conversation_id
    )
