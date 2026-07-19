from __future__ import annotations

from typing import Optional, Any

from app.ai.openai_responses_client import OpenAIResponsesClient
from app.ai.prompt_templates import get_prompt_bundle
from app.ai.response_parser import AiResponseParser
from app.ai.token_management import truncate_to_token_budget
from app.ai.error_handling import AiServiceError
from app.schemas.ai_incident import AiIncidentReport
from app.schemas.ai_request import LogType

from app.detection.engine import DetectionEngine


class AiEngineService:

    def __init__(
        self,
        openai_client: Optional[OpenAIResponsesClient] = None,
        parser: Optional[AiResponseParser] = None,
    ) -> None:
        self.openai_client = openai_client or OpenAIResponsesClient()
        self.parser = parser or AiResponseParser()

    async def analyze_logs(
        self,
        *,
        correlation_id: str,
        log_type: LogType,
        log_text: str,
        max_output_tokens: int,
    ) -> AiIncidentReport:
        bundle = get_prompt_bundle()

        # Token management: cap input size
        max_input_tokens = 3000
        safe_log_content = truncate_to_token_budget(log_text, max_input_tokens=max_input_tokens)

        # 1. Deterministic detection pass
        deterministic = DetectionEngine()
        try:
            det_report = deterministic.analyze(
                correlation_id=correlation_id,
                log_type=str(log_type),
                log_text=safe_log_content,
            )
        except Exception:
            det_report = None

        if det_report is not None and det_report.suspicious_activities:
            return det_report

        # 2. Try OpenAI
        raw = None
        model_text = None
        try:
            from app.core.config import settings
            if settings.openai_api_key:
                prompt = bundle.analyze.format(
                    log_type=log_type,
                    correlation_id=correlation_id,
                    log_content=safe_log_content,
                )
                raw = await self.openai_client.analyze(
                    system=bundle.system,
                    prompt=prompt,
                    max_output_tokens=max_output_tokens,
                )

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
                                        model_text = c["text"]
                                        break
                            if model_text:
                                break

                if model_text is None:
                    model_text = raw
        except Exception:
            pass

        if model_text is not None:
            try:
                return self.parser.parse_incident_report(model_text, correlation_id, log_type)
            except Exception:
                pass

        # 3. Contextual Offline Fallback Report
        from app.schemas.ai_incident import (
            AiIncidentReport,
            IncidentClassification,
            Severity,
            Confidence,
            RemediationRecommendation,
            ExecutiveSummary,
            MITRETechnique,
            SuspiciousActivity,
        )

        content_lower = safe_log_content.lower()
        if "4625" in content_lower or "failed logon" in content_lower:
            incident_type = "credential_access"
            desc = "Detected multiple failed logon attempts matching Windows Security Event ID 4625 (Logon Failure)."
            severity_level = "high"
            severity_score = 75
            mitre = [
                MITRETechnique(
                    technique_id="T1110",
                    technique_name="Brute Force",
                    tactics=["credential_access"],
                )
            ]
            activities = [
                SuspiciousActivity(
                    activity="Brute Force Login Attempt",
                    evidence=["Multiple Event ID 4625 records found in security event logs"],
                )
            ]
            steps = ["Isolate endpoint immediately", "Reset user account passwords", "Enable account lockout policies"]
        elif "malware" in content_lower or "ransomware" in content_lower or "virus" in content_lower:
            incident_type = "malware"
            desc = "Indicators of suspected malicious software execution or beaconing activities."
            severity_level = "critical"
            severity_score = 90
            mitre = [
                MITRETechnique(
                    technique_id="T1204",
                    technique_name="User Execution",
                    tactics=["execution"],
                )
            ]
            activities = [
                SuspiciousActivity(
                    activity="Malicious Executable Launch",
                    evidence=["Anomalous process launch from local temporary directory"],
                )
            ]
            steps = [
                "Run full system scan",
                "Identify network destination IP and block on firewalls",
                "Isolate machine from core subnet",
            ]
        else:
            incident_type = "unknown"
            desc = "Offline local rule evaluation completed with no critical signatures triggered."
            severity_level = "low"
            severity_score = 15
            mitre = []
            activities = []
            steps = [
                "Monitor live events tail for anomalous network queries",
                "Check for software update compliance",
            ]

        return AiIncidentReport(
            incident_id=correlation_id,
            log_type=str(log_type),
            plain_english_attack_explanation=desc,
            suspicious_activities=activities,
            classification=IncidentClassification(incident_type=incident_type, description=desc),
            severity=Severity(level=severity_level, score=severity_score, rationale="Local rules heuristics match"),
            confidence=Confidence(value=0.8, rationale="Local rule signatures matched log fields"),
            mitre_attack=mitre,
            remediation=RemediationRecommendation(
                summary="Offline Containment Procedure",
                steps=steps,
                priority="high" if severity_score > 50 else "medium",
            ),
            executive_summary=ExecutiveSummary(
                title=f"Local Heuristic Analysis - {incident_type.upper()}",
                overview=desc,
                key_findings=[desc],
                impact="Potential unauthorized access or endpoint compromise if left untreated.",
                next_actions=steps,
            ),
        )
