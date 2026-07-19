from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class MITRETechnique(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID, e.g., T1059")
    technique_name: str = Field(..., description="Human readable technique name")
    tactics: list[str] = Field(default_factory=list, description="Related ATT&CK tactics")


class SuspiciousActivity(BaseModel):
    activity: str
    evidence: list[str] = Field(default_factory=list)


class IncidentClassification(BaseModel):
    incident_type: Literal[
        "malware",
        "phishing",
        "credential_access",
        "lateral_movement",
        "privilege_escalation",
        "persistence",
        "exfiltration",
        "command_and_control",
        "dos",
        "reconnaissance",
        "suspicious",
        "unknown",
    ] = "unknown"
    description: str = Field(..., description="Plain-English classification description")


class Severity(BaseModel):
    level: Literal["low", "medium", "high", "critical"]
    score: int = Field(..., ge=0, le=100, description="Numeric severity score 0-100")
    rationale: str


class Confidence(BaseModel):
    value: float = Field(..., ge=0.0, le=1.0)
    rationale: str


class RemediationRecommendation(BaseModel):
    summary: str
    steps: list[str] = Field(default_factory=list)
    priority: Literal["low", "medium", "high"] = "medium"


class ExecutiveSummary(BaseModel):
    title: str
    overview: str
    key_findings: list[str] = Field(default_factory=list)
    impact: str = ""
    next_actions: list[str] = Field(default_factory=list)


class AiIncidentReport(BaseModel):
    """Structured incident intelligence returned by the AI."""

    incident_id: str = Field(..., description="Client provided correlation ID if available")
    log_type: str

    plain_english_attack_explanation: str
    suspicious_activities: list[SuspiciousActivity] = Field(default_factory=list)

    classification: IncidentClassification
    severity: Severity
    confidence: Confidence

    mitre_attack: list[MITRETechnique] = Field(
        default_factory=list, description="Mapped MITRE ATT&CK techniques"
    )

    remediation: RemediationRecommendation
    executive_summary: ExecutiveSummary

    # Optional: pass-through structured evidence and model metadata
    raw: dict[str, Any] = Field(default_factory=dict, description="Raw model response")

