from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class ReportMetadata(BaseModel):
    report_id: str = Field(..., description="Client correlation id or generated report identifier")
    incident_id: str | None = None
    report_type: str
    generated_at: datetime
    version: str = "1.0"


class ExecutiveReport(BaseModel):
    title: str
    overview: str
    key_findings: list[str] = Field(default_factory=list)
    impact: str = ""
    next_actions: list[str] = Field(default_factory=list)


class IncidentSummary(BaseModel):
    incident_classification: str
    description: str
    ai_explanation: str


class ThreatSeverity(BaseModel):
    level: Literal["low", "medium", "high", "critical"]
    score: int = Field(..., ge=0, le=100)
    rationale: str


class RiskScore(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    rationale: str


class ConfidenceScore(BaseModel):
    value: float = Field(..., ge=0.0, le=1.0)
    rationale: str


class TimelineItem(BaseModel):
    timestamp: datetime | None = None
    event: str
    evidence: list[str] = Field(default_factory=list)


class AffectedAsset(BaseModel):
    asset: str
    asset_type: str | None = None
    description: str | None = None
    evidence: list[str] = Field(default_factory=list)


class Recommendation(BaseModel):
    priority: Literal["low", "medium", "high"] = "medium"
    summary: str
    steps: list[str] = Field(default_factory=list)


class EvidenceItem(BaseModel):
    evidence: str
    source: str | None = None


class IndicatorOfCompromise(BaseModel):
    ioc: str
    ioc_type: str | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class MITRETechnique(BaseModel):
    technique_id: str
    technique_name: str
    tactics: list[str] = Field(default_factory=list)


class MITREAttackReport(BaseModel):
    techniques: list[MITRETechnique] = Field(default_factory=list)


class IOCReport(BaseModel):
    indicators: list[IndicatorOfCompromise] = Field(default_factory=list)


class ChartSpec(BaseModel):
    # Keep generic: front-end can interpret as needed.
    chart_type: str
    title: str
    series: list[dict[str, Any]] = Field(default_factory=list)


class TechnicalReport(BaseModel):
    report_metadata: ReportMetadata

    incident_summary: IncidentSummary

    threat_severity: ThreatSeverity
    risk_score: RiskScore
    confidence_score: ConfidenceScore

    timeline: list[TimelineItem] = Field(default_factory=list)

    affected_assets: list[AffectedAsset] = Field(default_factory=list)

    mitre_attack: MITREAttackReport

    indicators_of_compromise: IOCReport

    ai_explanation: str
    recommended_response_actions: list[Recommendation] = Field(default_factory=list)

    evidence: list[EvidenceItem] = Field(default_factory=list)

    charts: list[ChartSpec] = Field(default_factory=list)


class ExecutiveReportWrapper(BaseModel):
    report_metadata: ReportMetadata

    executive_summary: ExecutiveReport

    threat_severity: ThreatSeverity
    risk_score: RiskScore
    confidence_score: ConfidenceScore

    timeline: list[TimelineItem] = Field(default_factory=list)

    affected_assets: list[AffectedAsset] = Field(default_factory=list)

    indicators_of_compromise: list[IndicatorOfCompromise] = Field(default_factory=list)

    mitre_attack: MITREAttackReport


class IncidentReportWrapper(BaseModel):
    report_metadata: ReportMetadata
    incident_summary: IncidentSummary
    executive_summary: ExecutiveReport
    threat_severity: ThreatSeverity
    risk_score: RiskScore
    confidence_score: ConfidenceScore


class FullIncidentReport(BaseModel):
    executive_report: ExecutiveReportWrapper
    technical_report: TechnicalReport
    incident_report: IncidentReportWrapper

    # Convenience: include raw source for auditability.
    source_raw: dict[str, Any] = Field(default_factory=dict)


# Export objects
class ExportFormat(BaseModel):
    format: Literal["pdf", "html", "json"]

