from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from app.reports.report_utils import (
    build_affected_assets_from_evidence,
    build_charts,
    build_confidence,
    build_evidence,
    build_mitre_report,
    build_ioc_report,
    build_recommendations,
    build_risk_score,
    build_timeline,
)
from app.schemas.ai_incident import AiIncidentReport
from app.schemas.report_exports import (
    AffectedAsset,
    ConfidenceScore,
    EvidenceItem,
    ExecutiveReport,
    ExecutiveReportWrapper,
    FullIncidentReport,
    IncidentReportWrapper,
    IncidentSummary,
    IndicatorOfCompromise,
    MITREAttackReport,
    MITRETechnique,
    RiskScore,
    Recommendation,
    ThreatSeverity,
    TechnicalReport,
    TimelineItem,
    ReportMetadata,
)


DEFAULT_REPORT_VERSION = "1.0"


@dataclass(frozen=True)
class ReportBuildContext:
    report_id: str
    report_type: str
    generated_at: datetime
    version: str = DEFAULT_REPORT_VERSION


class IncidentReportBuilder:
    def build_full_report(
        self,
        *,
        ai_report: AiIncidentReport,
        ctx: ReportBuildContext,
    ) -> FullIncidentReport:
        metadata = ReportMetadata(
            report_id=ctx.report_id,
            incident_id=ai_report.incident_id,
            report_type=ctx.report_type,
            generated_at=ctx.generated_at,
            version=ctx.version,
        )

        # Shared section building
        threat_severity = ThreatSeverity(
            level=ai_report.severity.level,
            score=ai_report.severity.score,
            rationale=ai_report.severity.rationale,
        )
        confidence = build_confidence(ai_report.confidence.value, ai_report.confidence.rationale)
        risk_score = build_risk_score(
            severity=ai_report.severity.score,
            confidence=ai_report.confidence.value,
            rationale=ai_report.classification.description,
        )

        incident_summary = IncidentSummary(
            incident_classification=ai_report.classification.incident_type,
            description=ai_report.classification.description,
            ai_explanation=ai_report.plain_english_attack_explanation,
        )

        timeline = build_timeline(ai_report)
        affected_assets = build_affected_assets_from_evidence(ai_report)
        recommendations = build_recommendations(ai_report.remediation)
        evidence_items = build_evidence(ai_report)

        mitre_attack = build_mitre_report(ai_report.mitre_attack)
        iocs = build_ioc_report(ai_report)

        charts = build_charts(ai_report)

        exec_summary = ExecutiveReport(
            title=ai_report.executive_summary.title,
            overview=ai_report.executive_summary.overview,
            key_findings=ai_report.executive_summary.key_findings,
            impact=ai_report.executive_summary.impact,
            next_actions=ai_report.executive_summary.next_actions,
        )

        executive_report = ExecutiveReportWrapper(
            report_metadata=metadata,
            executive_summary=exec_summary,
            threat_severity=threat_severity,
            risk_score=risk_score,
            confidence_score=confidence,
            timeline=timeline,
            affected_assets=affected_assets,
            indicators_of_compromise=iocs.indicators,
            mitre_attack=mitre_attack,
        )

        technical_report = TechnicalReport(
            report_metadata=metadata,
            incident_summary=incident_summary,
            threat_severity=threat_severity,
            risk_score=risk_score,
            confidence_score=confidence,
            timeline=timeline,
            affected_assets=affected_assets,
            mitre_attack=mitre_attack,
            indicators_of_compromise=iocs,
            ai_explanation=ai_report.plain_english_attack_explanation,
            recommended_response_actions=recommendations,
            evidence=evidence_items,
            charts=charts,
        )

        incident_report = IncidentReportWrapper(
            report_metadata=metadata,
            incident_summary=incident_summary,
            executive_summary=exec_summary,
            threat_severity=threat_severity,
            risk_score=risk_score,
            confidence_score=confidence,
        )

        return FullIncidentReport(
            executive_report=executive_report,
            technical_report=technical_report,
            incident_report=incident_report,
            source_raw=ai_report.model_dump(mode="json"),
        )

