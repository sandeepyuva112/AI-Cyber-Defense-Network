from __future__ import annotations

from datetime import datetime

import pytest

from app.reports.report_builder import IncidentReportBuilder, ReportBuildContext
from app.reports.exporters import JSONExporter, HTMLExporter
from app.schemas.ai_incident import (
    AiIncidentReport,
    Confidence,
    ExecutiveSummary,
    IncidentClassification,
    MITRETechnique,
    RemediationRecommendation,
    Severity,
    SuspiciousActivity,
)


@pytest.fixture()
def ai_report() -> AiIncidentReport:
    return AiIncidentReport(
        incident_id="corr-1",
        log_type="linux_syslog",
        plain_english_attack_explanation="Possible credential abuse.",
        suspicious_activities=[
            SuspiciousActivity(activity="Multiple failed logins", evidence=["User admin failed 10 times"]),
            SuspiciousActivity(activity="Password spray detected", evidence=["Rate limit triggered", "Possible domain evil.com"]),
        ],
        classification=IncidentClassification(
            incident_type="credential_access",
            description="Likely password spraying leading to credential access attempts.",
        ),
        severity=Severity(level="high", score=80, rationale="Many failed attempts across accounts."),
        confidence=Confidence(value=0.7, rationale="Evidence supports suspicious authentication patterns."),
        mitre_attack=[
            MITRETechnique(technique_id="T1110", technique_name="Brute Force", tactics=["credential-access"])
        ],
        remediation=RemediationRecommendation(
            summary="Enforce MFA and block abusive IPs.",
            steps=["Enable MFA", "Block offending IPs", "Review authentication logs"],
            priority="high",
        ),
        executive_summary=ExecutiveSummary(
            title="Credential Access Incident",
            overview="An attacker appears to be attempting to compromise credentials.",
            key_findings=["Multiple failed logins", "Rate limit triggered"],
            impact="Potential account takeover attempts.",
            next_actions=["Investigate accounts", "Hunt for successful logons"],
        ),
        raw={"model": "test"},
    )


def test_report_builder_includes_sections(ai_report: AiIncidentReport) -> None:
    builder = IncidentReportBuilder()
    ctx = ReportBuildContext(report_id=ai_report.incident_id, report_type="incident", generated_at=datetime.utcnow())
    full = builder.build_full_report(ai_report=ai_report, ctx=ctx)

    assert full.executive_report.executive_summary.overview
    assert full.technical_report.incident_summary.description
    assert full.technical_report.evidence
    assert full.technical_report.mitre_attack.techniques


def test_exporters_json_html(ai_report: AiIncidentReport) -> None:
    builder = IncidentReportBuilder()
    ctx = ReportBuildContext(report_id=ai_report.incident_id, report_type="incident", generated_at=datetime.utcnow())
    full = builder.build_full_report(ai_report=ai_report, ctx=ctx)

    j = JSONExporter().export(full)
    assert "executive_report" in j
    assert "technical_report" in j

    html = HTMLExporter().export(full)
    assert "Executive Summary" in html
    assert "MITRE" in html or "ATT" in html

