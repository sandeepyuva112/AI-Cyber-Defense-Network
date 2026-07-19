from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from app.schemas.ai_incident import AiIncidentReport, RemediationRecommendation
from app.schemas.report_exports import (
    AffectedAsset,
    ConfidenceScore,
    EvidenceItem,
    ExecutiveReport,
    IOCReport,
    IndicatorOfCompromise,
    MITREAttackReport,
    MITRETechnique,
    Recommendation,
    RiskScore,
    ThreatSeverity,
    TimelineItem,
    ChartSpec,
)


def build_confidence(value: float, rationale: str) -> ConfidenceScore:
    return ConfidenceScore(value=value, rationale=rationale)


def build_risk_score(*, severity: int, confidence: float, rationale: str) -> RiskScore:
    # Simple production-safe heuristic: high severity increases risk; low confidence increases uncertainty.
    # Clamp 0..100.
    base = float(severity)
    adjusted = base * (0.7 + 0.3 * confidence)
    adjusted = max(0.0, min(100.0, adjusted))
    return RiskScore(score=adjusted, rationale=rationale)


def _extract_ioc_candidates(text: str) -> list[str]:
    if not text:
        return []

    # Heuristic IOC patterns (best-effort)
    patterns = [
        r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",  # IPv4
        r"\b(?:[a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}\b",  # MAC
        r"\b[A-Fa-f0-9]{32,64}\b",  # hashes (md5/sha variants)
        r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",  # domains
    ]

    out: list[str] = []
    for p in patterns:
        for m in re.findall(p, text):
            if m not in out:
                out.append(m)
    return out


def build_ioc_report(ai_report: AiIncidentReport) -> IOCReport:
    evidence_blob = "\n".join(e for sa in ai_report.suspicious_activities for e in sa.evidence)
    candidates = _extract_ioc_candidates(evidence_blob)

    indicators: list[IndicatorOfCompromise] = []
    for c in candidates:
        indicators.append(IndicatorOfCompromise(ioc=c, ioc_type=None, confidence=None))
    return IOCReport(indicators=indicators)


def build_mitre_report(mitre_items: list[Any]) -> MITREAttackReport:
    techniques: list[MITRETechnique] = []
    for t in mitre_items:
        techniques.append(
            MITRETechnique(
                technique_id=t.technique_id,
                technique_name=t.technique_name,
                tactics=list(getattr(t, "tactics", []) or []),
            )
        )
    return MITREAttackReport(techniques=techniques)


def build_recommendations(remediation: Any) -> list[Recommendation]:
    # remediation is RemediationRecommendation schema
    return [
        Recommendation(
            priority=remediation.priority,
            summary=remediation.summary,
            steps=list(remediation.steps or []),
        )
    ]


def build_evidence(ai_report: AiIncidentReport) -> list[EvidenceItem]:
    items: list[EvidenceItem] = []
    for sa in ai_report.suspicious_activities:
        for ev in sa.evidence or []:
            items.append(EvidenceItem(evidence=ev, source=sa.activity))

    # Fallback: include the suspicious activity descriptions themselves
    if not items:
        for sa in ai_report.suspicious_activities:
            items.append(EvidenceItem(evidence=sa.activity, source="suspicious_activity"))

    return items


def build_timeline(ai_report: AiIncidentReport) -> list[TimelineItem]:
    # No explicit timestamps in current schema; derive ordering from evidence list.
    timeline: list[TimelineItem] = []
    for idx, sa in enumerate(ai_report.suspicious_activities):
        evidence = list(sa.evidence or [])
        timeline.append(
            TimelineItem(
                timestamp=None,
                event=sa.activity,
                evidence=evidence,
            )
        )
    return timeline


def build_affected_assets_from_evidence(ai_report: AiIncidentReport) -> list[AffectedAsset]:
    # Best-effort extraction for now: look for common asset markers in evidence.
    evidence_blob = "\n".join(e for sa in ai_report.suspicious_activities for e in sa.evidence)
    assets: list[AffectedAsset] = []

    host_matches = re.findall(r"\b(?:host|hostname|server)[:=\s]+([^\s,;]+)", evidence_blob, flags=re.IGNORECASE)
    ip_matches = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", evidence_blob)
    domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", evidence_blob)

    seen: set[str] = set()
    for h in host_matches + ip_matches + domain_matches:
        if h in seen:
            continue
        seen.add(h)
        assets.append(AffectedAsset(asset=h, asset_type=None, description=None, evidence=[]))

    return assets


def build_charts(ai_report: AiIncidentReport) -> list[ChartSpec]:
    # Charts are generic spec objects.
    charts: list[ChartSpec] = []

    # Severity chart (single value)
    charts.append(
        ChartSpec(
            chart_type="bar",
            title="Threat Severity",
            series=[{"label": ai_report.severity.level, "value": ai_report.severity.score}],
        )
    )

    # MITRE technique count
    tech_counts: dict[str, int] = {}
    for t in ai_report.mitre_attack:
        tech_counts[t.technique_name] = tech_counts.get(t.technique_name, 0) + 1

    charts.append(
        ChartSpec(
            chart_type="bar",
            title="MITRE Techniques",
            series=[{"label": k, "value": v} for k, v in tech_counts.items()] or [{"label": "N/A", "value": 0}],
        )
    )

    return charts

