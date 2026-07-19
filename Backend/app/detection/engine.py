from __future__ import annotations

import time
from typing import Any

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

from .rules import match_rules
from .scoring import Evidence, aggregate_confidence, severity_from_weight


class DetectionEngine:
    """Deterministic (non-LLM) detection engine.

    Input: raw log text.
    Output: AiIncidentReport (schema-compatible).
    """

    def analyze(self, *, correlation_id: str, log_type: str, log_text: str) -> AiIncidentReport:
        start = time.time()

        matches, extracted_iocs = match_rules(log_text or "")
        has_ioc = bool(extracted_iocs)

        # Convert matches -> Evidence for scoring
        evidences: list[Evidence] = []
        for m in matches:
            mitre = m.mitre
            evidences.append(
                Evidence(
                    rule_id=m.rule_id,
                    rule_name=m.rule_name,
                    weight=m.weight,
                    confidence=m.confidence,
                    evidence=m.evidence,
                    mitre=mitre,
                    classification=m.classification,
                )
            )

        total_weight = sum(e.weight for e in evidences) if evidences else 0
        sev_level, sev_score = severity_from_weight(total_weight)
        conf_val = aggregate_confidence(evidences, has_ioc=has_ioc)

        # Pick classification by max weight; fallback unknown
        classification: str = "unknown"
        if evidences:
            classification = max(evidences, key=lambda e: e.weight).classification

        # Build suspicious activities
        suspicious_activities: list[SuspiciousActivity] = []
        for e in evidences[:6]:
            suspicious_activities.append(SuspiciousActivity(activity=e.rule_name, evidence=e.evidence))

        mitre_attack: list[MITRETechnique] = []
        for e in evidences:
            for tech_id, tech_name, tactics in e.mitre:
                mitre_attack.append(
                    MITRETechnique(
                        technique_id=tech_id,
                        technique_name=tech_name,
                        tactics=tactics,
                    )
                )

        # Deduplicate MITRE
        uniq_mitre: dict[str, MITRETechnique] = {m.technique_id: m for m in mitre_attack}
        mitre_attack = list(uniq_mitre.values())

        # Severity & Confidence rationales
        sev_rationale = (
            "Higher score indicates multiple corroborating indicators across the log. "
            f"Total evidence weight={total_weight}."
        )
        conf_rationale = (
            "Confidence reflects how specifically the log matches known heuristics/IOC patterns. "
            f"IOC extracted={has_ioc}."
        )

        severity = Severity(level=sev_level, score=sev_score, rationale=sev_rationale)
        confidence = Confidence(value=conf_val, rationale=conf_rationale)

        incident_type = classification  # schema expects allowed literals

        # Executive summary
        title = "Threat indicators detected" if evidences else "No strong threat indicators"
        overview = (
            "Deterministic engine identified likely suspicious behaviors from the provided log text. "
            "Evidence is based on IOC/behavior heuristics and is not a definitive verdict."
        )
        key_findings = [f"{e.rule_name}: {e.evidence[0] if e.evidence else ''}" for e in evidences]
        impact = (
            "Potential compromise involving credential abuse, execution, persistence, or C2." if evidences else ""
        )
        next_actions = [
            "Validate indicators against endpoint/network telemetry",
            "Review the referenced log events and correlate with host/process lineage",
            "Block/contain suspicious source IPs/domains if confirmed",
        ]

        exec_summary = ExecutiveSummary(
            title=title,
            overview=overview,
            key_findings=key_findings[:5],
            impact=impact,
            next_actions=next_actions,
        )

        remediation = RemediationRecommendation(
            summary="Perform targeted incident response steps based on the detected category.",
            steps=[
                "Collect additional logs: authentication, process creation, registry changes, and network flow",
                "Search for persistence mechanisms and remove unauthorized scheduled tasks/services/run keys",
                "Quarantine suspected payloads and check for persistence across reboots",
                "Hunt for lateral movement attempts and block related remote execution tooling",
            ],
            priority="high" if sev_score >= 70 else "medium",
        )

        report = AiIncidentReport(
            incident_id=correlation_id,
            log_type=str(log_type),
            plain_english_attack_explanation=(
                "Likely malicious activity inferred from log text heuristics. "
                "Use evidence below to guide verification and containment."
                if evidences
                else "No high-confidence threat patterns were found in the provided log text."
            ),
            suspicious_activities=suspicious_activities,
            classification=IncidentClassification(incident_type=incident_type, description="Heuristic deterministic classification"),
            severity=severity,
            confidence=confidence,
            mitre_attack=mitre_attack,
            remediation=remediation,
            executive_summary=exec_summary,
            raw={
                "correlation_id": correlation_id,
                "log_type": log_type,
                "evidence": [e.__dict__ for e in evidences],
                "ioc_extracted": extracted_iocs,
                "total_evidence_weight": total_weight,
                "engine_ms": int((time.time() - start) * 1000),
            },
        )

        return report

