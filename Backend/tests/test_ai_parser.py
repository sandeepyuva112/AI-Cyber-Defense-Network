from __future__ import annotations

import json

import pytest

from app.ai.response_parser import AiResponseParser


def test_parser_accepts_valid_json():
    correlation_id = "corr-1"
    log_type = "windows_event_logs"

    model_output = {
        "incident_id": correlation_id,
        "log_type": log_type,
        "plain_english_attack_explanation": "Suspicious authentication activity detected.",
        "suspicious_activities": [
            {"activity": "Multiple failed logins", "evidence": ["EventID 4625 repeated"]}
        ],
        "classification": {"incident_type": "credential_access", "description": "Likely brute force"},
        "severity": {"level": "high", "score": 80, "rationale": "Multiple attempts"},
        "confidence": {"value": 0.7, "rationale": "Clear repeated patterns"},
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "tactics": ["credential access"],
            }
        ],
        "remediation": {
            "summary": "Harden authentication and investigate accounts.",
            "steps": ["Review account activity", "Enable MFA", "Lockout policy"],
            "priority": "high",
        },
        "executive_summary": {
            "title": "Suspicious sign-in behavior",
            "overview": "Failed login attempts were observed.",
            "key_findings": ["Repeated failed logins"],
            "impact": "Potential brute-force attempt",
            "next_actions": ["Investigate source IPs"],
        },
    }

    parser = AiResponseParser()
    report = parser.parse_incident_report(model_output, correlation_id, log_type)

    assert report.incident_id == correlation_id
    assert report.log_type == log_type
    assert report.severity.level in {"low", "medium", "high", "critical"}


def test_parser_extracts_json_from_text():
    correlation_id = "corr-2"
    log_type = "linux_syslog"

    payload = {
        "incident_id": correlation_id,
        "log_type": log_type,
        "plain_english_attack_explanation": "Recon activity likely.",
        "suspicious_activities": [],
        "classification": {"incident_type": "reconnaissance", "description": "Port scanning"},
        "severity": {"level": "medium", "score": 55, "rationale": "Unclear impact"},
        "confidence": {"value": 0.5, "rationale": "Limited evidence"},
        "mitre_attack": [],
        "remediation": {
            "summary": "Review network activity.",
            "steps": ["Check firewall logs"],
            "priority": "medium",
        },
        "executive_summary": {
            "title": "Possible recon",
            "overview": "Suspicious connection attempts.",
            "key_findings": [],
            "impact": "",
            "next_actions": [],
        },
    }

    # Text wrapper: inject JSON directly without an extra leading/trailing brace.
    text = "Some text before " + json.dumps(payload) + " trailing"

    parser = AiResponseParser()
    report = parser.parse_incident_report(text, correlation_id, log_type)
    assert report.incident_id == correlation_id

