from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PromptBundle:
    system: str
    analyze: str


def get_prompt_bundle() -> PromptBundle:
    system = (
        "You are a cybersecurity incident analysis engine. "
        "You will receive security logs. "
        "Return ONLY valid JSON that conforms to the required schema. "
        "Write all explanations in plain English. "
        "Map findings to MITRE ATT&CK technique IDs when possible. "
        "Never output markdown."
    )

    analyze = (
        "Analyze the following {log_type} logs. "
        "Requirements: "
        "1) Explain the most likely attacks in plain English. "
        "2) Detect suspicious activities with evidence. "
        "3) Classify the incident type and describe why. "
        "4) Assign severity (low/medium/high/critical) with a 0-100 score and rationale. "
        "5) Estimate confidence (0.0-1.0) with rationale. "
        "6) Map findings to MITRE ATT&CK with technique IDs and tactics when possible. "
        "7) Recommend remediation steps. "
        "8) Produce an executive summary. "
        "Output JSON with keys exactly matching the schema fields.\n\n"
        "CORRELATION ID: {correlation_id}\n\n"
        "LOGS:\n{log_content}\n"
    )

    return PromptBundle(system=system, analyze=analyze)

