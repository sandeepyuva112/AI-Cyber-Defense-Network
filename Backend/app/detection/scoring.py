from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Evidence:
    rule_id: str
    rule_name: str
    weight: int  # contribution to score
    confidence: float  # contribution to confidence
    evidence: list[str]
    mitre: list[tuple[str, str, list[str]]]
    classification: str


def severity_from_weight(total_weight: int) -> tuple[str, int]:
    # total_weight is an arbitrary scale, map to 0-100.
    # Keep it deterministic and monotonic.
    score = max(0, min(100, int(total_weight * 10)))

    if score >= 90:
        return ("critical", score)
    if score >= 70:
        return ("high", score)
    if score >= 40:
        return ("medium", score)
    return ("low", score)


def aggregate_confidence(evidences: list[Evidence], has_ioc: bool) -> float:
    if not evidences:
        return 0.0

    # Weighted average; add small boost if we extracted IOCs.
    total = sum(max(1e-9, e.confidence) for e in evidences)
    base = sum(e.confidence for e in evidences) / len(evidences)
    boost = 0.08 if has_ioc else 0.0

    # clamp
    val = base + boost
    return max(0.0, min(1.0, float(val)))

