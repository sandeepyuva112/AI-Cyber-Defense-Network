from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AiServiceError(Exception):
    message: str
    code: str
    details: str = ""


def normalize_openai_error(payload: object) -> str:
    if isinstance(payload, dict):
        # best-effort extraction
        msg = payload.get("message") or payload.get("error") or payload.get("detail")
        return str(msg) if msg is not None else str(payload)
    return str(payload)

