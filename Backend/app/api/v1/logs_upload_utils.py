from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Any, Optional

from app.parsers.factory import get_parser


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def detect_log_type_from_filename(filename: Optional[str]) -> str | None:
    if not filename:
        return None

    name = filename.lower()
    if name.endswith(".evtx"):
        return "windows_event_logs"
    if name.endswith(".syslog") or name.endswith(".log") or name.startswith("syslog"):
        # syslog is ambiguous; best-effort.
        return "syslog"
    if name.endswith(".csv"):
        return "csv_logs"
    if name.endswith(".json"):
        return "json_logs"
    if name.endswith(".xml"):
        # No XML parser yet; caller should map to best-effort.
        return "json_logs"
    if name.endswith(".txt") or name.endswith(".log.txt"):
        return "unknown"
    return None


def parse_uploaded_log(
    *,
    raw_bytes: bytes,
    log_type: str | None,
    source_filename: str | None,
    metadata: Optional[dict[str, Any]] = None,
) -> tuple[str, list[dict[str, Any]]]:
    """Parse uploaded log bytes and return:
    - decoded text (best-effort)
    - normalized LogEvent dict payloads

    This function is intentionally parser-agnostic and reuses the existing
    get_parser(...) factory and parser implementations.
    """

    # Decode with best-effort fallbacks.
    try:
        text = raw_bytes.decode("utf-8")
    except Exception:
        text = raw_bytes.decode("latin-1", errors="replace")

    resolved_type = (log_type or detect_log_type_from_filename(source_filename) or "unknown")

    parser = get_parser(resolved_type)
    events = parser.parse(text, metadata=metadata or {"filename": source_filename})

    # Convert Pydantic schema to plain dicts.
    events_payload = [e.model_dump(mode="python", exclude_none=False) for e in events]

    return text, events_payload


def best_effort_events_count(events_payload: list[dict[str, Any]]) -> int:
    return len(events_payload)


def utc_now() -> datetime:
    return datetime.utcnow()

