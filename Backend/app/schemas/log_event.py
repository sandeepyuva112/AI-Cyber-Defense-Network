from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class LogEvent(BaseModel):
    """Normalized log event.

    Parsers should populate as many fields as possible from the source log.
    For malformed logs, parsers MUST return at least one LogEvent instance
    and should set `event_type="malformed"`.
    """

    timestamp: Optional[datetime] = Field(
        default=None, description="Event timestamp (parsed/normalized)", examples=["2026-01-01T12:34:56Z"]
    )
    source: Optional[str] = Field(default=None, description="Log source/hostname/provider")

    ip: Optional[str] = Field(default=None, description="Primary IP (best-effort)")
    destination_ip: Optional[str] = Field(default=None, description="Destination IP (if present)")

    username: Optional[str] = Field(default=None, description="User/account associated with the event")

    event_id: Optional[str] = Field(default=None, description="Event identifier/code")

    process: Optional[str] = Field(default=None, description="Process/service/application")

    severity: Optional[str] = Field(
        default=None,
        description="Normalized severity string (e.g., Critical/High/Medium/Low/Informational or numeric-mapped)",
    )

    message: Optional[str] = Field(default=None, description="Human-readable event message")

    event_type: str = Field(
        default="unknown",
        description="Normalized event type/category (e.g., authentication, access, web, firewall, malformed, ...)",
    )

    ioc: list[str] = Field(default_factory=list, description="Indicators of compromise extracted from the log")

    threat_score: Optional[float] = Field(default=None, description="Threat score if present; otherwise None")

    # Optional raw retention for troubleshooting
    raw: dict[str, Any] = Field(default_factory=dict, description="Original parsed structure (best-effort)")

