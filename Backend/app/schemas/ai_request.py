from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, Field


LogType = Literal[
    "windows_event_logs",
    "linux_syslog",
    "firewall_logs",
    "authentication_logs",
    "network_logs",
]


class AnalyzeLogsRequest(BaseModel):
    correlation_id: str = Field(..., description="Client correlation ID for traceability")
    log_type: LogType

    # Provide either raw text or structured lines.
    log_text: Optional[str] = Field(None, description="Raw log text for analysis")
    log_lines: Optional[list[str]] = Field(None, description="Individual log lines")

    # Optional constraints
    max_output_tokens: Optional[int] = Field(1200, ge=128, le=4096)


class AnalyzeLogsResponse(BaseModel):
    report: dict

