from __future__ import annotations

from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.windows_event_logs_parser import WindowsEventLogsParser
from app.parsers.syslog_parser import SyslogParser
from app.parsers.json_logs_parser import JsonLogsParser
from app.parsers.csv_logs_parser import CsvLogsParser
from app.parsers.apache_logs_parser import ApacheLogsParser
from app.parsers.nginx_logs_parser import NginxLogsParser
from app.parsers.firewall_logs_parser import FirewallLogsParser


def _normalize_log_type(log_type: Optional[str]) -> str:
    if not log_type:
        return "unknown"

    s = log_type.strip().lower().replace("-", "_").replace(" ", "_")

    aliases = {
        "windows_event_logs": "windows_event_logs",
        "windows": "windows_event_logs",
        "win_event_logs": "windows_event_logs",
        "syslog": "syslog",
        "linux_syslog": "syslog",
        "json": "json_logs",
        "json_logs": "json_logs",
        "csv": "csv_logs",
        "csv_logs": "csv_logs",
        "apache": "apache_logs",
        "apache_logs": "apache_logs",
        "nginx": "nginx_logs",
        "nginx_logs": "nginx_logs",
        "firewall": "firewall_logs",
        "firewall_logs": "firewall_logs",
    }

    return aliases.get(s, s)


def get_parser(log_type: Optional[str]) -> BaseLogParser:
    lt = _normalize_log_type(log_type)

    if lt == "windows_event_logs":
        return WindowsEventLogsParser()
    if lt == "syslog":
        return SyslogParser()
    if lt == "json_logs":
        return JsonLogsParser()
    if lt == "csv_logs":
        return CsvLogsParser()
    if lt == "apache_logs":
        return ApacheLogsParser()
    if lt == "nginx_logs":
        return NginxLogsParser()
    if lt == "firewall_logs":
        return FirewallLogsParser()

    # Unknown: return parser that yields a single malformed LogEvent-like output
    return JsonLogsParser()  # best effort fallback

