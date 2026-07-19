from __future__ import annotations

import csv
import json
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import Any, Iterable, Optional


# --- Regex helpers ---
IP_V4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
IP_GENERIC_RE = re.compile(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b|\b(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}\b")

URL_RE = re.compile(r"\bhttps?://[^\s\"']+\b", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")


def extract_ips(text: str) -> list[str]:
    ips: list[str] = []
    for m in IP_GENERIC_RE.finditer(text):
        s = m.group(0)
        try:
            ip_address(s)
            if s not in ips:
                ips.append(s)
        except Exception:
            pass
    return ips


def extract_iocs(text: str) -> list[str]:
    iocs: list[str] = []
    for rx in (URL_RE, IP_GENERIC_RE, DOMAIN_RE):
        for m in rx.finditer(text or ""):
            val = m.group(0)
            if val not in iocs:
                iocs.append(val)
    return iocs


def parse_datetime(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, datetime):
        return value

    s = str(value).strip()
    if not s:
        return None

    # Common variants
    fmts = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",  # syslog (no year)
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%dT%H:%M:%S%z",
    ]

    # Best effort for syslog without year: assume current year in UTC.
    for fmt in fmts:
        try:
            dt = datetime.strptime(s, fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now(timezone.utc).year, tzinfo=timezone.utc)
            return dt
        except Exception:
            continue

    # ISO fallback
    try:
        # Handle trailing Z
        if s.endswith("Z"):
            s2 = s[:-1] + "+00:00"
            return datetime.fromisoformat(s2)
        return datetime.fromisoformat(s)
    except Exception:
        return None


_SEV_MAP = {
    "emerg": "Critical",
    "alert": "Critical",
    "crit": "Critical",
    "critical": "Critical",
    "err": "High",
    "error": "High",
    "warning": "Medium",
    "warn": "Medium",
    "notice": "Low",
    "info": "Informational",
    "informational": "Informational",
    "debug": "Low",
}


def normalize_severity(value: Any, *, fallback: Optional[str] = None) -> Optional[str]:
    if value is None:
        return fallback

    s = str(value).strip().lower()
    if not s:
        return fallback

    # Numeric syslog severity (0-7)
    try:
        n = int(float(s))
        # 0-1 critical, 2-3 high, 4 medium, 5 low, 6-7 informational/low
        if n <= 1:
            return "Critical"
        if n <= 3:
            return "High"
        if n == 4:
            return "Medium"
        if n == 5:
            return "Low"
        return "Informational"
    except Exception:
        pass

    return _SEV_MAP.get(s, fallback)


def safe_json_loads(text: str) -> Optional[dict[str, Any]]:
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else {"value": obj}
    except Exception:
        return None


def split_json_lines(text: str) -> Iterable[str]:
    for line in (text or "").splitlines():
        if line.strip():
            yield line


def detect_csv_dialect(sample: str) -> csv.Dialect:
    snip = sample[:8000]
    return csv.Sniffer().sniff(snip, delimiters=[",", ";", "\t", "|", " "])


def get_first(lst: list[Any]) -> Any:
    return lst[0] if lst else None

