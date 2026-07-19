from __future__ import annotations

import re
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, extract_ips, normalize_severity, parse_datetime
from app.schemas.log_event import LogEvent


class FirewallLogsParser(BaseLogParser):
    """Best-effort parser for common firewall logs.

    Supports:
    - key/value lines: src=1.2.3.4 dst=5.6.7.8 user=bob action=deny
    - tokenized: ALLOW/deny traffic src -> dst user
    """

    _kv_pairs_re = re.compile(r"(?P<key>[A-Za-z0-9_\-]+)=(?P<val>[^\s]+)")

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            lines = [l for l in (text or "").splitlines() if l.strip()]
            if not lines:
                return [LogEvent(event_type="malformed", message=None, ioc=[], raw=raw)]

            events: list[LogEvent] = []
            for line in lines:
                events.append(self._from_line(line))
            return events
        except Exception:
            return [
                LogEvent(
                    event_type="malformed",
                    message=(text or "")[:2000] or None,
                    ioc=extract_iocs(text or ""),
                    raw=raw,
                )
            ]

    def _from_line(self, line: str) -> LogEvent:
        try:
            kv = {m.group("key").lower(): m.group("val") for m in self._kv_pairs_re.finditer(line or "")}

            src = kv.get("src") or kv.get("source") or kv.get("src_ip")
            dst = kv.get("dst") or kv.get("dest") or kv.get("destination") or kv.get("dst_ip")
            user = kv.get("user") or kv.get("username") or kv.get("account")
            action = kv.get("action") or kv.get("act") or kv.get("decision")
            severity_raw = kv.get("severity") or kv.get("level")
            sev = normalize_severity(severity_raw)

            # timestamp best-effort
            ts = kv.get("time") or kv.get("timestamp") or kv.get("ts")
            timestamp = parse_datetime(ts)
            if not timestamp:
                # try ISO in raw line
                iso = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s]*", line or "")
                timestamp = parse_datetime(iso.group(0)) if iso else None

            event_id = kv.get("eventid") or kv.get("event_id")
            process = kv.get("service") or kv.get("app")
            process = process if process else "firewall"

            ips = extract_ips(line)
            if not src and ips:
                src = ips[0]
            if not dst and len(ips) > 1:
                dst = ips[1]

            iocs = extract_iocs(line)

            # event type
            low = (line or "").lower()
            if action and action.lower() in {"deny", "blocked", "block", "drop"}:
                event_type = "firewall_deny"
                severity = sev or "High"
            elif action and action.lower() in {"allow", "pass", "accept"}:
                event_type = "firewall_allow"
                severity = sev or "Informational"
            elif "deny" in low or "block" in low or "drop" in low:
                event_type = "firewall_deny"
                severity = sev or "High"
            else:
                event_type = "firewall"
                severity = sev

            message = line[:2000]

            return LogEvent(
                timestamp=timestamp,
                source="firewall",
                ip=str(src) if src else (ips[0] if ips else None),
                destination_ip=str(dst) if dst else (ips[1] if len(ips) > 1 else None),
                username=str(user) if user else None,
                event_id=str(event_id) if event_id else None,
                process=str(process) if process else None,
                severity=severity,
                message=message,
                event_type=event_type,
                ioc=iocs,
                threat_score=None,
                raw={"line": line, "kv": kv},
            )
        except Exception:
            ips = extract_ips(line or "")
            return LogEvent(
                event_type="malformed",
                message=(line or "")[:2000] or None,
                ip=ips[0] if ips else None,
                destination_ip=ips[1] if len(ips) > 1 else None,
                ioc=extract_iocs(line or ""),
                threat_score=None,
                raw={"line": line},
            )

