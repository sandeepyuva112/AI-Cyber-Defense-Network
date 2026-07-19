from __future__ import annotations

import re
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, extract_ips, normalize_severity, parse_datetime
from app.schemas.log_event import LogEvent


class SyslogParser(BaseLogParser):
    """Parse RFC3164/RFC5424-ish syslog lines."""

    # Examples:
    # <34>Oct 11 22:14:15 hostname sshd[123]: Failed password for invalid user test from 1.2.3.4 port 22
    # <165>1 2020-01-01T00:00:00Z host app - - - message
    _rfc5424_re = re.compile(
        r"^<(?P<pri>\d+)>(?:(?P<ver>\d+)\s+)?(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>\S+)\s+(?P<rest>.*)$"
    )
    _rfc3164_re = re.compile(
        r"^<(?P<pri>\d+)>(?P<ts>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<proc>[^:]+):\s*(?P<msg>.*)$"
    )

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            line = (text or "").strip()
            if not line:
                return [
                    LogEvent(
                        message=None,
                        event_type="malformed",
                        ioc=[],
                        raw=raw,
                    )
                ]

            m5424 = self._rfc5424_re.match(line)
            if m5424:
                pri = int(m5424.group("pri"))
                ts = m5424.group("ts")
                host = m5424.group("host")
                proc = m5424.group("proc")
                rest = m5424.group("rest")
                # split severity from pri: facility*8 + severity
                sev_num = pri % 8
                sev = normalize_severity(sev_num)
                timestamp = parse_datetime(ts)
                # For RFC5424, rest begins after proc and may contain structured data
                msg = rest
            else:
                m3164 = self._rfc3164_re.match(line)
                if not m3164:
                    raise ValueError("Unrecognized syslog format")
                pri = int(m3164.group("pri"))
                sev = normalize_severity(pri % 8)
                timestamp = parse_datetime(m3164.group("ts"))
                host = m3164.group("host")
                proc = m3164.group("proc").strip()
                msg = m3164.group("msg")

            ips = extract_ips(msg)
            ip = ips[0] if ips else None
            dst = ips[1] if len(ips) > 1 else None
            iocs = extract_iocs(msg)

            # event type best-effort
            low_msg = (msg or "").lower()
            if any(k in low_msg for k in ("failed password", "invalid user", "authentication failure")):
                event_type = "authentication"
            elif any(k in low_msg for k in ("accepted password", "session opened")):
                event_type = "authentication_success"
            elif any(k in low_msg for k in ("sshd", "sudo")):
                event_type = "access"
            else:
                event_type = "syslog"

            return [
                LogEvent(
                    timestamp=timestamp,
                    source=host,
                    ip=ip,
                    destination_ip=dst,
                    username=None,
                    event_id=None,
                    process=proc,
                    severity=sev,
                    message=msg,
                    event_type=event_type,
                    ioc=iocs,
                    threat_score=None,
                    raw=raw,
                )
            ]
        except Exception:
            ips = extract_ips(text or "")
            return [
                LogEvent(
                    timestamp=None,
                    source=None,
                    ip=ips[0] if ips else None,
                    destination_ip=ips[1] if len(ips) > 1 else None,
                    username=None,
                    event_id=None,
                    process=None,
                    severity=None,
                    message=(text or "")[:2000] or None,
                    event_type="malformed",
                    ioc=extract_iocs(text or ""),
                    threat_score=None,
                    raw=raw,
                )
            ]

