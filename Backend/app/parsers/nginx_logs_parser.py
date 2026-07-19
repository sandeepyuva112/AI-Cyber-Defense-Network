from __future__ import annotations

import re
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, parse_datetime
from app.schemas.log_event import LogEvent


class NginxLogsParser(BaseLogParser):
    """Parse Nginx access logs (common combined format)."""

    # 127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 200 2326 "-" "UA"
    _combined_re = re.compile(
        r"^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<ts>[^\]]+)\]\s+\"(?P<method>\S+)\s+(?P<path>[^\s]+)\s+\S+\"\s+(?P<status>\d{3})\s+(?P<size>\S+)" 
        r"(?:\s+\"(?P<ref>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\")?"
    )

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            lines = [l for l in (text or "").splitlines() if l.strip()]
            if not lines:
                return [LogEvent(event_type="malformed", message=None, ioc=[], raw=raw)]

            events: list[LogEvent] = []
            for line in lines:
                m = self._combined_re.match(line.strip())
                if not m:
                    events.append(
                        LogEvent(
                            event_type="malformed",
                            message=line[:2000],
                            ioc=extract_iocs(line),
                            raw={"line": line},
                        )
                    )
                    continue

                ip = m.group("ip")
                user = m.group("user")
                ts = m.group("ts")
                status = int(m.group("status"))
                method = m.group("method")
                path = m.group("path")
                ua = m.group("ua")

                # Timestamp: 10/Oct/2000:13:55:36 -0700
                timestamp = None
                try:
                    from datetime import datetime as _dt

                    timestamp = _dt.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
                except Exception:
                    timestamp = parse_datetime(ts)

                severity = "Critical" if status >= 500 else "High" if status >= 400 else "Informational"
                event_type = "http" if method else "nginx_log"

                msg = f"{method} {path} -> {status}"
                iocs = extract_iocs(line)

                events.append(
                    LogEvent(
                        timestamp=timestamp,
                        source="nginx",
                        ip=ip,
                        destination_ip=None,
                        username=None if user == "-" else user,
                        event_id=str(status),
                        process="nginx",
                        severity=severity,
                        message=msg,
                        event_type=event_type,
                        ioc=iocs,
                        threat_score=None,
                        raw={"line": line, "ua": ua},
                    )
                )

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

