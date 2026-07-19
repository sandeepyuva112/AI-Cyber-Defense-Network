from __future__ import annotations

import json
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, extract_ips, normalize_severity, parse_datetime
from app.schemas.log_event import LogEvent


class JsonLogsParser(BaseLogParser):
    """Parse JSON log entries: JSON Lines or single JSON object."""

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            s = (text or "").strip()
            if not s:
                return [LogEvent(event_type="malformed", message=None, ioc=[], raw=raw)]

            # JSON Lines (multiple objects)
            if "\n" in s and s.lstrip().startswith("{"):
                events: list[LogEvent] = []
                for line in s.splitlines():
                    if not line.strip():
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict):
                            events.append(self._from_obj(obj, raw_obj=obj))
                        else:
                            events.append(
                                LogEvent(
                                    event_type="malformed",
                                    message=str(obj)[:2000],
                                    ioc=extract_iocs(str(obj)),
                                    raw={"value": obj},
                                )
                            )
                    except Exception:
                        events.append(
                            LogEvent(
                                event_type="malformed",
                                message=line[:2000],
                                ioc=extract_iocs(line),
                                raw={"line": line},
                            )
                        )
                return events

            # Single object
            obj = json.loads(s)
            if not isinstance(obj, dict):
                return [
                    LogEvent(
                        event_type="malformed",
                        message=str(obj)[:2000],
                        ioc=extract_iocs(str(obj)),
                        raw={"value": obj},
                    )
                ]
            return [self._from_obj(obj, raw_obj=obj)]
        except Exception:
            # Fallback malformed handling
            return [
                LogEvent(
                    event_type="malformed",
                    message=(text or "")[:2000] or None,
                    ioc=extract_iocs(text or ""),
                    raw=raw,
                )
            ]

    def _from_obj(self, obj: dict[str, Any], raw_obj: dict[str, Any]) -> LogEvent:
        # Timestamp
        ts = (
            obj.get("timestamp")
            or obj.get("time")
            or obj.get("@timestamp")
            or obj.get("event_time")
            or obj.get("ts")
        )
        timestamp = parse_datetime(ts)

        # Source/host
        source = obj.get("source") or obj.get("host") or obj.get("logger") or obj.get("service")

        # Severity
        sev = obj.get("severity") or obj.get("level") or (obj.get("log") or {}).get("level") if isinstance(obj.get("log"), dict) else None
        sev = normalize_severity(sev)

        # Message
        message = obj.get("message") or obj.get("msg") or obj.get("event")

        # IPs
        ip = obj.get("ip") or obj.get("src_ip") or (obj.get("source", {}) if isinstance(obj.get("source"), dict) else {}).get("ip")
        dst = obj.get("destination_ip") or obj.get("dst_ip") or (obj.get("destination", {}) if isinstance(obj.get("destination"), dict) else {}).get("ip")
        ips = extract_ips(message or "")
        if not ip and ips:
            ip = ips[0]
        if not dst and len(ips) > 1:
            dst = ips[1]

        # Username
        username = obj.get("username") or obj.get("user") or obj.get("account") or obj.get("principal")

        # Event id
        event_id = obj.get("event_id") or obj.get("eventId") or obj.get("EventID")

        process = obj.get("process") or obj.get("program") or obj.get("proc")

        # Event type
        event_type = obj.get("event_type") or obj.get("type") or obj.get("category") or "json_log"

        # IOC + Threat score
        ioc = obj.get("ioc") or []
        if isinstance(ioc, str):
            ioc = [ioc]
        if not ioc:
            ioc = extract_iocs(json.dumps(obj, default=str))

        threat_score = obj.get("threat_score") or obj.get("threatScore") or obj.get("score")
        try:
            threat_score = float(threat_score) if threat_score is not None else None
        except Exception:
            threat_score = None

        return LogEvent(
            timestamp=timestamp,
            source=str(source) if source is not None else None,
            ip=str(ip) if ip is not None else None,
            destination_ip=str(dst) if dst is not None else None,
            username=str(username) if username is not None else None,
            event_id=str(event_id) if event_id is not None else None,
            process=str(process) if process is not None else None,
            severity=sev,
            message=str(message) if message is not None else None,
            event_type=str(event_type) if event_type is not None else "json_log",
            ioc=list(ioc),
            threat_score=threat_score,
            raw=raw_obj,
        )

