from __future__ import annotations

import re
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, extract_ips, normalize_severity, parse_datetime
from app.schemas.log_event import LogEvent


class WindowsEventLogsParser(BaseLogParser):
    """Best-effort parser for Windows Event Logs.

    Supports either:
    - JSON objects (common Windows Event export)
    - key/value or XML-like text blobs.
    """

    _kv_re = re.compile(r"(?P<key>Provider|EventID|Event Id|Computer|TimeCreated|Level|User|Account|Message|SourceName|ProcessName|IpAddress|IpAddresses|Ip|IpV4|Severity)\s*[:=]\s*(?P<val>.+?)(?:\r?\n|$)")

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            # If it's a JSON object, handle keys.
            import json

            s = (text or "").strip()
            if s.startswith("{"):
                obj = json.loads(s)
                return [self._from_windows_obj(obj, raw)]
        except Exception:
            pass

        try:
            # XML-like: <EventID>4625</EventID> etc.
            def tag(name: str) -> Optional[str]:
                m = re.search(rf"<{re.escape(name)}>(?P<v>.*?)</{re.escape(name)}>", text or "", re.IGNORECASE | re.DOTALL)
                return m.group("v").strip() if m else None

            event_id = tag("EventID") or tag("EventId") or tag("Event")
            ts = tag("TimeCreated") or tag("SystemTimeCreated")
            severity_raw = tag("Level") or tag("Severity")
            source = tag("Provider") or tag("ProviderName") or tag("Computer")
            username = tag("TargetUserName") or tag("User") or tag("Account")
            process = tag("ProcessName")

            # Message often exists inside <Message> ...
            message = tag("Message")
            if not message:
                # fallback: try to locate after 'Message'
                m = re.search(r"Message\s*[:=]\s*(?P<v>.+)$", text or "", re.IGNORECASE | re.DOTALL)
                message = m.group("v").strip() if m else None

            ips = extract_ips(text or "")
            ip = ips[0] if ips else None
            dst = ips[1] if len(ips) > 1 else None

            iocs = extract_iocs(text or "")
            sev = normalize_severity(severity_raw, fallback=None)

            # Timestamp normalization
            timestamp = parse_datetime(ts)
            if not timestamp:
                # look for ISO in the blob
                iso_m = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\s<]*", text or "")
                timestamp = parse_datetime(iso_m.group(0)) if iso_m else None

            event_type = "authentication" if (str(event_id) in {"4624", "4625", "4768", "4769"}) else "windows_event"

            if not event_id and not message and not ts and not source:
                return [
                    LogEvent(
                        timestamp=None,
                        source=None,
                        ip=ip,
                        destination_ip=dst,
                        username=None,
                        event_id=None,
                        process=None,
                        severity=sev,
                        message=(text or "")[:2000] or None,
                        event_type="malformed",
                        ioc=iocs,
                        threat_score=None,
                        raw=raw,
                    )
                ]

            return [
                LogEvent(
                    timestamp=timestamp,
                    source=source,
                    ip=ip,
                    destination_ip=dst,
                    username=username,
                    event_id=str(event_id) if event_id else None,
                    process=process,
                    severity=sev,
                    message=message,
                    event_type=event_type,
                    ioc=iocs,
                    threat_score=None,
                    raw=raw,
                )
            ]

        except Exception:
            ips = extract_ips(text or "")
            iocs = extract_iocs(text or "")
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
                    ioc=iocs,
                    threat_score=None,
                    raw=raw,
                )
            ]



    def _from_windows_obj(self, obj: dict[str, Any], raw: dict[str, Any]) -> LogEvent:
        # Common shapes from event export tools
        system = obj.get("System") or obj.get("system") or {}
        event = obj.get("EventData") or obj.get("eventdata") or {}

        event_id = system.get("EventID") or system.get("EventId") or obj.get("EventID") or obj.get("EventId")
        provider = system.get("Provider") or obj.get("Provider")
        source = provider.get("Name") if isinstance(provider, dict) else provider or obj.get("Computer")

        # Timestamp
        ts_val = system.get("TimeCreated") or system.get("SystemTime") or system.get("time") or obj.get("TimeCreated")
        timestamp = None
        if isinstance(ts_val, dict):
            timestamp = parse_datetime(ts_val.get("SystemTime") or ts_val.get("time"))
        else:
            timestamp = parse_datetime(ts_val)

        # Severity
        level_raw = system.get("Level") or system.get("severity")
        sev = normalize_severity(level_raw, fallback=None)

        # User and process
        username = None
        for k in ("TargetUserName", "User", "Account", "SubjectUserName", "username"):
            if k in event:
                username = event.get(k)
                break
        process = event.get("ProcessName") or event.get("Process")

        # Message
        message = obj.get("Message") or system.get("Message")

        ips = extract_ips(str(obj))
        ip = ips[0] if ips else None
        dst = ips[1] if len(ips) > 1 else None
        iocs = extract_iocs(str(obj))

        event_type = "authentication" if str(event_id) in {"4624", "4625", "4768", "4769"} else "windows_event"

        return LogEvent(
            timestamp=timestamp,
            source=str(source) if source is not None else None,
            ip=ip,
            destination_ip=dst,
            username=str(username) if username is not None else None,
            event_id=str(event_id) if event_id is not None else None,
            process=str(process) if process is not None else None,
            severity=sev,
            message=str(message) if message is not None else None,
            event_type=event_type,
            ioc=iocs,
            threat_score=None,
            raw=raw,
        )

