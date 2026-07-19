from __future__ import annotations

import csv
import io
from typing import Any, Optional

from app.parsers.base import BaseLogParser
from app.parsers.utils import extract_iocs, extract_ips, normalize_severity, parse_datetime, detect_csv_dialect
from app.schemas.log_event import LogEvent


class CsvLogsParser(BaseLogParser):
    """Parse CSV logs with best-effort header mapping."""

    _FIELD_ALIASES = {
        "timestamp": {"timestamp", "time", "@timestamp", "ts", "datetime"},
        "source": {"source", "host", "hostname", "provider"},
        "ip": {"ip", "src_ip", "source_ip"},
        "destination_ip": {"destination_ip", "dst_ip", "dest_ip"},
        "username": {"username", "user", "account", "principal"},
        "event_id": {"event_id", "eventid", "event_id", "eventid"},
        "process": {"process", "program", "proc"},
        "severity": {"severity", "level"},
        "message": {"message", "msg"},
        "event_type": {"event_type", "type", "category"},
        "ioc": {"ioc", "indicators"},
        "threat_score": {"threat_score", "threatscore", "score"},
    }

    def parse(self, text: str, metadata: Optional[dict[str, Any]] = None) -> list[LogEvent]:
        raw = {"input": text}
        try:
            s = (text or "").strip("\ufeff")
            if not s:
                return [LogEvent(event_type="malformed", message=None, ioc=[], raw=raw)]

            # Try dialect detection on first chunk
            try:
                dialect = detect_csv_dialect(s)
            except Exception:
                dialect = csv.excel
            f = io.StringIO(s)
            reader = csv.DictReader(f, dialect=dialect)
            if not reader.fieldnames:
                raise ValueError("CSV missing header")

            events: list[LogEvent] = []
            for row in reader:
                events.append(self._from_row(row))
            return events or [LogEvent(event_type="malformed", message=None, ioc=[], raw=raw)]
        except Exception:
            ips = extract_ips(text or "")
            return [
                LogEvent(
                    event_type="malformed",
                    message=(text or "")[:2000] or None,
                    ip=ips[0] if ips else None,
                    destination_ip=ips[1] if len(ips) > 1 else None,
                    ioc=extract_iocs(text or ""),
                    raw=raw,
                )
            ]

    def _map_row_field(self, key: str, row: dict[str, Any]) -> Any:
        lower_key_map = {k.lower().strip(): k for k in row.keys() if k}
        # Direct lookup
        if key in lower_key_map:
            return row.get(lower_key_map[key])
        return None

    def _from_row(self, row: dict[str, Any]) -> LogEvent:
        def find_any(alias_set: set[str]) -> Any:
            for a in alias_set:
                v = self._map_row_field(a, row)
                if v not in (None, ""):
                    return v
            return None

        timestamp = parse_datetime(find_any(self._FIELD_ALIASES["timestamp"]) )
        source = find_any(self._FIELD_ALIASES["source"])
        ip = find_any(self._FIELD_ALIASES["ip"])
        dst = find_any(self._FIELD_ALIASES["destination_ip"])
        username = find_any(self._FIELD_ALIASES["username"])
        event_id = find_any(self._FIELD_ALIASES["event_id"])
        process = find_any(self._FIELD_ALIASES["process"])
        severity_raw = find_any(self._FIELD_ALIASES["severity"])
        severity = normalize_severity(severity_raw)
        message = find_any(self._FIELD_ALIASES["message"])
        event_type = find_any(self._FIELD_ALIASES["event_type"]) or "csv_log"

        ioc = find_any(self._FIELD_ALIASES["ioc"]) or []
        if isinstance(ioc, str):
            # allow semicolon/comma separated
            if ";" in ioc:
                ioc = [x.strip() for x in ioc.split(";") if x.strip()]
            elif "," in ioc:
                ioc = [x.strip() for x in ioc.split(",") if x.strip()]
            else:
                ioc = [ioc]
        if not ioc:
            ioc = extract_iocs(str(row))

        threat_score = find_any(self._FIELD_ALIASES["threat_score"])
        try:
            threat_score = float(threat_score) if threat_score not in (None, "") else None
        except Exception:
            threat_score = None

        # Best-effort IPs from message if missing
        if (not ip) and message:
            ips = extract_ips(message)
            ip = ips[0] if ips else ip
            dst = ips[1] if len(ips) > 1 else dst

        return LogEvent(
            timestamp=timestamp,
            source=str(source) if source is not None and str(source).strip() else None,
            ip=str(ip) if ip is not None and str(ip).strip() else None,
            destination_ip=str(dst) if dst is not None and str(dst).strip() else None,
            username=str(username) if username is not None and str(username).strip() else None,
            event_id=str(event_id) if event_id is not None and str(event_id).strip() else None,
            process=str(process) if process is not None and str(process).strip() else None,
            severity=severity,
            message=str(message) if message is not None and str(message).strip() else None,
            event_type=str(event_type) if event_type is not None else "csv_log",
            ioc=list(ioc),
            threat_score=threat_score,
            raw=row,
        )

