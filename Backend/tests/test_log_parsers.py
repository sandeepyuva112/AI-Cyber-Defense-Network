from __future__ import annotations

from typing import Any

import pytest

from app.parsers.factory import get_parser
from app.schemas.log_event import LogEvent


def _assert_event(ev: LogEvent) -> None:
    assert isinstance(ev, LogEvent)
    # All fields exist by schema
    assert hasattr(ev, "timestamp")
    assert hasattr(ev, "source")
    assert hasattr(ev, "ip")
    assert hasattr(ev, "destination_ip")
    assert hasattr(ev, "username")
    assert hasattr(ev, "event_id")
    assert hasattr(ev, "process")
    assert hasattr(ev, "severity")
    assert hasattr(ev, "message")
    assert hasattr(ev, "event_type")
    assert hasattr(ev, "ioc")
    assert hasattr(ev, "threat_score")


@pytest.mark.parametrize(
    "log_type,text,expect_event_type",
    [
        (
            "windows_event_logs",
            '{"System": {"EventID": 4625, "Provider": {"Name": "Security-Auditing"}, "TimeCreated": "2026-01-01T12:00:00Z", "Level": "Error"}, "EventData": {"TargetUserName": "bob", "ProcessName": "winlogon"}, "Message": "Failed login from 1.2.3.4"}',
            "authentication",
        ),
        (
            "syslog",
            "<34>Oct 11 22:14:15 myhost sshd[123]: Failed password for invalid user test from 1.2.3.4 port 22",
            "authentication",
        ),
        (
            "json_logs",
            '{"timestamp":"2026-01-01T12:00:00Z","source":"app","level":"error","message":"Login failed ip=5.6.7.8","user":"alice","event_id":"AUTH-1","event_type":"authentication","ioc":["5.6.7.8"],"threat_score":0.9}',
            "authentication",
        ),
        (
            "csv_logs",
            "timestamp,source,ip,destination_ip,username,event_id,process,severity,message,event_type,ioc,threat_score\n2026-01-01T12:00:00Z,host1,1.1.1.1,2.2.2.2,alice,E1,proc1,High,Hello,http,[\"1.1.1.1\"],50",
            "http",
        ),
        (
            "apache_logs",
            '127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://ref" "Mozilla/5.0"',
            "http",
        ),
        (
            "nginx_logs",
            '127.0.0.1 - - [10/Oct/2000:13:55:36 -0700] "GET /path HTTP/1.1" 404 2326 "-" "UA"',
            "http",
        ),
        (
            "firewall_logs",
            "time=2026-01-01T12:00:00Z action=deny src=9.9.9.9 dst=8.8.8.8 user=bob severity=high message=blocked connection",
            "firewall_deny",
        ),
    ],
)
def test_parsers_return_normalized_events(log_type: str, text: str, expect_event_type: str) -> None:
    parser = get_parser(log_type)
    events = parser.parse(text)
    assert isinstance(events, list)
    assert len(events) >= 1
    ev = events[0]
    _assert_event(ev)
    assert ev.event_type == expect_event_type or expect_event_type in (ev.event_type or "")


@pytest.mark.parametrize(
    "log_type,text",
    [
        ("windows_event_logs", "not an event"),
        ("syslog", "<not-pri> nonsense"),
        ("json_logs", "{this is not json"),
        ("csv_logs", "just one line without header"),
        ("apache_logs", "bad apache line"),
        ("nginx_logs", "bad nginx line"),
        ("firewall_logs", "%%%"),
    ],
)
def test_parsers_handle_malformed_input_gracefully(log_type: str, text: str) -> None:
    parser = get_parser(log_type)
    events = parser.parse(text)
    assert isinstance(events, list)
    assert len(events) >= 1
    ev = events[0]
    _assert_event(ev)
    assert ev.event_type == "malformed" or (ev.message is not None)

