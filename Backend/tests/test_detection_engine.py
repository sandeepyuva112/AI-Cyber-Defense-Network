from __future__ import annotations

from app.detection.engine import DetectionEngine


def test_detects_powershell_abuse():
    eng = DetectionEngine()
    log = "PowerShell -EncodedCommand aW52b2tlI...; Invoke-WebRequest; iex"
    report = eng.analyze(correlation_id="c1", log_type="windows_event_logs", log_text=log)

    assert report.severity.score >= 40
    assert report.suspicious_activities
    assert report.confidence.value > 0.0


def test_returns_schema_even_if_empty():
    eng = DetectionEngine()
    log = "some benign log line"
    report = eng.analyze(correlation_id="c2", log_type="linux_syslog", log_text=log)

    assert report.incident_id == "c2"
    assert report.log_type == "linux_syslog"
    assert report.severity.score >= 0
    assert report.confidence.value >= 0.0

