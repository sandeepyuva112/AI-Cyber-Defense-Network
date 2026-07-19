from __future__ import annotations

import json
from typing import Any


BASE_CSS = """
body{font-family:Arial,Helvetica,sans-serif;margin:24px;color:#111}
h1{font-size:20px}
h2{font-size:14px;margin-top:22px}
.section{border:1px solid #ddd;border-radius:6px;padding:12px;margin-top:12px}
.small{color:#444;font-size:12px}
pre{background:#f6f6f6;padding:12px;border-radius:6px;overflow:auto}
ul{margin: 6px 0 0 18px}
"""


def _asdict(obj: Any) -> Any:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json")
    return obj


def render_html(report_obj: Any) -> str:
    data = _asdict(report_obj)

    meta = data.get("executive_report", {}).get("report_metadata", {})
    title = meta.get("report_type", "Incident Report")

    exec_summary = data.get("executive_report", {}).get("executive_summary", {})
    technical = data.get("technical_report", {})

    iocs = data.get("executive_report", {}).get("indicators_of_compromise", [])
    mitre = data.get("executive_report", {}).get("mitre_attack", {}).get("techniques", [])

    evidence = [e.get("evidence") for e in technical.get("evidence", []) if e.get("evidence")]

    def li(items: list[str]) -> str:
        return "".join([f"<li>{x}</li>" for x in items]) if items else "<li>None</li>"

    return f"""<!doctype html>
<html>
<head>
<meta charset='utf-8'/>
<style>{BASE_CSS}</style>
</head>
<body>
  <div class='small'>Generated at: {meta.get('generated_at')} | Version: {meta.get('version')} | Report ID: {meta.get('report_id')}</div>
  <h1>{title}</h1>

  <div class='section'>
    <h2>Executive Summary</h2>
    <b>{exec_summary.get('title','')}</b><br/>
    <div style='margin-top:8px'>{exec_summary.get('overview','')}</div>
    <div style='margin-top:8px'><b>Key Findings</b><ul>{li(exec_summary.get('key_findings', []))}</ul></div>
    <div style='margin-top:8px'><b>Impact</b><div>{exec_summary.get('impact','')}</div></div>
    <div style='margin-top:8px'><b>Next Actions</b><ul>{li(exec_summary.get('next_actions', []))}</ul></div>
  </div>

  <div class='section'>
    <h2>Incident Summary</h2>
    <div><b>Classification</b>: {technical.get('incident_summary',{}).get('incident_classification','')}</div>
    <div style='margin-top:8px'>{technical.get('incident_summary',{}).get('description','')}</div>
  </div>

  <div class='section'>
    <h2>Threat & Risk</h2>
    <div><b>Severity</b>: {technical.get('threat_severity',{}).get('level','')} ({technical.get('threat_severity',{}).get('score','')})</div>
    <div style='margin-top:8px'>{technical.get('threat_severity',{}).get('rationale','')}</div>
    <div style='margin-top:8px'><b>Risk Score</b>: {technical.get('risk_score',{}).get('score','')}</div>
    <div style='margin-top:8px'><b>Confidence</b>: {technical.get('confidence_score',{}).get('value','')}</div>
    <div style='margin-top:8px'>{technical.get('confidence_score',{}).get('rationale','')}</div>
  </div>

  <div class='section'>
    <h2>Indicators of Compromise (IOCs)</h2>
    <ul>{''.join([f"<li>{i.get('ioc','')}</li>" for i in iocs]) if iocs else '<li>None</li>'}</ul>
  </div>

  <div class='section'>
    <h2>MITRE ATT&CK Mapping</h2>
    <ul>{''.join([f"<li>{t.get('technique_id','')} - {t.get('technique_name','')}</li>" for t in mitre]) if mitre else '<li>None</li>'}</ul>
  </div>

  <div class='section'>
    <h2>Timeline</h2>
    <ul>{''.join([f"<li>{t.get('event','')}</li>" for t in technical.get('timeline',[])]) if technical.get('timeline',[]) else '<li>None</li>'}</ul>
  </div>

  <div class='section'>
    <h2>Evidence</h2>
    <ul>{''.join([f"<li>{e}</li>" for e in evidence[:200]]) if evidence else '<li>None</li>'}</ul>
  </div>

  <div class='section'>
    <h2>Recommended Response Actions</h2>
    <pre>{json.dumps(technical.get('recommended_response_actions',[]), indent=2)}</pre>
  </div>

</body>
</html>"""

