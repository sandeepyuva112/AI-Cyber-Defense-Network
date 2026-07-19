from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from .ioc_patterns import (
    C2_STRINGS,
    IOC_STRINGS,
    IOC_REGEXES,
    LOL_BIN_PATTERNS,
    PERSISTENCE_ARTIFACTS,
)


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    rule_name: str
    classification: str
    evidence: list[str]
    weight: int
    confidence: float
    mitre: list[tuple[str, str, list[str]]]


def _find_any(text: str, patterns: list[str]) -> list[str]:
    hits: list[str] = []
    lower = text.lower()
    for p in patterns:
        if re.search(p, lower, flags=re.IGNORECASE):
            hits.append(p)
    return hits


def _extract_iocs(text: str) -> tuple[bool, dict[str, list[str]]]:
    extracted: dict[str, list[str]] = {}
    has_any = False
    for k, rx in IOC_REGEXES.items():
        matches = re.findall(rx, text, flags=re.IGNORECASE)
        if matches:
            has_any = True
            # cap per type
            extracted[k] = list({m for m in matches})[:10]
    return has_any, extracted


def match_rules(log_text: str) -> tuple[list[RuleMatch], dict[str, list[str]]]:
    text = log_text or ""
    lower = text.lower()

    has_ioc, extracted_iocs = _extract_iocs(text)
    matches: list[RuleMatch] = []

    # Brute Force
    brute_hits = _find_any(lower, IOC_STRINGS.get("bruteforce", []))
    if len(brute_hits) >= 1 and re.search(r"(failed|invalid).{0,40}(password|login)", lower):
        evidence = ["authentication failures detected"]
        matches.append(
            RuleMatch(
                rule_id="RULE_BRUTE_FORCE",
                rule_name="Brute Force",
                classification="credential_access",
                evidence=evidence,
                weight=4,
                confidence=0.55,
                mitre=[("T1110", "Brute Force", ["credential-access"])],
            )
        )


    # Credential Stuffing (heuristic: many users / repeated failures)
    cs_hits = _find_any(lower, IOC_STRINGS.get("credential_stuffing", []))
    if cs_hits or re.search(r"(multiple|many).{0,30}(users|accounts)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_CREDENTIAL_STUFFING",
                rule_name="Credential Stuffing",
                classification="credential_access",
                evidence=["patterns consistent with credential stuffing/spraying"],
                weight=5,
                confidence=0.6,
                mitre=[("T1110.004", "Password Spraying", ["credential-access"])],
            )
        )

    # Port Scan (heuristic: many destination ports from a source)
    if re.search(r"(scan|scanned|probing)", lower) or re.search(r"(dstport|dpt)=", lower):
        # If we see multiple ports in text, boost
        ports = re.findall(r"(dpt|dstport)[:=]\s*(\d{1,5})", lower)
        unique_ports = {p[1] for p in ports} if ports else set()
        if len(unique_ports) >= 5:
            matches.append(
                RuleMatch(
                    rule_id="RULE_PORT_SCAN",
                    rule_name="Port Scan",
                    classification="reconnaissance",
                    evidence=[f"unique destination ports observed: {len(unique_ports)}"],
                    weight=6,
                    confidence=0.65,
                    mitre=[("T1046", "Network Service Scanning", ["reconnaissance"])],
                )
            )

    # PowerShell Abuse
    ps_hits = _find_any(lower, IOC_STRINGS.get("powershell", []))
    if ps_hits:
        evidence = ["PowerShell indicators present"]
        if re.search(r"-enc\s|encodedcommand", lower):
            evidence.append("Encoded/obfuscated PowerShell command detected")
        matches.append(
            RuleMatch(
                rule_id="RULE_POWERSHELL_ABUSE",
                rule_name="PowerShell Abuse",
                classification="suspicious",
                evidence=evidence,
                weight=6,
                confidence=0.7,
                mitre=[("T1059.001", "PowerShell", ["execution"])],
            )
        )

    # Privilege Escalation (heuristic: UAC bypass, token, admin group)
    if re.search(r"(uac|bypass|elevat|token|sebackupprivilege|seimpersonate)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_PRIV_ESC",
                rule_name="Privilege Escalation",
                classification="privilege_escalation",
                evidence=["privilege escalation indicators detected"],
                weight=8,
                confidence=0.68,
                mitre=[("T1068", "Exploitation for Privilege Escalation", ["privilege-escalation"])],
            )
        )

    # Malware Execution & Suspicious Process / C2
    lol_hits = _find_any(lower, LOL_BIN_PATTERNS)
    c2_hit = any(re.search(p, lower, flags=re.IGNORECASE) for p in C2_STRINGS)
    if lol_hits and re.search(r"(download|execute|payload|malware|stage|invoke|run)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_MALWARE_EXEC",
                rule_name="Malware Execution",
                classification="malware",
                evidence=["execution of suspicious tooling/payload indicators"],
                weight=7,
                confidence=0.6,
                mitre=[("T1204", "User Execution", ["execution"] )],
            )
        )

    if c2_hit and re.search(r"(http|https|domain|beacon|checkin)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_C2",
                rule_name="Command & Control",
                classification="command_and_control",
                evidence=["network beacons/C2-like strings detected"],
                weight=7,
                confidence=0.62,
                mitre=[("T1071", "Application Layer Protocol", ["command-and-control"])],
            )
        )

    # Persistence
    if any(re.search(a, lower) for a in PERSISTENCE_ARTIFACTS) or re.search(r"(scheduled task|cron|runonce)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_PERSISTENCE",
                rule_name="Persistence",
                classification="persistence",
                evidence=["persistence artifact patterns observed"],
                weight=8,
                confidence=0.66,
                mitre=[("T1547", "Boot or Logon Autostart Execution", ["persistence"])],
            )
        )

    # Lateral Movement (heuristic)
    if re.search(r"(wmic|psexec|smb|remote|wmi\b|rsh|ssh|rdp)", lower):
        matches.append(
            RuleMatch(
                rule_id="RULE_LATERAL",
                rule_name="Lateral Movement",
                classification="lateral_movement",
                evidence=["remote execution/lateral movement indicators detected"],
                weight=8,
                confidence=0.62,
                mitre=[("T1021", "Remote Services", ["lateral-movement"])],
            )
        )

    # Registry Changes
    if re.search(r"\\(run|runonce|services|currentcontrolset)\\", lower) or _find_any(lower, [r"reg add", r"reg delete"]):
        matches.append(
            RuleMatch(
                rule_id="RULE_REGISTRY",
                rule_name="Registry Changes",
                classification="persistence",
                evidence=["registry modification indicators detected"],
                weight=6,
                confidence=0.6,
                mitre=[("T1112", "Modify Registry", ["persistence"] )],
            )
        )

    # Fileless Malware (heuristic)
    if any(re.search(p, lower) for p in [r"powershell", r"wmic", r"regsvr32", r"mshta"]) and re.search(
        r"(memory|reflect|in-memory|fileless|without file)", lower
    ):
        matches.append(
            RuleMatch(
                rule_id="RULE_FILELESS",
                rule_name="Fileless Malware",
                classification="malware",
                evidence=["fileless/in-memory execution indicators"],
                weight=9,
                confidence=0.7,
                mitre=[("T1055", "Process Injection", ["defense-evasion", "execution"])],
            )
        )

    # Living off the Land (catch-all)
    if lol_hits and len(lol_hits) >= 2:
        matches.append(
            RuleMatch(
                rule_id="RULE_LOTL",
                rule_name="Living off the Land",
                classification="suspicious",
                evidence=["multiple LOLBins/tooling indicators present"],
                weight=5,
                confidence=0.55,
                mitre=[("T1106", "Native API", ["defense-evasion"])],
            )
        )

    # Deduplicate by rule_id
    unique: dict[str, RuleMatch] = {m.rule_id: m for m in matches}
    return list(unique.values()), extracted_iocs

