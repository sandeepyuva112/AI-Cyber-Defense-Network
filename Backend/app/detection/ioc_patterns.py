from __future__ import annotations

# Simple, regex-friendly IOC & artifact patterns.
# Note: These are heuristic/surrogate indicators intended for log-text analysis.

IOC_STRINGS: dict[str, list[str]] = {
    # Credential access / brute force common markers
    "bruteforce": [
        r"failed password",
        r"authentication failure",
        r"invalid user",
        r"login failure",
        r"too many authentication failures",
        r"rate limit",
    ],
    "credential_stuffing": [
        r"account locked",
        r"password authentication failed",
        r"multiple users",
        r"distributed",
        r"spray",
    ],
    # PowerShell / LOLBins
    "powershell": [
        r"powershell",
        r"-enc\s",
        r"encodedcommand",
        r"frombase64string",
        r"iex\s",
        r"iwr\s",
        r"invoke-webrequest",
    ],
    "reg_changes": [
        r"reg add",
        r"reg delete",
        r"set-value",
        r"registry",
        r"microsoft\\windows\\currentversion\\run",
        r"\brunonce\b",
    ],
    "fileless": [
        r"powershell",
        r"wscript",
        r"cscript",
        r"rundll32",
        r"mshta",
        r"regsvr32",
        r"wmic",
        r"winrm",
        r"inline powershell",
    ],
}

# Common persistence locations (Windows)
PERSISTENCE_ARTIFACTS: list[str] = [
    r"\\Windows\\CurrentVersion\\Run",
    r"\\Windows\\CurrentVersion\\RunOnce",
    r"\\Services\\",
    r"\\Tasks\\",
    r"\\AppInit_DLLs",
    r"\\Image File Execution Options",
    r"schtasks",
    r"at.exe",
    r"regsvr32",
]

# Common C2 / beaconing indicators (highly heuristic)
C2_STRINGS: list[str] = [
    r"/wp-admin/admin-ajax\.php",
    r"/news\.php",
    r"checkin",
    r"beacon",
    r"periodic",
    r"user-agent",
    r"http",
    r"https",
    r"domain",
]

# Living-off-the-land binaries
LOL_BIN_PATTERNS: list[str] = [
    r"powershell",
    r"cmd\.exe",
    r"wscript\.exe",
    r"cscript\.exe",
    r"rundll32\.exe",
    r"mshta\.exe",
    r"regsvr32\.exe",
    r"wmic",
    r"certutil\.exe",
    r"bitsadmin",
    r"tftp",
    r"curl",
    r"wget",
]

# IOC-like things extracted from log text (regex)
IOC_REGEXES: dict[str, str] = {
    "ip_v4": r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\b",
    "url": r"\bhttps?://[^\s\"]+",
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "base64": r"\b(?:[A-Za-z0-9+/]{40,}={0,2})\b",
}

