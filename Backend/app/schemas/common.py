from enum import Enum


class Severity(str, Enum):
    critical = "Critical"
    high = "High"
    medium = "Medium"
    low = "Low"
    informational = "Informational"


class NistFunction(str, Enum):
    identify = "Identify"
    protect = "Protect"
    detect = "Detect"
    respond = "Respond"
    recover = "Recover"

