from pydantic import BaseModel
from typing import List
from enum import Enum


class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    XSS = "xss"


class Severity(str, Enum):
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


class Issue(BaseModel):
    line: int
    vuln_type: VulnType
    snippet: str
    confidence: str
    severity: Severity


class ScanRequest(BaseModel):
    code: str


class ScanResponse(BaseModel):
    issues: List[Issue]
