from pydantic import BaseModel
from typing import List
from enum import Enum


class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    HARDCODED_SECRET = "hardcoded_secret"
    XSS = "xss"
    SYNTAX_ERROR = "syntax_error"
    MUTABLE_DEFAULT_ARG = "mutable_default_arg"
    BARE_EXCEPT = "bare_except"
    BUILTIN_REASSIGN = "builtin_reassign"
    IS_LITERAL_COMPARE = "is_literal_compare"
    EQUALS_NONE = "equals_none"
    UNDEFINED_NAME = "undefined_name"


class IssueCategory(str, Enum):
    SECURITY = "security"
    SYNTAX = "syntax"
    LOGIC = "logic"


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
    category: IssueCategory = IssueCategory.SECURITY
    message: str = ""


class ScanRequest(BaseModel):
    code: str


class ScanResponse(BaseModel):
    issues: List[Issue]
