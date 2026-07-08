import ast
import re

from backend.schemas import Issue, VulnType, Severity

SQL_KEYWORDS = ["select", "insert", "update", "delete", "from", "where", "drop", "union"]

SUSPICIOUS_VAR_PATTERNS = [
    re.compile(r"(api[_-]?key|apikey)", re.IGNORECASE),
    re.compile(r"(secret|token|password|passwd|credential)", re.IGNORECASE),
    re.compile(r"(auth[_-]?key|authkey)", re.IGNORECASE),
]

HARDCODED_VALUE_PATTERN = re.compile(r'["\'][A-Za-z0-9_\-/=+]{16,}["\']')

COMMAND_INJECTION_PATTERNS = [
    re.compile(r'os\.system\s*\(.*\)'),
    re.compile(r'os\.popen\s*\(.*\)'),
    re.compile(r'subprocess\.[a-zA-Z]+\s*\(.*shell\s*=\s*True.*\)'),
    re.compile(r'subprocess\.[a-zA-Z]+\s*\(.*,\s*shell\s*=\s*True'),
]

XSS_PATTERNS = [
    re.compile(r'render_template_string\s*\(f["\']'),
    re.compile(r'{{.*\|safe}}'),
    re.compile(r'{%\s*autoescape\s+false\s*%}'),
    re.compile(r'Markup\s*\(.*\)'),
]


def _get_line_snippet(code: str, line_no: int) -> str:
    lines = code.split("\n")
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def _check_sql_injection(code: str) -> list[Issue]:
    issues = []
    lines = code.split("\n")
    in_sql_context = False

    for i, line in enumerate(lines):
        line_lower = line.lower()
        has_sql_keyword = any(
            kw in line_lower for kw in SQL_KEYWORDS
        )

        if has_sql_keyword:
            in_sql_context = True

        if in_sql_context:
            has_concat = "+" in line and ('"' in line or "'" in line)
            has_fstring = 'f"' in line_lower or "f'" in line_lower
            has_format = ".format(" in line
            has_percent = re.search(r'%\s*\(', line)

            if has_concat or has_fstring or has_format or has_percent:
                issues.append(
                    Issue(
                        line=i + 1,
                        vuln_type=VulnType.SQL_INJECTION,
                        snippet=_get_line_snippet(code, i + 1),
                        confidence="high" if has_fstring else "medium",
                        severity=Severity.HIGH,
                    )
                )
                in_sql_context = False

        if line.rstrip().endswith(";"):
            in_sql_context = False

    return issues


def _check_command_injection(code: str) -> list[Issue]:
    issues = []
    for i, line in enumerate(code.split("\n")):
        for pattern in COMMAND_INJECTION_PATTERNS:
            if pattern.search(line):
                issues.append(
                    Issue(
                        line=i + 1,
                        vuln_type=VulnType.COMMAND_INJECTION,
                        snippet=_get_line_snippet(code, i + 1),
                        confidence="high",
                        severity=Severity.HIGH,
                    )
                )
                break
    return issues


def _check_hardcoded_secrets(code: str) -> list[Issue]:
    issues = []
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        if any(p.search(var_name) for p in SUSPICIOUS_VAR_PATTERNS):
                            if isinstance(node.value, ast.Constant) and isinstance(
                                node.value.value, str
                            ):
                                val = node.value.value
                                if HARDCODED_VALUE_PATTERN.match(f'"{val}"') or len(
                                    val
                                ) >= 8:
                                    issues.append(
                                        Issue(
                                            line=node.lineno,
                                            vuln_type=VulnType.HARDCODED_SECRET,
                                            snippet=_get_line_snippet(
                                                code, node.lineno
                                            ),
                                            confidence="high",
                                            severity=Severity.HIGH,
                                        )
                                    )
    except SyntaxError:
        lines = code.split("\n")
        for i, line in enumerate(lines):
            for pattern in SUSPICIOUS_VAR_PATTERNS:
                if pattern.search(line) and "=" in line:
                    rhs = line.split("=", 1)[1].strip()
                    if HARDCODED_VALUE_PATTERN.match(rhs):
                        issues.append(
                            Issue(
                                line=i + 1,
                                vuln_type=VulnType.HARDCODED_SECRET,
                                snippet=_get_line_snippet(code, i + 1),
                                confidence="medium",
                                severity=Severity.HIGH,
                            )
                        )
    return issues


def _check_xss(code: str) -> list[Issue]:
    issues = []
    for i, line in enumerate(code.split("\n")):
        for pattern in XSS_PATTERNS:
            if pattern.search(line):
                issues.append(
                    Issue(
                        line=i + 1,
                        vuln_type=VulnType.XSS,
                        snippet=_get_line_snippet(code, i + 1),
                        confidence="high",
                        severity=Severity.HIGH,
                    )
                )
                break
    return issues


def check_all_vuln_types(code: str) -> list[Issue]:
    issues = []
    issues.extend(_check_sql_injection(code))
    issues.extend(_check_command_injection(code))
    issues.extend(_check_hardcoded_secrets(code))
    issues.extend(_check_xss(code))
    issues.sort(key=lambda x: x.line)
    return issues
