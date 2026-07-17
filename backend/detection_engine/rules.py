import ast
import re

from backend.schemas import Issue, VulnType, Severity, IssueCategory

SQL_KEYWORDS = ["select", "insert", "update", "delete", "drop", "union", "create", "alter"]

SUSPICIOUS_VAR_PATTERNS = [
    re.compile(r"(api[_-]?key|apikey)", re.IGNORECASE),
    re.compile(r"(secret|token|password|passwd|credential)", re.IGNORECASE),
    re.compile(r"(auth[_-]?key|authkey)", re.IGNORECASE),
    re.compile(r"(access[_-]?key|aws[_-]?access[_-]?key|private[_-]?key)", re.IGNORECASE),
]

HARDCODED_VALUE_PATTERN = re.compile(r'["\'][A-Za-z0-9_\-/=+]{16,}["\']')

COMMAND_INJECTION_PATTERNS = [
    re.compile(r'os\.system\s*\(.*\)'),
    re.compile(r'os\.popen\s*\(.*\)'),
    re.compile(r'subprocess\.[a-zA-Z]+\s*\(.*shell\s*=\s*True.*\)'),
    re.compile(r'subprocess\.[a-zA-Z]+\s*\(.*,\s*shell\s*=\s*True'),
]

XSS_PATTERNS = [
    re.compile(r'render_template_string\s*\((?:\s*f["\']|[^)]*\+)'),
    re.compile(r'{{.*[|]safe\s*}}'),
    re.compile(r'{%\s*autoescape\s+false\s*%}'),
    re.compile(r'Markup\s*\((?!.*escape\s*\()'),
]

PYTHON_BUILTINS = {
    "True", "False", "None",
    "print", "len", "range", "int", "str", "float", "bool",
    "list", "dict", "set", "tuple", "type", "input", "open",
    "sum", "min", "max", "abs", "all", "any", "sorted",
    "reversed", "enumerate", "zip", "map", "filter",
    "isinstance", "issubclass", "hasattr", "getattr", "setattr", "delattr",
    "dir", "id", "repr", "object", "super", "callable", "iter", "next",
    "Exception", "ValueError", "TypeError", "KeyError",
    "IndexError", "AttributeError", "ImportError", "StopIteration",
    "RuntimeError", "ZeroDivisionError", "FileNotFoundError",
    "MemoryError", "NameError", "SyntaxError", "IndentationError",
    "TabError", "SystemExit", "KeyboardInterrupt", "BaseException",
    "property", "staticmethod", "classmethod", "hash", "help",
    "hex", "oct", "bin", "ord", "chr", "format", "vars",
    "globals", "locals", "slice", "pow", "round", "__import__",
    "AssertionError", "NotImplementedError", "PendingDeprecationWarning",
    "bytes", "bytearray", "memoryview", "frozenset",
    "hasattr", "issubclass", "isinstance",
}

SHADOWED_BUILTINS = {
    "list", "dict", "set", "tuple", "str", "int", "float", "bool",
    "input", "print", "open", "len", "range", "type", "sum", "min", "max",
    "file", "exec", "eval", "id", "object", "super",
}


def _get_line_snippet(code: str, line_no: int) -> str:
    lines = code.split("\n")
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1].strip()
    return ""


def _check_sql_injection(code: str) -> list[Issue]:
    issues = []
    lines = code.split("\n")

    for i, line in enumerate(lines):
        line_lower = line.lower()
        has_sql_keyword = any(
            re.search(r'\b' + kw + r'\b', line_lower) for kw in SQL_KEYWORDS
        )
        if not has_sql_keyword:
            continue

        has_concat = "+" in line and ('"' in line or "'" in line)
        has_fstring = 'f"' in line_lower or "f'" in line_lower
        has_format = ".format(" in line
        has_percent = re.search(r'%\s*\(', line) or re.search(r'%[sdxr]["\']?\s*%', line)

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


def check_syntax_errors(code: str) -> list[Issue]:
    try:
        ast.parse(code)
    except SyntaxError as e:
        line_no = e.lineno or 1
        return [
            Issue(
                line=line_no,
                vuln_type=VulnType.SYNTAX_ERROR,
                snippet=_get_line_snippet(code, line_no),
                confidence="high",
                severity=Severity.HIGH,
                category=IssueCategory.SYNTAX,
                message=e.msg,
            )
        ]
    return []


def check_logical_errors(code: str) -> list[Issue]:
    issues = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return issues

    for node in ast.walk(tree):
        line_no = getattr(node, "lineno", 0)

        # 1. Mutable default arguments
        if isinstance(node, ast.FunctionDef):
            for default in node.args.defaults + node.args.kw_defaults:
                if default is not None and isinstance(default, (ast.List, ast.Dict, ast.Set)):
                    issues.append(
                        Issue(
                            line=default.lineno,
                            vuln_type=VulnType.MUTABLE_DEFAULT_ARG,
                            snippet=_get_line_snippet(code, default.lineno),
                            confidence="high",
                            severity=Severity.MEDIUM,
                            category=IssueCategory.LOGIC,
                            message="Mutable default argument is shared across all calls",
                        )
                    )

        # 2. Bare except handlers
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            issues.append(
                Issue(
                    line=line_no,
                    vuln_type=VulnType.BARE_EXCEPT,
                    snippet=_get_line_snippet(code, line_no),
                    confidence="high",
                    severity=Severity.MEDIUM,
                    category=IssueCategory.LOGIC,
                    message="Bare except catches SystemExit and KeyboardInterrupt",
                )
            )

        # 3. Built-in name shadowing
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id in SHADOWED_BUILTINS:
                    issues.append(
                        Issue(
                            line=target.lineno,
                            vuln_type=VulnType.BUILTIN_REASSIGN,
                            snippet=_get_line_snippet(code, target.lineno),
                            confidence="high",
                            severity=Severity.LOW,
                            category=IssueCategory.LOGIC,
                            message=f"Assigning to built-in '{target.id}' shadows the original",
                        )
                    )

        # 4. 'is' comparison with a literal (except None)
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, ast.Is) and isinstance(comp, ast.Constant) and comp.value is not None:
                    issues.append(
                        Issue(
                            line=line_no,
                            vuln_type=VulnType.IS_LITERAL_COMPARE,
                            snippet=_get_line_snippet(code, line_no),
                            confidence="high",
                            severity=Severity.MEDIUM,
                            category=IssueCategory.LOGIC,
                            message=f"Use '==' instead of 'is' to compare literal values",
                        )
                    )

        # 5. '== None' instead of 'is None'
        if isinstance(node, ast.Compare):
            for op, comp in zip(node.ops, node.comparators):
                if isinstance(op, ast.Eq) and isinstance(comp, ast.Constant) and comp.value is None:
                    issues.append(
                        Issue(
                            line=line_no,
                            vuln_type=VulnType.EQUALS_NONE,
                            snippet=_get_line_snippet(code, line_no),
                            confidence="high",
                            severity=Severity.LOW,
                            category=IssueCategory.LOGIC,
                            message="Use 'is None' instead of '== None' for identity comparison",
                        )
                    )

        # 6. Undefined variable references
    defined_names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name):
            if isinstance(n.ctx, (ast.Store, ast.AugStore)):
                defined_names.add(n.id)
            elif isinstance(n.ctx, ast.Del):
                defined_names.discard(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defined_names.add(n.name)
            for arg in n.args.args + n.args.posonlyargs + n.args.kwonlyargs:
                defined_names.add(arg.arg)
            if n.args.vararg:
                defined_names.add(n.args.vararg.arg)
            if n.args.kwarg:
                defined_names.add(n.args.kwarg.arg)
        elif isinstance(n, ast.ClassDef):
            defined_names.add(n.name)
        elif isinstance(n, ast.Import):
            for alias in n.names:
                defined_names.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(n, ast.ImportFrom):
            for alias in n.names:
                defined_names.add(alias.asname or alias.name)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            defined_names.add(n.name)

    first_ref = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            if n.id not in defined_names and n.id not in PYTHON_BUILTINS:
                if n.id not in first_ref:
                    first_ref[n.id] = (n.lineno, _get_line_snippet(code, n.lineno))

    for name, (lineno, snippet) in sorted(first_ref.items()):
        issues.append(
            Issue(
                line=lineno,
                vuln_type=VulnType.UNDEFINED_NAME,
                snippet=snippet,
                confidence="medium",
                severity=Severity.MEDIUM,
                category=IssueCategory.LOGIC,
                message=f"Name '{name}' is not defined in this scope",
            )
        )

    return issues


def check_all_vuln_types(code: str) -> list[Issue]:
    issues = []
    issues.extend(_check_sql_injection(code))
    issues.extend(_check_command_injection(code))
    issues.extend(_check_hardcoded_secrets(code))
    issues.extend(_check_xss(code))
    issues.sort(key=lambda x: x.line)
    return issues
