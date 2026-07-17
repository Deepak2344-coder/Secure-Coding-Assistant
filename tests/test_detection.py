from backend.detection_engine.rules import (
    _check_sql_injection,
    _check_command_injection,
    _check_hardcoded_secrets,
    _check_xss,
    check_syntax_errors,
    check_logical_errors,
)
from backend.detection_engine.scanner import run_scan
from backend.schemas import ScanRequest, VulnType, IssueCategory, Severity


# ── SQL Injection ──────────────────────────────────────────────────

class TestSqlInjection:
    def test_detects_concat(self):
        code = 'query = "SELECT * FROM users WHERE name = " + name'
        issues = _check_sql_injection(code)
        assert len(issues) == 1
        assert issues[0].vuln_type == VulnType.SQL_INJECTION
        assert issues[0].severity == Severity.HIGH

    def test_detects_fstring(self):
        code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
        issues = _check_sql_injection(code)
        assert len(issues) == 1
        assert issues[0].confidence == "high"

    def test_detects_format(self):
        code = 'query = "SELECT * FROM users WHERE name = {}".format(name)'
        issues = _check_sql_injection(code)
        assert len(issues) == 1

    def test_detects_percent_formatting(self):
        code = 'query = "SELECT * FROM users WHERE name = %s" % name'
        issues = _check_sql_injection(code)
        assert len(issues) == 1

    def test_detects_percent_no_quote(self):
        code = "query = 'SELECT * FROM users WHERE name = %s' % name"
        issues = _check_sql_injection(code)
        assert len(issues) == 1

    def test_detects_percent_dict(self):
        code = 'query = "SELECT * FROM users WHERE id = %(id)s" % {"id": uid}'
        issues = _check_sql_injection(code)
        assert len(issues) == 1

    def test_ignores_safe_query(self):
        code = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))'
        issues = _check_sql_injection(code)
        assert len(issues) == 0

    def test_ignores_print(self):
        code = 'print("select * from somewhere")'
        issues = _check_sql_injection(code)
        assert len(issues) == 0

    def test_multiline(self):
        code = """def f():
    q = "SELECT * FROM t WHERE x = " + x
    db.execute(q)"""
        issues = _check_sql_injection(code)
        assert len(issues) == 1
        assert issues[0].line == 2

    def test_insert(self):
        code = 'q = "INSERT INTO users VALUES (" + val + ")"'
        issues = _check_sql_injection(code)
        assert len(issues) == 1


# ── Command Injection ──────────────────────────────────────────────

class TestCommandInjection:
    def test_os_system(self):
        code = 'os.system("ping -c 1 " + host)'
        issues = _check_command_injection(code)
        assert len(issues) == 1
        assert issues[0].vuln_type == VulnType.COMMAND_INJECTION

    def test_os_popen(self):
        code = 'os.popen("ls " + path)'
        issues = _check_command_injection(code)
        assert len(issues) == 1

    def test_subprocess_shell_true(self):
        code = 'subprocess.call("ls " + path, shell=True)'
        issues = _check_command_injection(code)
        assert len(issues) == 1

    def test_subprocess_popen_shell_true(self):
        code = 'subprocess.Popen(cmd, shell=True)'
        issues = _check_command_injection(code)
        assert len(issues) == 1

    def test_ignores_safe_subprocess(self):
        code = 'subprocess.run(["ls", "-l", path])'
        issues = _check_command_injection(code)
        assert len(issues) == 0

    def test_ignores_unrelated(self):
        code = 'print("hello world")'
        issues = _check_command_injection(code)
        assert len(issues) == 0


# ── Hardcoded Secrets ──────────────────────────────────────────────

class TestHardcodedSecrets:
    def test_api_key_assignment(self):
        code = 'API_KEY = "sk-1234567890abcdef12345678"'
        issues = _check_hardcoded_secrets(code)
        assert len(issues) == 1
        assert issues[0].vuln_type == VulnType.HARDCODED_SECRET

    def test_password_assignment(self):
        code = 'DB_PASSWORD = "super_secret_123"'
        issues = _check_hardcoded_secrets(code)
        assert len(issues) == 1

    def test_token_assignment(self):
        code = 'auth_token = "ghp_1234567890abcdef"'
        issues = _check_hardcoded_secrets(code)
        assert len(issues) == 1

    def test_ignores_env_var(self):
        code = 'API_KEY = os.getenv("API_KEY")'
        issues = _check_hardcoded_secrets(code)
        assert len(issues) == 0

    def test_ignores_short_string(self):
        code = 'name = "hello"'
        issues = _check_hardcoded_secrets(code)
        assert len(issues) == 0


# ── XSS ────────────────────────────────────────────────────────────

class TestXss:
    def test_render_template_string_with_fstring(self):
        code = 'return render_template_string(f"<h1>{name}</h1>")'
        issues = _check_xss(code)
        assert len(issues) == 1
        assert issues[0].vuln_type == VulnType.XSS

    def test_render_template_string_with_concat(self):
        code = 'return render_template_string("<h1>" + name + "</h1>")'
        issues = _check_xss(code)
        assert len(issues) == 1

    def test_safe_filter(self):
        code = "{{ user_input|safe}}"
        issues = _check_xss(code)
        assert len(issues) == 1

    def test_safe_filter_with_space(self):
        code = "{{ user_input|safe }}"
        issues = _check_xss(code)
        assert len(issues) == 1

    def test_autoescape_false(self):
        code = "{% autoescape false %}"
        issues = _check_xss(code)
        assert len(issues) == 1

    def test_markup(self):
        code = 'return Markup("<h1>" + title + "</h1>")'
        issues = _check_xss(code)
        assert len(issues) == 1

    def test_ignores_safe_render(self):
        code = 'return render_template("page.html", name=name)'
        issues = _check_xss(code)
        assert len(issues) == 0

    def test_ignores_markup_with_escape(self):
        code = 'return Markup.escape(user_input)'
        issues = _check_xss(code)
        assert len(issues) == 0

    def test_no_xss_mistake_for_sql(self):
        code = 'q = "SELECT * FROM users WHERE name = " + name'
        issues = _check_xss(code)
        assert len(issues) == 0


# ── Syntax Errors ──────────────────────────────────────────────────

class TestSyntaxErrors:
    def test_detects_syntax_error(self):
        code = "def f(:\n    pass"
        issues = check_syntax_errors(code)
        assert len(issues) == 1
        assert issues[0].vuln_type == VulnType.SYNTAX_ERROR
        assert issues[0].category == IssueCategory.SYNTAX

    def test_ignores_valid_code(self):
        code = "def f():\n    pass"
        issues = check_syntax_errors(code)
        assert len(issues) == 0


# ── Logical Errors ─────────────────────────────────────────────────

class TestLogicalErrors:
    def test_mutable_default_arg(self):
        code = "def f(items=[]):\n    pass"
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.MUTABLE_DEFAULT_ARG in types

    def test_bare_except(self):
        code = "try:\n    pass\nexcept:\n    pass"
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.BARE_EXCEPT in types

    def test_builtin_shadow(self):
        code = "list = [1, 2, 3]"
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.BUILTIN_REASSIGN in types

    def test_is_literal_compare(self):
        code = 'if x is 42:\n    pass'
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.IS_LITERAL_COMPARE in types

    def test_is_none_ok(self):
        code = 'if x is None:\n    pass'
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.IS_LITERAL_COMPARE not in types

    def test_equals_none(self):
        code = 'if x == None:\n    pass'
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.EQUALS_NONE in types

    def test_undefined_name(self):
        code = "x = undefined_var + 1"
        issues = check_logical_errors(code)
        types = [i.vuln_type for i in issues]
        assert VulnType.UNDEFINED_NAME in types

    def test_no_false_positives(self):
        code = """import os
x = 42
if x is None:
    pass
def f(items):
    pass"""
        issues = check_logical_errors(code)
        assert len(issues) == 0


# ── Scanner Integration ────────────────────────────────────────────

class TestScanner:
    def test_run_scan_returns_response(self):
        code = 'import os; os.system("ping -c 1 localhost")'
        result = run_scan(ScanRequest(code=code))
        types = {i.vuln_type for i in result.issues}
        assert VulnType.COMMAND_INJECTION in types

    def test_run_scan_short_circuits_on_syntax_error(self):
        code = "def f(:\n'system' + 'ping'"
        result = run_scan(ScanRequest(code=code))
        assert len(result.issues) == 1
        assert result.issues[0].vuln_type == VulnType.SYNTAX_ERROR

    def test_run_scan_empty_code(self):
        result = run_scan(ScanRequest(code=""))
        assert len(result.issues) == 0

    def test_run_scan_multiple_issues(self):
        code = """q = "SELECT * FROM t WHERE x = " + x
os.system("ping " + host)
API_KEY = "sk-1234567890abcdef12345678\""""
        result = run_scan(ScanRequest(code=code))
        vuln_types = {i.vuln_type for i in result.issues}
        assert VulnType.SQL_INJECTION in vuln_types
        assert VulnType.COMMAND_INJECTION in vuln_types
        assert VulnType.HARDCODED_SECRET in vuln_types
