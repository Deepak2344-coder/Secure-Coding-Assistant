from dataclasses import dataclass, field


@dataclass
class CorpusChunk:
    vuln_type: str
    text: str
    cwe_id: str
    source_url: str


CORPUS: list[CorpusChunk] = [
    # ── SQL Injection ──────────────────────────────────────────────
    CorpusChunk(
        vuln_type="sql_injection",
        text="SQL Injection (CWE-89) occurs when untrusted user input is concatenated directly into an SQL query string. "
        "An attacker can craft input that breaks out of the intended string context and executes arbitrary SQL commands. "
        "This can lead to unauthorized data access, data modification, or complete database compromise. "
        "OWASP Top 10 classifies this as an Injection risk. The root cause is treating user input as executable code "
        "rather than as data. Mitigation requires parameterized queries (prepared statements) where the SQL structure "
        "is defined separately from the data values.",
        cwe_id="CWE-89",
        source_url="https://cwe.mitre.org/data/definitions/89.html",
    ),
    CorpusChunk(
        vuln_type="sql_injection",
        text="Safe alternatives to concatenated SQL queries include: (1) using parameterized queries with placeholders like "
        "cursor.execute('SELECT * FROM users WHERE name = ?', (user_name,)), (2) using an ORM like SQLAlchemy that "
        "generates parameterized queries automatically, and (3) strict input validation as a defense-in-depth layer. "
        "String formatting methods such as f-strings, .format(), and %-formatting are equally dangerous when building SQL strings "
        "because they do not distinguish between code and data. Never build SQL strings with user-controlled input.",
        cwe_id="CWE-89",
        source_url="https://owasp.org/www-community/attacks/SQL_Injection",
    ),
    CorpusChunk(
        vuln_type="sql_injection",
        text="Common injection points in Python include: string concatenation with '+', f-string interpolation "
        "(f'SELECT * FROM users WHERE id = {user_id}'), .format() calls, and %-formatting with user-controlled data. "
        "Even if the input appears sanitized, edge cases like encoded characters, comment sequences ('--'), "
        "and UNION-based payloads can bypass naive filters. Prepared statements are the only reliable defense. "
        "Tools like Bandit and SonarQube flag these patterns at the syntactic level, but understanding why "
        "they are dangerous requires knowledge of how SQL parsers interpret user data mixed with control characters.",
        cwe_id="CWE-89",
        source_url="https://cwe.mitre.org/data/definitions/89.html",
    ),
    # ── Command Injection ──────────────────────────────────────────
    CorpusChunk(
        vuln_type="command_injection",
        text="Command Injection (CWE-78) occurs when user-controlled data is passed to a shell command parser "
        "without proper sanitization. In Python, common vectors include os.system(), os.popen(), "
        "and subprocess functions with shell=True. When shell=True is used, the command string is interpreted "
        "by the system shell (e.g., /bin/sh or cmd.exe), which recognizes special characters like ';', '|', '&&', "
        "and backticks. An attacker can inject arbitrary shell commands by embedding these metacharacters in input. "
        "OWASP Top 10 classifies this as an Injection risk.",
        cwe_id="CWE-78",
        source_url="https://cwe.mitre.org/data/definitions/78.html",
    ),
    CorpusChunk(
        vuln_type="command_injection",
        text="The safest alternative is to avoid shell=True entirely. Use subprocess.run() with a list of arguments "
        "instead of a string: subprocess.run(['ls', '-l', user_path]) — this bypasses the shell parser entirely "
        "and passes arguments directly to the executable. When shell=True is unavoidable (rare), validate input "
        "against an allowlist of safe characters and reject anything containing shell metacharacters. "
        "The shlex.quote() function can help but is not foolproof. os.system() should never be used with "
        "untrusted input; it always invokes the shell.",
        cwe_id="CWE-78",
        source_url="https://owasp.org/www-community/attacks/Command_Injection",
    ),
    CorpusChunk(
        vuln_type="command_injection",
        text="Python-specific command injection risks: subprocess.call(shell_cmd, shell=True), "
        "os.system(f'ping {host}'), os.popen(command). Even indirect injection through environment variables "
        "or configuration files can be exploited. The severity is critical because shell access often leads "
        "to full system compromise, data exfiltration, or lateral movement within a network. "
        "CWE-78 is ranked in the 2024 CWE Top 25 Most Dangerous Software Weaknesses.",
        cwe_id="CWE-78",
        source_url="https://cwe.mitre.org/data/definitions/78.html",
    ),
    # ── Hardcoded Secrets ──────────────────────────────────────────
    CorpusChunk(
        vuln_type="hardcoded_secret",
        text="Hardcoded Secrets (CWE-798) refers to embedding authentication credentials — API keys, passwords, "
        "database connection strings, encryption keys, or tokens — directly in source code. This is dangerous "
        "because source code is frequently stored in version control systems (Git), shared with other developers, "
        "or deployed to multiple environments. Anyone with access to the repository gains permanent access to "
        "those credentials. OWASP Top 10 classifies this under Cryptographic Failures (previously Sensitive "
        "Data Exposure). Rotating compromised credentials is difficult and often incomplete.",
        cwe_id="CWE-798",
        source_url="https://cwe.mitre.org/data/definitions/798.html",
    ),
    CorpusChunk(
        vuln_type="hardcoded_secret",
        text="Modern approaches to secrets management include: (1) environment variables loaded at runtime, "
        "(2) dedicated secrets managers like HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault, "
        "(3) .env files for local development (never committed to version control), and (4) CI/CD pipeline "
        "injection of secrets at deploy time. In Python, use libraries like python-dotenv to load .env files "
        "or os.getenv() for environment variables. Never hardcode secrets even in test files, as test repos "
        "are often less protected than production repos. CWE-798 is part of the CWE Top 25.",
        cwe_id="CWE-798",
        source_url="https://owasp.org/www-community/attacks/Hardcoded_passwords",
    ),
    CorpusChunk(
        vuln_type="hardcoded_secret",
        text="Detection patterns for hardcoded secrets include: variable names containing 'api_key', 'secret', "
        "'password', 'token', 'credential', or 'auth' followed by a string literal assignment. "
        "Tools can also flag long alphanumeric strings that match common key formats (Base64, hex, or UUID patterns). "
        "However, static analysis alone cannot distinguish a real secret from a test value, so human review "
        "or heuristic scoring (entropy, context) is needed. git-secrets, truffleHog, and Gitleaks are "
        "specialized scanners for detecting secrets in codebases and git history.",
        cwe_id="CWE-798",
        source_url="https://cwe.mitre.org/data/definitions/798.html",
    ),
    # ── XSS ────────────────────────────────────────────────────────
    CorpusChunk(
        vuln_type="xss",
        text="Cross-Site Scripting (XSS, CWE-79) occurs when an application includes untrusted user input in "
        "web pages without proper escaping or sanitization. In Python web applications, XSS commonly arises in "
        "Flask when render_template_string() is called with user-controlled data, or when the |safe filter "
        "or Markup() is applied to untrusted strings in Jinja2 templates. XSS allows attackers to execute "
        "arbitrary JavaScript in a victim's browser, which can steal session cookies, redirect users to "
        "malicious sites, deface pages, or trigger malicious actions as the authenticated user.",
        cwe_id="CWE-79",
        source_url="https://cwe.mitre.org/data/definitions/79.html",
    ),
    CorpusChunk(
        vuln_type="xss",
        text="There are three types of XSS: (1) Reflected — input is immediately returned by the server in an error "
        "or search result, (2) Stored — input is saved in a database and served to other users later, "
        "(3) DOM-based — the client-side JavaScript itself processes untrusted input unsafely. "
        "OWASP Top 10 classifies XSS under Injection. Prevention techniques include: context-aware auto-escaping "
        "(Jinja2 enables this by default — never disable it with autoescape false), using a Content Security Policy "
        "(CSP) header, and validating/sanitizing input server-side. The safe filter should be avoided unless the "
        "content is known to be trusted HTML from an admin source.",
        cwe_id="CWE-79",
        source_url="https://owasp.org/www-community/attacks/xss/",
    ),
    CorpusChunk(
        vuln_type="xss",
        text="In Jinja2 templates, auto-escaping escapes characters like <, >, &, ', and \" to their HTML entity "
        "equivalents, preventing script execution. This protection is lost when: autoescape is set to false, "
        "the |safe filter is applied, or Markup() wraps a string (which marks it as safe HTML). "
        "render_template_string() is particularly dangerous because it is often used with dynamically "
        "constructed template strings that include user input — unlike render_template() which reads a "
        "static template file. CWE-79 is consistently one of the most prevalent vulnerabilities in web "
        "applications according to the CWE Top 25 and OWASP surveys.",
        cwe_id="CWE-79",
        source_url="https://cwe.mitre.org/data/definitions/79.html",
    ),
]
