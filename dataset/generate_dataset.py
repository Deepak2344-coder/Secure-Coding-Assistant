"""Deterministic, template-based generator for the Secure Coding Assistant benchmark dataset.

Produces ~320 labeled samples (vulnerable + secure) across the 4 target
vulnerability classes. Reproducible, $0, no network/LLM dependency.

Run:  python -m dataset.generate_dataset
Output: dataset/samples.json
"""
import json
import os
from itertools import product

HERE = os.path.dirname(os.path.abspath(__file__))

VULN_TYPES = ["sql_injection", "command_injection", "hardcoded_secret", "xss"]


# --------------------------------------------------------------------------
# SQL Injection
# --------------------------------------------------------------------------
def _sqli_vulnerable():
    imports = {
        "sqlite3": "import sqlite3\n",
        "psycopg2": "import psycopg2\n",
        "pymysql": "import pymysql\n",
        "raw": "",
    }
    setups = {
        "sqlite3": "    conn = sqlite3.connect('app.db')\n",
        "psycopg2": "    conn = psycopg2.connect()\n    cur = conn.cursor()\n",
        "pymysql": "    conn = pymysql.connect()\n    cursor = conn.cursor()\n",
        "raw": "",
    }
    execs = {
        "sqlite3": "conn.execute",
        "psycopg2": "cur.execute",
        "pymysql": "cursor.execute",
        "raw": "db.run",
    }
    styles = ["concat", "fstring", "format", "percent"]
    clauses = [
        "SELECT * FROM users WHERE name = ",
        "SELECT id FROM accounts WHERE email = ",
        "INSERT INTO logs VALUES (",
        "DELETE FROM sessions WHERE id = ",
        "UPDATE users SET email = ",
        "SELECT * FROM products WHERE cat = ",
    ]
    funcs = ["get_user", "login", "search", "find_record", "fetch"]
    vars_ = ["name", "username", "user_input", "term", "ident"]

    def build_query(style, clause, var):
        if style == "concat":
            return '"' + clause + '\'" + ' + var + ' + "\'"'
        if style == "fstring":
            return 'f"' + clause + '{' + var + '}"'
        if style == "format":
            return '"' + clause + "'{}'" + '"' + ".format(" + var + ")"
        if style == "percent":
            return '"' + clause + '%s" % ' + var
        raise ValueError(style)

    out = []
    seen = set()
    for lib, func, var, style, clause in product(imports, funcs, vars_, styles, clauses):
        q = build_query(style, clause, var)
        # Assemble via concatenation (q may contain braces) to avoid f-string parsing.
        code = (
            imports[lib]
            + f"def {func}({var}):\n"
            + setups[lib]
            + f"    {execs[lib]}({q})\n"
        )
        key = (lib, func, var, style, clause[:15])
        if key in seen:
            continue
        seen.add(key)
        out.append(code)
        if len(out) >= 72:
            break
    return out


def _sqli_secure():
    out = []
    libs = [
        ("import sqlite3\n",
         "    conn = sqlite3.connect('app.db')\n    conn.execute(\"SELECT * FROM users WHERE name = ?\", (name,))"),
        ("import psycopg2\n",
         "    conn = psycopg2.connect()\n    cur = conn.cursor()\n    cur.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"),
        ("import pymysql\n",
         "    conn = pymysql.connect()\n    cursor = conn.cursor()\n    cursor.execute(\"SELECT * FROM users WHERE name = %s\", (name,))"),
    ]
    funcs = ["get_user", "login", "fetch"]
    for (pre, stmt), func in product(libs, funcs):
        out.append(f"{pre}def {func}(name):\n{stmt}\n")
    # ORM style
    out.append(
        "from sqlalchemy import text\n"
        "def get_user(name):\n"
        "    stmt = text('SELECT * FROM users WHERE name = :name')\n"
        "    result = session.execute(stmt, {'name': name})\n"
    )
    return out[:8]


# --------------------------------------------------------------------------
# Command Injection
# --------------------------------------------------------------------------
def _cmd_vulnerable():
    styles = {
        "os_system_concat": lambda v: f"\"ping -c 1 \" + {v}",
        "os_system_fstring": lambda v: f"f\"ping -c 1 {{{v}}}\"",
        "os_popen_concat": lambda v: f"\"echo \" + {v}",
        "subprocess_call": "subprocess.call(cmd, shell=True)",
        "subprocess_run": "subprocess.run(cmd, shell=True)",
        "subprocess_popen_fstring": lambda v: f"f\"ls -la {{{v}}}\"",
    }
    funcs = ["ping", "run_cmd", "execute", "list_dir", "do_backup"]
    vars_ = ["host", "user_input", "path", "filename", "arg"]
    out = []
    seen = set()
    for (style_name, style_val), func, var in product(styles.items(), funcs, vars_):
        if style_name.startswith("subprocess"):
            call = style_val
            pre = "import subprocess\n"
            code = f"{pre}def {func}({var}):\n    {call}\n"
        else:
            q = style_val(var) if callable(style_val) else style_val
            pre = "import os\n"
            code = f"{pre}def {func}({var}):\n    os.system({q})\n"
        key = (style_name, func, var)
        if key in seen:
            continue
        seen.add(key)
        out.append(code)
        if len(out) >= 72:
            break
    return out


def _cmd_secure():
    out = []
    templates = [
        ("import subprocess\n"
         "def ping(host):\n"
         "    subprocess.run(['ping', '-c', '1', host])\n"),
        ("import subprocess\n"
         "def run_cmd(arg):\n"
         "    subprocess.run(['ls', '-la', arg])\n"),
        ("import subprocess\n"
         "def list_dir(path):\n"
         "    subprocess.run(['dir', path], shell=False)\n"),
        ("import subprocess\n"
         "def do_backup(filename):\n"
         "    subprocess.run(['tar', '-czf', 'backup.tar.gz', filename])\n"),
        ("import subprocess\n"
         "def execute(cmd_args):\n"
         "    subprocess.run(cmd_args)\n"),
    ]
    return templates[:8]


# --------------------------------------------------------------------------
# Hardcoded Secret
# --------------------------------------------------------------------------
def _secret_vulnerable():
    names = [
        "API_KEY", "api_key", "SECRET_KEY", "secret_token", "DB_PASSWORD",
        "password", "auth_key", "github_token", "aws_access_key", "client_secret",
    ]
    values = [
        "sk-2a3b4c5d6e7f8g9h0i1j2k3l4m5n6o7p",
        "super_secret_p@ssw0rd_2024",
        "ghp_1234567890abcdefghijklmnopqrstuvwxyz",
        "AKIAIOSFODNN7EXAMPLE3PLUS",
        "django-insecure-abc123def456ghi789jkl",
        "bearer_abcdef1234567890abcdef1234567890",
        "token_9f8e7d6c5b4a39281706f5e4d3c2b1a0",
        "postgres://user:Pa55w0rd@localhost:5432/db",
    ]
    out = []
    seen = set()
    for name, val in product(names, values):
        code = f"{name} = \"{val}\"\n"
        key = (name, val[:8])
        if key in seen:
            continue
        seen.add(key)
        out.append(code)
        if len(out) >= 72:
            break
    return out


def _secret_secure():
    out = [
        "import os\nAPI_KEY = os.environ.get('API_KEY')\n",
        "import os\nDB_PASSWORD = os.getenv('DB_PASSWORD')\n",
        "import os\nSECRET_KEY = os.environ['SECRET_KEY']\n",
        "from config import settings\napi_token = settings.API_TOKEN\n",
        "import os\naws_key = os.environ.get('AWS_ACCESS_KEY_ID')\n",
        "API_KEY = load_secret('api_key')  # from vault\n",
        "password = get_credentials('db')['password']\n",
        "token = keyring.get_password('svc', 'token')\n",
    ]
    return out[:8]


# --------------------------------------------------------------------------
# XSS
# --------------------------------------------------------------------------
def _xss_vulnerable():
    styles = {
        "render_template_string_f": lambda v: f"render_template_string(f\"<h1>Welcome {v}!</h1>\")",
        "render_template_string_concat": lambda v: f"render_template_string(\"<p>\" + {v} + \"</p>\")",
        "markup": lambda v: f"Markup(f\"<div class='alert'>{v}</div>\")",
        "safe_filter": "return '<div>{{ user_input|safe }}</div>'",
        "autoescape_false": "{% autoescape false %}\n{{ user_comment }}\n{% endautoescape %}",
    }
    funcs = ["render_profile", "display_message", "show_search", "greet", "render_comment"]
    vars_ = ["username", "msg", "query", "user_input", "comment"]
    out = []
    seen = set()
    for (style_name, style_val), func, var in product(styles.items(), funcs, vars_):
        if style_name in ("safe_filter", "autoescape_false"):
            code = style_val
        else:
            q = style_val(var) if callable(style_val) else style_val
            pre = "from flask import render_template_string\nfrom markupsafe import Markup\n" if "Markup" in q else "from flask import render_template_string\n"
            code = f"{pre}def {func}({var}):\n    return {q}\n"
        key = (style_name, func, var)
        if key in seen:
            continue
        seen.add(key)
        out.append(code)
        if len(out) >= 72:
            break
    return out


def _xss_secure():
    out = [
        ("from flask import render_template_string\n"
         "def render_profile(username):\n"
         "    return render_template_string('<h1>Welcome {{ username }}</h1>', username=username)\n"),
        ("from flask import render_template\n"
         "def display_message(msg):\n"
         "    return render_template('message.html', msg=msg)\n"),
        ("from markupsafe import escape\n"
         "def greet(user_input):\n"
         "    return '<div>' + escape(user_input) + '</div>'\n"),
        ("from flask import render_template_string\n"
         "def show_search(query):\n"
         "    return render_template_string('<p>You searched for: {{ query }}</p>', query=query)\n"),
        ("from markupsafe import escape\nfrom markupsafe import Markup\n"
         "def render_comment(comment):\n"
         "    return Markup('<div>' + escape(comment) + '</div>')\n"),
        ("def greet2(name):\n    return f'<b>' + name + '</b>'\n"),
        ("from flask import render_template\n"
         "def render_user(username):\n"
         "    return render_template('user.html', username=username)\n"),
        ("from markupsafe import escape\n"
         "def show(user_input):\n"
         "    return escape(user_input)\n"),
    ]
    return out[:8]


GENERATORS = {
    "sql_injection": (_sqli_vulnerable, _sqli_secure),
    "command_injection": (_cmd_vulnerable, _cmd_secure),
    "hardcoded_secret": (_secret_vulnerable, _secret_secure),
    "xss": (_xss_vulnerable, _xss_secure),
}


def generate():
    samples = []
    for vtype, (vuln_fn, secure_fn) in GENERATORS.items():
        vuln = vuln_fn()
        secure = secure_fn()
        for i, code in enumerate(vuln, 1):
            samples.append({
                "id": f"{vtype[:4]}_v_{i:03d}",
                "vuln_type": vtype,
                "label": "vulnerable",
                "expected_vuln_type": vtype,
                "code": code.rstrip("\n"),
                "notes": f"Templated {vtype} vulnerable sample #{i}",
            })
        for i, code in enumerate(secure, 1):
            samples.append({
                "id": f"{vtype[:4]}_s_{i:03d}",
                "vuln_type": vtype,
                "label": "secure",
                "expected_vuln_type": None,
                "code": code.rstrip("\n"),
                "notes": f"Templated {vtype} secure/patched sample #{i}",
            })
    return samples


def main():
    samples = generate()
    out_path = os.path.join(HERE, "samples.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(samples, f, indent=2, ensure_ascii=False)

    # Summary
    from collections import Counter
    by_label = Counter(s["label"] for s in samples)
    by_type = Counter(s["vuln_type"] for s in samples)
    print(f"Wrote {len(samples)} samples to {out_path}")
    print("By label:", dict(by_label))
    print("By type:", dict(by_type))


if __name__ == "__main__":
    main()
