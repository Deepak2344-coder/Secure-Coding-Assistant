import streamlit as st
import requests
import json
import difflib
import base64
import html
from datetime import datetime
from io import BytesIO
import os

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="Secure Coding Assistant",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .severity-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        white-space: nowrap;
    }
    .severity-high { background-color: #fee2e2; color: #991b1b; }
    .severity-medium { background-color: #fef3c7; color: #92400e; }
    .severity-low { background-color: #dcfce7; color: #166534; }
    .category-badge {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 500;
        background-color: #f1f5f9;
        color: #334155;
    }
    .copy-btn {
        background: #f1f5f9;
        border: 1px solid #e2e8f0;
        border-radius: 4px;
        padding: 4px 8px;
        font-size: 0.75rem;
        cursor: pointer;
        transition: all 0.2s;
    }
    .copy-btn:hover {
        background: #e2e8f0;
    }
    .copy-btn.copied {
        background: #dcfce7;
        border-color: #86efac;
        color: #166534;
    }
    .diff-container {
        font-family: 'Monospace', monospace;
        font-size: 0.85rem;
        line-height: 1.5;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        overflow: hidden;
    }
    .diff-line { white-space: pre-wrap; font-family: monospace; }
    .diff-removed { background-color: #dc2626; color: #ffffff; }
    .diff-added { background-color: #4ade80; color: #ffffff; }
    .diff-unchanged { background-color: #ffffff; color: #1e293b; }
    .diff-header { background-color: #1e293b; color: #ffffff; font-weight: bold; }
    .diff-legend { font-size: 0.8rem; margin-bottom: 0.5rem; }
    .tooltipped { position: relative; cursor: help; }
    .tooltipped::after {
        content: attr(data-tooltip);
        position: absolute;
        bottom: 125%;
        left: 50%;
        transform: translateX(-50%);
        background: #1e293b;
        color: white;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.7rem;
        white-space: nowrap;
        opacity: 0;
        visibility: hidden;
        transition: all 0.2s;
        z-index: 100;
    }
    .tooltipped:hover::after {
        opacity: 1;
        visibility: visible;
    }
    .report-header {
        text-align: center;
        padding: 1rem;
        border-bottom: 2px solid #e2e8f0;
        margin-bottom: 1.5rem;
    }
    .issue-card {
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 1rem;
        background: white;
    }
    .issue-header {
        display: flex;
        align-items: center;
        gap: 8px;
        margin-bottom: 0.75rem;
        flex-wrap: wrap;
    }
    .line-badge {
        background: #e2e8f0;
        color: #334155;
        padding: 2px 8px;
        border-radius: 4px;
        font-family: monospace;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .vuln-type {
        font-weight: 600;
        color: #1e293b;
        text-transform: capitalize;
    }
    .stDownloadButton > button {
        background: #3b82f6;
        color: white;
        border: none;
    }
    .stDownloadButton > button:hover {
        background: #2563eb;
    }
    .stButton > button[kind="secondary"] {
        background: #f1f5f9;
        color: #334155;
        border: 1px solid #e2e8f0;
    }
    .stButton > button[kind="secondary"]:hover {
        background: #e2e8f0;
    }
</style>
""", unsafe_allow_html=True)

st.title("🛡️ Secure Coding Assistant")
st.markdown(
    "Paste your Python code below to scan for security vulnerabilities, "
    "syntax errors, and common logical mistakes."
)

SEVERITY_CONFIG = {
    "High": {
        "icon": "🔴",
        "label": "High",
        "css_class": "severity-high",
        "tooltip": "High severity: Immediate security risk, exploit likely",
    },
    "Medium": {
        "icon": "🟡",
        "label": "Medium",
        "css_class": "severity-medium",
        "tooltip": "Medium severity: Potential security risk, requires attention",
    },
    "Low": {
        "icon": "🟢",
        "label": "Low",
        "css_class": "severity-low",
        "tooltip": "Low severity: Minor issue, defensive improvement recommended",
    },
}

CATEGORY_CONFIG = {
    "security": {"icon": "🔴", "label": "Security", "tooltip": "Security vulnerability - may allow attacks"},
    "syntax": {"icon": "🟣", "label": "Syntax", "tooltip": "Syntax error - code will not run"},
    "logic": {"icon": "🟠", "label": "Logic", "tooltip": "Logic error - code runs but behaves incorrectly"},
}

def copy_button(text: str, key: str, label: str = "📋 Copy") -> None:
    """Render a copy-to-clipboard button using Streamlit's built-in clipboard."""
    if st.button(label, key=key, help="Copy to clipboard"):
        st.code(text, language="python")
        st.toast(f"Copied {label.lower()}!", icon="✅")

def render_severity_badge(severity: str) -> str:
    """Render a styled severity badge with icon and tooltip."""
    config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["Low"])
    return f'<span class="severity-badge {config["css_class"]} tooltipped" data-tooltip="{config["tooltip"]}">{config["icon"]} {config["label"]}</span>'

def render_category_badge(category: str) -> str:
    """Render a styled category badge with icon and tooltip."""
    config = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["security"])
    return f'<span class="category-badge tooltipped" data-tooltip="{config["tooltip"]}">{config["icon"]} {config["label"]}</span>'

def generate_diff(original: str, modified: str) -> str:
    """Generate a side-by-side diff HTML between original and modified code.

    Design: white canvas for unchanged lines; solid red with white text for
    the vulnerable ("wrong") lines; solid light green with white text for the
    secure ("right") rewrite lines.
    """
    original_lines = original.splitlines(keepends=True)
    modified_lines = modified.splitlines(keepends=True)
    
    diff = difflib.SequenceMatcher(None, original_lines, modified_lines)
    
    html_parts = ['<div class="diff-container">']
    html_parts.append(
        '<div class="diff-legend">'
        '<span style="display:inline-block;width:12px;height:12px;background:#dc2626;vertical-align:middle;margin-right:4px;border-radius:2px;"></span>'
        'Vulnerable (original) &nbsp;&nbsp; '
        '<span style="display:inline-block;width:12px;height:12px;background:#4ade80;vertical-align:middle;margin-right:4px;border-radius:2px;"></span>'
        'Secure rewrite'
        '</div>'
    )
    html_parts.append('<table style="width: 100%; border-collapse: collapse; font-family: monospace; font-size: 0.85rem;">')
    html_parts.append(
        '<thead><tr>'
        '<th class="diff-header" style="width: 50%; padding: 6px 10px; text-align: left;">🔴 Original (Vulnerable)</th>'
        '<th class="diff-header" style="width: 50%; padding: 6px 10px; text-align: left;">🟢 Secure Rewrite</th>'
        '</tr></thead>'
    )
    html_parts.append('<tbody>')
    
    cell_style = 'padding: 2px 10px; border-right: 1px solid #e2e8f0;'
    blank_style = 'padding: 2px 10px; background-color: #ffffff;'
    
    for tag, i1, i2, j1, j2 in diff.get_opcodes():
        if tag == 'equal':
            for i in range(i1, i2):
                line = html.escape(original_lines[i].rstrip('\n')) or "&nbsp;"
                html_parts.append(
                    f'<tr><td class="diff-line diff-unchanged" style="{cell_style}">{line}</td>'
                    f'<td class="diff-line diff-unchanged" style="padding: 2px 10px;">{line}</td></tr>'
                )
        elif tag == 'delete':
            for i in range(i1, i2):
                line = html.escape(original_lines[i].rstrip('\n')) or "&nbsp;"
                html_parts.append(
                    f'<tr><td class="diff-line diff-removed" style="{cell_style}">{line}</td>'
                    f'<td class="diff-line diff-unchanged" style="{blank_style}">&nbsp;</td></tr>'
                )
        elif tag == 'insert':
            for j in range(j1, j2):
                line = html.escape(modified_lines[j].rstrip('\n')) or "&nbsp;"
                html_parts.append(
                    f'<tr><td class="diff-line diff-unchanged" style="{cell_style}">&nbsp;</td>'
                    f'<td class="diff-line diff-added" style="padding: 2px 10px;">{line}</td></tr>'
                )
        elif tag == 'replace':
            max_lines = max(i2 - i1, j2 - j1)
            for k in range(max_lines):
                has_orig = i1 + k < i2
                has_mod = j1 + k < j2
                orig_line = html.escape(original_lines[i1 + k].rstrip('\n')) if has_orig else "&nbsp;"
                mod_line = html.escape(modified_lines[j1 + k].rstrip('\n')) if has_mod else "&nbsp;"
                orig_class = "diff-removed" if has_orig else "diff-unchanged"
                mod_class = "diff-added" if has_mod else "diff-unchanged"
                orig_style = cell_style if has_orig else blank_style
                mod_style = "padding: 2px 10px;" if has_mod else blank_style
                html_parts.append(
                    f'<tr><td class="diff-line {orig_class}" style="{orig_style}">{orig_line}</td>'
                    f'<td class="diff-line {mod_class}" style="{mod_style}">{mod_line}</td></tr>'
                )
    
    html_parts.append('</tbody></table></div>')
    return ''.join(html_parts)

def generate_markdown_report(code: str, issues: list, scan_time: str) -> str:
    """Generate a Markdown report of the full scan."""
    lines = [
        "# Secure Coding Assistant - Scan Report",
        f"**Scan Time:** {scan_time}",
        f"**Lines of Code:** {len(code.splitlines())}",
        f"**Issues Found:** {len(issues)}",
        "",
        "---",
        "",
        "## Source Code",
        "```python",
        code,
        "```",
        "",
        "---",
        "",
        "## Issues Detected",
        "",
    ]
    
    if not issues:
        lines.append("No issues detected! 🎉")
    else:
        for i, issue in enumerate(issues, 1):
            severity = issue.get("severity", "Low")
            category = issue.get("category", "security")
            severity_config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["Low"])
            category_config = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["security"])
            
            lines.extend([
                f"### Issue #{i}: {issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}",
                f"**Line:** {issue.get('line', 'N/A')}  ",
                f"**Severity:** {severity_config['icon']} {severity}  ",
                f"**Category:** {category_config['icon']} {category_config['label']}  ",
                f"**Confidence:** {issue.get('confidence', 'N/A')}  ",
                f"**CWE Reference:** {issue.get('cwe_reference', 'N/A')}  ",
                "",
                "#### Vulnerable Code",
                "```python",
                issue.get('snippet', ''),
                "```",
                "",
            ])
            
            if issue.get("message"):
                lines.extend(["#### Detail", issue["message"], ""])
            
            if issue.get("explanation"):
                lines.extend(["#### Explanation", issue["explanation"], ""])
            
            if issue.get("secure_rewrite"):
                lines.extend([
                    "#### Secure Rewrite",
                    "```python",
                    issue["secure_rewrite"],
                    "```",
                    "",
                ])
            
            if issue.get("source_url"):
                lines.extend([f"**Reference:** [{issue['cwe_reference']}]({issue['source_url']})", ""])
            
            lines.append("---")
            lines.append("")
    
    return "\n".join(lines)

def _pdf_safe(text: str) -> str:
    """Make text safe for the default (Latin-1) PDF fonts.

    Replaces common Unicode punctuation (em/en dashes, smart quotes,
    arrows, bullets, ellipsis, non-breaking spaces) with ASCII equivalents
    and drops any remaining non-Latin-1 characters so fpdf2 never raises
    FPDFUnicodeEncodingException.
    """
    if text is None:
        return ""
    repl = {
        "\u2014": "-", "\u2013": "-",          # em / en dash
        "\u2018": "'", "\u2019": "'",          # smart single quotes
        "\u201c": '"', "\u201d": '"',          # smart double quotes
        "\u2026": "...", "\u2022": "*",        # ellipsis / bullet
        "\u2192": "->", "\u2190": "<-", "\u2194": "<->",  # arrows
        "\u00a0": " ",                          # non-breaking space
        "\u2011": "-", "\u2043": "-",          # non-breaking / hyphen bullet
    }
    for k, v in repl.items():
        text = text.replace(k, v)
    return text.encode("latin-1", "replace").decode("latin-1")


def generate_pdf_report(code: str, issues: list, scan_time: str) -> bytes:
    """Generate a PDF report using FPDF."""
    if not FPDF_AVAILABLE:
        return None
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, _pdf_safe("Secure Coding Assistant - Scan Report"), ln=True, align="C")
    pdf.ln(5)
    
    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, _pdf_safe(f"Scan Time: {scan_time}"), ln=True)
    pdf.cell(0, 6, _pdf_safe(f"Lines of Code: {len(code.splitlines())}"), ln=True)
    pdf.cell(0, 6, _pdf_safe(f"Issues Found: {len(issues)}"), ln=True)
    pdf.ln(5)
    
    # Source Code
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("Source Code"), ln=True)
    pdf.set_font("Courier", "", 8)
    for line in code.splitlines():
        pdf.cell(0, 4, _pdf_safe(line[:120]), ln=True)
    pdf.ln(5)
    
    # Issues
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, _pdf_safe("Issues Detected"), ln=True)
    pdf.ln(2)
    
    for i, issue in enumerate(issues, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, _pdf_safe(f"Issue #{i}: {issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}"), ln=True)
        
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, _pdf_safe(f"  Line: {issue.get('line', 'N/A')}  |  Severity: {issue.get('severity', 'Low')}  |  Category: {issue.get('category', 'security')}"), ln=True)
        pdf.cell(0, 5, _pdf_safe(f"  Confidence: {issue.get('confidence', 'N/A')}  |  CWE: {issue.get('cwe_reference', 'N/A')}"), ln=True)
        
        if issue.get("snippet"):
            pdf.set_font("Courier", "", 8)
            for line in issue["snippet"].splitlines():
                pdf.cell(0, 4, _pdf_safe(f"  {line[:100]}"), ln=True)
        
        if issue.get("message"):
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, _pdf_safe(f"  Detail: {issue['message']}"))
        
        if issue.get("explanation"):
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, _pdf_safe("  Explanation:"), ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, _pdf_safe(f"  {issue['explanation']}"))
        
        if issue.get("secure_rewrite"):
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, _pdf_safe("  Secure Rewrite:"), ln=True)
            pdf.set_font("Courier", "", 8)
            for line in issue["secure_rewrite"].splitlines():
                pdf.cell(0, 4, _pdf_safe(f"  {line[:100]}"), ln=True)
        
        pdf.ln(3)
    
    return bytes(pdf.output())

def download_button(content: str, filename: str, label: str, mime: str) -> None:
    """Create a download button for text content."""
    b64 = base64.b64encode(content.encode()).decode()
    href = f'<a href="data:{mime};base64,{b64}" download="{filename}" style="display: inline-block; padding: 0.5rem 1rem; background: #3b82f6; color: white; border-radius: 0.375rem; text-decoration: none; font-weight: 500;">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

def pdf_download_button(pdf_bytes: bytes, filename: str, label: str) -> None:
    """Create a download button for PDF content."""
    b64 = base64.b64encode(pdf_bytes).decode()
    href = f'<a href="data:application/pdf;base64,{b64}" download="{filename}" style="display: inline-block; padding: 0.5rem 1rem; background: #3b82f6; color: white; border-radius: 0.375rem; text-decoration: none; font-weight: 500;">{label}</a>'
    st.markdown(href, unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ Settings")
    API_URL = st.text_input("API URL", value=API_URL, help="FastAPI backend URL")
    show_diff = st.checkbox("Show Diff View", value=True, help="Show side-by-side diff for secure rewrites")
    show_raw = st.checkbox("Show Raw JSON", value=False, help="Display raw API response")
    
    st.divider()
    st.markdown("### 📊 Scan Summary")
    if "scan_result" in st.session_state:
        result = st.session_state.scan_result
        issues = result.get("issues", [])
        st.metric("Issues Found", len(issues))
        if issues:
            high = sum(1 for i in issues if i.get("severity") == "High")
            med = sum(1 for i in issues if i.get("severity") == "Medium")
            low = sum(1 for i in issues if i.get("severity") == "Low")
            col1, col2, col3 = st.columns(3)
            col1.metric("🔴 High", high)
            col2.metric("🟡 Medium", med)
            col3.metric("🟢 Low", low)
    
    st.divider()
    st.markdown("### 📥 Export Report")
    if "scan_result" in st.session_state and "scan_code" in st.session_state:
        is_multi = st.session_state.scan_code == "__multi__"
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build display code for report
        if is_multi and st.session_state.uploaded_files:
            combined = "\n\n".join(
                f"# --- {path} ---\n{code}"
                for path, code in st.session_state.uploaded_files.items()
            )
        else:
            combined = st.session_state.scan_code if not is_multi else ""

        if combined:
            md_report = generate_markdown_report(
                combined,
                st.session_state.scan_result.get("issues", []),
                scan_time
            )
            download_button(md_report, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", "📄 Download Markdown", "text/markdown")

        if FPDF_AVAILABLE and not is_multi:
            pdf_bytes = generate_pdf_report(
                st.session_state.scan_code,
                st.session_state.scan_result.get("issues", []),
                scan_time
            )
            if pdf_bytes:
                pdf_download_button(pdf_bytes, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", "📑 Download PDF")
        elif not FPDF_AVAILABLE:
            st.caption("💡 Install `fpdf2` for PDF export: `pip install fpdf2`")

# --- Callback-based file upload (single .py + multi-file .zip) ---
if "code_text" not in st.session_state:
    st.session_state.code_text = ""
if "uploaded_files" not in st.session_state:
    st.session_state.uploaded_files = {}


def _on_upload():
    f = st.session_state.get("file_uploader")
    if f is not None:
        try:
            st.session_state.code_text = f.read().decode("utf-8")
            st.session_state.uploaded_files = {}
        except Exception:
            st.session_state.code_text = ""


def _on_upload_zip():
    zf = st.session_state.get("zip_uploader")
    if zf is not None:
        import zipfile
        try:
            files = {}
            with zipfile.ZipFile(zf) as z:
                for name in z.namelist():
                    if name.endswith(".py"):
                        files[name] = z.read(name).decode("utf-8")
            if files:
                st.session_state.uploaded_files = files
                total = sum(len(c.splitlines()) for c in files.values())
                names = "\n".join(f"  - {k} ({len(v.splitlines())} lines)" for k, v in files.items())
                st.session_state._zip_msg = f"Loaded {len(files)} files ({total} lines):\n{names}"
            else:
                st.session_state._zip_msg = "No .py files found in the archive."
        except Exception:
            st.session_state._zip_msg = "Could not read zip file."


def _clear():
    st.session_state.code_text = ""
    st.session_state.uploaded_files = {}
    st.session_state._zip_msg = ""
    if "scan_result" in st.session_state:
        del st.session_state.scan_result
    if "scan_code" in st.session_state:
        del st.session_state.scan_code


col_left, col_right = st.columns(2)
with col_left:
    st.file_uploader(
        "Upload a .py file",
        type=["py"],
        key="file_uploader",
        on_change=_on_upload,
    )
with col_right:
    st.file_uploader(
        "Or upload a .zip project",
        type=["zip"],
        key="zip_uploader",
        on_change=_on_upload_zip,
    )

if st.session_state.uploaded_files:
    st.info(st.session_state.get("_zip_msg", ""), icon="📦")

code_text = st.text_area(
    "Code Input",
    height=300,
    key="code_text",
    placeholder='# Paste your Python code here...\n\ndef get_user(name):\n    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n    ...',
)

col1, col2, col3 = st.columns([1, 1, 1])
files_mode = bool(st.session_state.uploaded_files)
with col1:
    scan_label = "🔍 Scan All Files" if files_mode else "🔍 Scan Code"
    scan_clicked = st.button(scan_label, type="primary", use_container_width=True)
with col2:
    st.button("🗑️ Clear", use_container_width=True, on_click=_clear)
with col3:
    if "scan_result" in st.session_state and st.button("🔄 Rescan", use_container_width=True):
        scan_clicked = True

if scan_clicked:
    if files_mode:
        files_dict = st.session_state.uploaded_files
        payload = {"files": files_dict}
        endpoint = f"{API_URL}/scan-files"
        timeout = 60 + 15 * len(files_dict)
        scan_code_key = "__multi__"
    else:
        if not st.session_state.code_text.strip():
            st.warning("Please enter or upload some code to scan.")
            scan_clicked = False
        else:
            payload = {"code": st.session_state.code_text}
            endpoint = f"{API_URL}/scan"
            timeout = 60
            scan_code_key = st.session_state.code_text

    if scan_clicked:
        with st.spinner(f"Scanning{' ' + str(len(files_dict)) + ' files' if files_mode else ' code'} for vulnerabilities..."):
            try:
                response = requests.post(
                    endpoint,
                    json=payload,
                    timeout=timeout,
                )
                response.raise_for_status()
                result = response.json()

                st.session_state.scan_result = result
                st.session_state.scan_code = scan_code_key

                if not result["issues"]:
                    st.success("✅ No issues detected! Your code looks secure.")
                else:
                    st.warning(f"⚠️ Found {len(result['issues'])} issue(s)")
                    if files_mode:
                        from collections import Counter
                        per_file = Counter(i.get("file_path", "?") for i in result["issues"])
                        details = ", ".join(f"{p}: {n}" for p, n in per_file.most_common())
                        st.caption(f"Per file — {details}")

                st.rerun()

            except requests.exceptions.ConnectionError:
                st.error(
                    "Cannot connect to the backend. Make sure the FastAPI server is running on port 8000."
                )
            except Exception as e:
                st.error(f"An error occurred: {e}")

if "scan_result" in st.session_state:
    result = st.session_state.scan_result
    issues = result.get("issues", [])
    code = st.session_state.get("scan_code", st.session_state.code_text)
    
    if issues:
        st.markdown("---")

        # Group issues by file_path for multi-file scans
        has_file_paths = any(i.get("file_path") for i in issues)
        if has_file_paths:
            from collections import defaultdict
            by_file = defaultdict(list)
            for i in issues:
                by_file[i.get("file_path", "")].append(i)
            file_groups = list(by_file.items())
        else:
            file_groups = [("", issues)]

        global_idx = 0
        for file_path, file_issues in file_groups:
            if file_path:
                st.markdown(f"### 📁 `{file_path}`")
                st.caption(f"{len(file_issues)} issue(s) in this file")

            for idx, issue in enumerate(file_issues):
                severity = issue.get("severity", "Low")
                category = issue.get("category", "security")
                severity_config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["Low"])
                category_config = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["security"])

                heading = (
                    f"Line {issue.get('line', '?')} — "
                    f"{issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}"
                )

                with st.expander(heading, expanded=(global_idx == 0)):
                    fp_badge = f'<span class="line-badge">{file_path}</span> ' if file_path else ""
                    st.markdown(
                        f"""
                        <div class="issue-header">
                            {fp_badge}
                            <span class="line-badge">Line {issue.get('line', '?')}</span>
                            <span class="vuln-type">{issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}</span>
                            {render_category_badge(category)}
                            {render_severity_badge(severity)}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    col1, col2, col3, col4 = st.columns(4)
                    col1.metric("Confidence", issue.get("confidence", "N/A"))
                    col2.metric("Severity", severity)
                    col3.metric("Category", category_config["label"])
                    col4.metric("CWE", issue.get("cwe_reference", "N/A"))

                    st.divider()

                    st.markdown("#### 🔴 Vulnerable Code")
                    snippet = issue.get("snippet", "")
                    st.code(snippet, language="python")

                    copy_col1, copy_col2 = st.columns([1, 5])
                    with copy_col1:
                        if st.button("📋 Copy", key=f"copy_snippet_{global_idx}", help="Copy vulnerable snippet"):
                            st.code(snippet, language="python")
                            st.toast("Copied vulnerable snippet!", icon="✅")

                    if issue.get("message"):
                        st.info(f"**Detail:** {issue['message']}")

                    if issue.get("explanation"):
                        st.markdown("#### 💡 Explanation")
                        st.info(issue["explanation"])

                    if issue.get("secure_rewrite"):
                        st.markdown("#### 🟢 Secure Rewrite")
                        rewrite = issue["secure_rewrite"]
                        st.code(rewrite, language="python")

                        copy_col1, copy_col2 = st.columns([1, 5])
                        with copy_col1:
                            if st.button("📋 Copy", key=f"copy_rewrite_{global_idx}", help="Copy secure rewrite"):
                                st.code(rewrite, language="python")
                                st.toast("Copied secure rewrite!", icon="✅")

                        if show_diff and snippet and rewrite:
                            st.markdown("#### 🔄 Diff View")
                            diff_html = generate_diff(snippet, rewrite)
                            st.markdown(diff_html, unsafe_allow_html=True)

                    if issue.get("cwe_reference"):
                        cwe = issue["cwe_reference"]
                        url = issue.get("source_url") or f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"
                        st.markdown(f"**Reference:** [{cwe}]({url})")

                global_idx += 1
    
    if show_raw:
        st.markdown("---")
        st.markdown("### Raw API Response")
        st.json(result)

# Footer
st.markdown("---")
st.caption(
    "🛡️ Secure Coding Assistant — Built for educational purposes. "
    "Not a substitute for professional security auditing."
)