import streamlit as st
import requests
import json
import difflib
import base64
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
    }
    .diff-line { white-space: pre-wrap; font-family: monospace; }
    .diff-added { background-color: #dcfce7; }
    .diff-removed { background-color: #fee2e2; }
    .diff-unchanged { background-color: transparent; }
    .diff-header { background-color: #f1f5f9; font-weight: bold; }
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

CATEGORY_ICON = {
    "security": "🔴",
    "syntax": "🟣",
    "logic": "🟠",
}

CATEGORY_LABEL = {
    "security": "Security",
    "syntax": "Syntax",
    "logic": "Logic",
}

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
    """Generate a side-by-side diff HTML between original and modified code."""
    original_lines = original.splitlines(keepends=True)
    modified_lines = modified.splitlines(keepends=True)
    
    diff = difflib.SequenceMatcher(None, original_lines, modified_lines)
    
    html_parts = ['<div class="diff-container">']
    html_parts.append('<table style="width: 100%; border-collapse: collapse; font-family: monospace; font-size: 0.85rem;">')
    html_parts.append('<thead><tr><th style="width: 50%; padding: 4px 8px; text-align: left; border-bottom: 1px solid #e2e8f0;">Original</th><th style="width: 50%; padding: 4px 8px; text-align: left; border-bottom: 1px solid #e2e8f0;">Secure Rewrite</th></tr></thead>')
    html_parts.append('<tbody>')
    
    for tag, i1, i2, j1, j2 in diff.get_opcodes():
        if tag == 'equal':
            for i in range(i1, i2):
                line = original_lines[i].rstrip('\n')
                html_parts.append(f'<tr><td class="diff-line diff-unchanged" style="padding: 2px 8px; border-right: 1px solid #e2e8f0;">{line or "&nbsp;"}</td><td class="diff-line diff-unchanged" style="padding: 2px 8px;">{line or "&nbsp;"}</td></tr>')
        elif tag == 'delete':
            for i in range(i1, i2):
                line = original_lines[i].rstrip('\n')
                html_parts.append(f'<tr><td class="diff-line diff-removed" style="padding: 2px 8px; border-right: 1px solid #e2e8f0; background: #fee2e2;">{line or "&nbsp;"}</td><td class="diff-line diff-unchanged" style="padding: 2px 8px; background: #f8fafc;">&nbsp;</td></tr>')
        elif tag == 'insert':
            for j in range(j1, j2):
                line = modified_lines[j].rstrip('\n')
                html_parts.append(f'<tr><td class="diff-line diff-unchanged" style="padding: 2px 8px; border-right: 1px solid #e2e8f0; background: #f8fafc;">&nbsp;</td><td class="diff-line diff-added" style="padding: 2px 8px; background: #dcfce7;">{line or "&nbsp;"}</td></tr>')
        elif tag == 'replace':
            max_lines = max(i2 - i1, j2 - j1)
            for k in range(max_lines):
                orig_line = original_lines[i1 + k].rstrip('\n') if i1 + k < i2 else ""
                mod_line = modified_lines[j1 + k].rstrip('\n') if j1 + k < j2 else ""
                orig_class = "diff-removed" if i1 + k < i2 else "diff-unchanged"
                mod_class = "diff-added" if j1 + k < j2 else "diff-unchanged"
                orig_bg = "background: #fee2e2;" if i1 + k < i2 else "background: #f8fafc;"
                mod_bg = "background: #dcfce7;" if j1 + k < j2 else "background: #f8fafc;"
                html_parts.append(f'<tr><td class="diff-line {orig_class}" style="padding: 2px 8px; border-right: 1px solid #e2e8f0; {orig_bg}">{orig_line or "&nbsp;"}</td><td class="diff-line {mod_class}" style="padding: 2px 8px; {mod_bg}">{mod_line or "&nbsp;"}</td></tr>')
    
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

def generate_pdf_report(code: str, issues: list, scan_time: str) -> bytes:
    """Generate a PDF report using FPDF."""
    if not FPDF_AVAILABLE:
        return None
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    
    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "Secure Coding Assistant - Scan Report", ln=True, align="C")
    pdf.ln(5)
    
    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"Scan Time: {scan_time}", ln=True)
    pdf.cell(0, 6, f"Lines of Code: {len(code.splitlines())}", ln=True)
    pdf.cell(0, 6, f"Issues Found: {len(issues)}", ln=True)
    pdf.ln(5)
    
    # Source Code
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Source Code", ln=True)
    pdf.set_font("Courier", "", 8)
    for line in code.splitlines():
        pdf.cell(0, 4, line[:120], ln=True)
    pdf.ln(5)
    
    # Issues
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "Issues Detected", ln=True)
    pdf.ln(2)
    
    for i, issue in enumerate(issues, 1):
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, f"Issue #{i}: {issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}", ln=True)
        
        pdf.set_font("Helvetica", "", 9)
        pdf.cell(0, 5, f"  Line: {issue.get('line', 'N/A')}  |  Severity: {issue.get('severity', 'Low')}  |  Category: {issue.get('category', 'security')}", ln=True)
        pdf.cell(0, 5, f"  Confidence: {issue.get('confidence', 'N/A')}  |  CWE: {issue.get('cwe_reference', 'N/A')}", ln=True)
        
        if issue.get("snippet"):
            pdf.set_font("Courier", "", 8)
            for line in issue["snippet"].splitlines():
                pdf.cell(0, 4, f"  {line[:100]}", ln=True)
        
        if issue.get("message"):
            pdf.set_font("Helvetica", "I", 9)
            pdf.multi_cell(0, 5, f"  Detail: {issue['message']}")
        
        if issue.get("explanation"):
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, "  Explanation:", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.multi_cell(0, 5, f"  {issue['explanation']}")
        
        if issue.get("secure_rewrite"):
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(0, 5, "  Secure Rewrite:", ln=True)
            pdf.set_font("Courier", "", 8)
            for line in issue["secure_rewrite"].splitlines():
                pdf.cell(0, 4, f"  {line[:100]}", ln=True)
        
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
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        md_report = generate_markdown_report(
            st.session_state.scan_code,
            st.session_state.scan_result.get("issues", []),
            scan_time
        )
        download_button(md_report, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md", "📄 Download Markdown", "text/markdown")
        
        if FPDF_AVAILABLE:
            pdf_bytes = generate_pdf_report(
                st.session_state.scan_code,
                st.session_state.scan_result.get("issues", []),
                scan_time
            )
            if pdf_bytes:
                pdf_download_button(pdf_bytes, f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf", "📑 Download PDF")
        else:
            st.caption("💡 Install `fpdf2` for PDF export: `pip install fpdf2`")

# Initialize session state for uploaded code
if "uploaded_code" not in st.session_state:
    st.session_state.uploaded_code = ""

# Get code from session state (uploaded file takes priority)
code_input = st.session_state.uploaded_code

code_input = st.text_area(
    "Code Input",
    height=300,
    value=code_input,
    placeholder='# Paste your Python code here...\n\ndef get_user(name):\n    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n    ...',
)

uploaded_file = st.file_uploader("Or upload a .py file", type=["py"])

if uploaded_file:
    uploaded_content = uploaded_file.read().decode("utf-8")
    st.session_state.uploaded_code = uploaded_content
    st.rerun()

# Sync text_area changes back to session state for scan
st.session_state.uploaded_code = code_input

col1, col2, col3 = st.columns([1, 1, 1])
with col1:
    scan_clicked = st.button("🔍 Scan Code", type="primary", use_container_width=True)
with col2:
    if st.button("🗑️ Clear", use_container_width=True):
        st.session_state.uploaded_code = ""
        st.rerun()
with col3:
    if "scan_result" in st.session_state and st.button("🔄 Rescan", use_container_width=True):
        scan_clicked = True

if scan_clicked:
    if not st.session_state.uploaded_code.strip():
        st.warning("Please enter or upload some code to scan.")
    else:
        with st.spinner("Scanning code for vulnerabilities..."):
            try:
                response = requests.post(
                    f"{API_URL}/scan",
                    json={"code": st.session_state.uploaded_code},
                    timeout=60,
                )
                response.raise_for_status()
                result = response.json()
                
                st.session_state.scan_result = result
                st.session_state.scan_code = st.session_state.uploaded_code
                
                if not result["issues"]:
                    st.success("✅ No issues detected! Your code looks secure.")
                else:
                    st.warning(f"⚠️ Found {len(result['issues'])} issue(s)")
                
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
    code = st.session_state.get("scan_code", code_input)
    
    if issues:
        st.markdown("---")
        
        for idx, issue in enumerate(issues):
            severity = issue.get("severity", "Low")
            category = issue.get("category", "security")
            severity_config = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["Low"])
            category_config = CATEGORY_CONFIG.get(category, CATEGORY_CONFIG["security"])
            
            heading = (
                f"Line {issue.get('line', '?')} — "
                f"{issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}"
            )
            
            with st.expander(heading, expanded=(idx == 0)):
                # Header with badges
                st.markdown(
                    f"""
                    <div class="issue-header">
                        <span class="line-badge">Line {issue.get('line', '?')}</span>
                        <span class="vuln-type">{issue.get('vuln_type', 'Unknown').replace('_', ' ').title()}</span>
                        {render_category_badge(category)}
                        {render_severity_badge(severity)}
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                
                # Details row
                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Confidence", issue.get("confidence", "N/A"))
                col2.metric("Severity", severity)
                col3.metric("Category", category_config["label"])
                col4.metric("CWE", issue.get("cwe_reference", "N/A"))
                
                st.divider()
                
                # Vulnerable snippet
                st.markdown("#### 🔴 Vulnerable Code")
                snippet = issue.get("snippet", "")
                st.code(snippet, language="python")
                
                copy_col1, copy_col2 = st.columns([1, 5])
                with copy_col1:
                    if st.button("📋 Copy", key=f"copy_snippet_{idx}", help="Copy vulnerable snippet"):
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
                        if st.button("📋 Copy", key=f"copy_rewrite_{idx}", help="Copy secure rewrite"):
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