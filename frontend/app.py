import streamlit as st
import requests

API_URL = "http://localhost:8000"

st.set_page_config(
    page_title="Secure Coding Assistant",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ Secure Coding Assistant")
st.markdown("Paste your Python code below to scan for common security vulnerabilities.")

code_input = st.text_area(
    "Code Input",
    height=300,
    placeholder='# Paste your Python code here...\n\ndef get_user(name):\n    query = "SELECT * FROM users WHERE name = \'" + name + "\'"\n    ...',
)

uploaded_file = st.file_uploader("Or upload a .py file", type=["py"])

if uploaded_file:
    code_input = uploaded_file.read().decode("utf-8")

if st.button("Scan Code", type="primary"):
    if not code_input.strip():
        st.warning("Please enter or upload some code to scan.")
    else:
        with st.spinner("Scanning for vulnerabilities..."):
            try:
                response = requests.post(
                    f"{API_URL}/scan",
                    json={"code": code_input},
                    timeout=30,
                )
                response.raise_for_status()
                result = response.json()

                if not result["issues"]:
                    st.success("No vulnerabilities detected!")
                else:
                    st.error(f"Found {len(result['issues'])} potential issue(s):")

                    for issue in result["issues"]:
                        severity = issue["severity"]
                        if severity == "High":
                            badge = "🔴 High"
                        elif severity == "Medium":
                            badge = "🟡 Medium"
                        else:
                            badge = "🟢 Low"

                        with st.expander(
                            f"Line {issue['line']} — {issue['vuln_type'].replace('_', ' ').title()} [{badge}]",
                            expanded=True,
                        ):
                            col1, col2 = st.columns([1, 3])
                            with col1:
                                st.markdown("**Line:**")
                                st.markdown("**Type:**")
                                st.markdown("**Confidence:**")
                                st.markdown("**Severity:**")
                                st.markdown("**Snippet:**")
                            with col2:
                                st.markdown(f"`{issue['line']}`")
                                st.markdown(f"`{issue['vuln_type']}`")
                                st.markdown(f"`{issue['confidence']}`")
                                st.markdown(f"`{issue['severity']}`")
                                st.code(issue["snippet"], language="python")

            except requests.exceptions.ConnectionError:
                st.error(
                    "Cannot connect to the backend. Make sure the FastAPI server is running on port 8000."
                )
            except Exception as e:
                st.error(f"An error occurred: {e}")

st.divider()
st.markdown(
    "**Note:** This is a syntactic scanner (v0). "
    "Semantic retrieval and LLM-based explanations coming in future releases."
)
