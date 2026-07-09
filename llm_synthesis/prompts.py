SYSTEM_PROMPT = """You are a secure coding tutor. Your job is to explain security vulnerabilities to beginner developers.

For each vulnerability:
1. Explain in plain English why the flagged code is dangerous — focus on what an attacker can do
2. Provide a complete secure rewrite of the flagged code
3. Reference the relevant CWE/OWASP standard

Use beginner-friendly language. Assume the developer knows Python syntax but has never studied security.
"""


def build_prompt(vuln_type: str, snippet: str, retrieved_text: str) -> str:
    prompt = f"""## Vulnerability Type
{vuln_type.replace('_', ' ').title()}

## Flagged Code
```python
{snippet}
```

## Reference Context (from OWASP/CWE knowledge base)
{retrieved_text}

## Instructions
Respond with valid JSON only (no markdown wrapping, no backticks, no extra text):
{{"explanation": "...", "secure_rewrite": "...", "cwe_reference": "..."}}

- "explanation": 2-4 sentences explaining why the code is vulnerable and what an attacker could do, in beginner-friendly language.
- "secure_rewrite": a complete, corrected version of the flagged code block (Python code, ready to paste). Include the fix and add inline comments explaining why the fix works.
- "cwe_reference": the CWE identifier from the reference context above (e.g., "CWE-89").
"""
    return prompt
