# LLM Synthesis Layer

**Lane 3 — Explanation & Secure Rewrite Generation**

## Current Status
🟢 Implemented — Gemini primary, Groq failover, structured output parsing.

## What Goes Here
- Prompt templates for each vulnerability type
- Gemini API integration (primary)
- Groq API integration (failover)
- Automatic failover logic on rate-limit / error
- Output parsing → structured `FixSuggestion` schema
- Confidence scoring

## Data Contract Input
Detection engine issue + retrieved OWASP/CWE text.

## Data Contract Output
```json
{
  "line": 14,
  "vuln_type": "command_injection",
  "severity": "High",
  "explanation": "This code runs a shell command...",
  "secure_rewrite": "subprocess.run([...])",
  "cwe_reference": "CWE-78"
}
```
