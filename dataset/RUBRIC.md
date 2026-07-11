# Dataset Labeling Rubric

This rubric defines how samples in `samples.json` are labeled so contributors
produce consistent, unambiguous benchmarks for the Secure Coding Assistant.

## Scope
Target vulnerability classes (v1, Python only):
1. `sql_injection` — string-concatenated / f-string / `.format()` / `%` built SQL
2. `command_injection` — `os.system`, `os.popen`, `subprocess` with `shell=True`
3. `hardcoded_secret` — API keys, passwords, tokens embedded directly in source
4. `xss` — unescaped user input rendered in HTML / Jinja2 templates

## Sample schema
```json
{
  "id": "sqli_v_001",
  "vuln_type": "sql_injection",
  "label": "vulnerable" | "secure",
  "expected_vuln_type": "sql_injection" | null,
  "code": "<valid python source>",
  "notes": "short explanation"
}
```

## Label rules
- **`label: "vulnerable"`** — the snippet contains a real instance of the
  `vuln_type`. `expected_vuln_type` MUST equal `vuln_type`.
- **`label: "secure"`** — the snippet is the corrected/patched version of a
  vulnerable pattern (parameterized query, `subprocess` list-args without
  shell, secret from env/secret-manager, Jinja2 autoescape / `escape()`).
  `expected_vuln_type` MUST be `null`. The detector is expected to return
  **no** security issue of that type (used to measure precision).

## Validity requirements
- `code` MUST be syntactically valid Python (the scanner early-returns on
  `SyntaxError` and skips vuln detection, which would invalidate metrics).
- Each snippet should be self-contained enough to scan in isolation. Imports
  used by the snippet are included.
- A sample is counted as a **true positive** if the detector returns at least
  one issue whose `vuln_type` matches `expected_vuln_type`.
- A `secure` sample is a **true negative** if the detector returns no security
  issue of that type; otherwise it is a **false positive**.

## Generation guidance
- Prefer varied, realistic constructions (multiple DB libraries, naming, styles)
  over near-duplicate snippets.
- Keep templated generation deterministic and reproducible (no random sampling
  without a fixed seed).
- LLM-augmented samples are allowed but MUST be reviewed and kept separate so
  the core templated set remains reproducible.
