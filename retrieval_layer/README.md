# Retrieval Layer

**Lane 2 — Semantic Search over Security Knowledge Base**

## Current Status
🟡 Placeholder — implementation starts in Weeks 3–4.

## What Goes Here
- OWASP / CWE source document curation
- Chunking strategy for reference texts
- Embedding pipeline using `sentence-transformers` (`all-MiniLM-L6-v2`)
- ChromaDB setup and indexing
- Query embedding + cosine-similarity retrieval

## Data Contract Input
The detection engine output (`Issue` objects with line, vuln_type, snippet).

## Data Contract Output
```json
{
  "line": 14,
  "vuln_type": "command_injection",
  "snippet": "os.system(user_input)",
  "retrieved_text": "CWE-78: Improper Neutralization...",
  "cwe_reference": "CWE-78",
  "source_url": "https://cwe.mitre.org/data/definitions/78.html"
}
```

## Dependencies (to add later)
- `sentence-transformers`
- `chromadb`
