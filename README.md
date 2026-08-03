# Secure Coding Assistant

An AI-powered tool that detects security vulnerabilities in Python code and provides educational explanations with secure rewrites. Think "Grammarly for insecure code."

## Quick Start

```bash
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

# Terminal 1 — Backend API
uvicorn backend.main:app --reload --port 8000

# Terminal 2 — Frontend UI
streamlit run frontend/app.py
```

Open `http://localhost:8501` in your browser.

## Architecture

```
Code Input → Syntactic Scan (AST + regex) → Vector Retrieval (ChromaDB)
  → LLM Synthesis (Gemini / Groq) → Report Rendering (Streamlit)
```

## Current Implementation

- **Detection Engine:** AST + regex rules for SQL injection, command injection, hardcoded secrets, XSS, syntax errors, and common logic mistakes
- **Backend:** FastAPI with `/scan`, `/scan-files`, and `/health` endpoints
- **Frontend:** Streamlit UI with code input (paste or upload single file / zip project), diff view, severity badges, and Markdown/PDF report export
- **Retrieval Layer:** Semantic retrieval over an OWASP/CWE knowledge base (ChromaDB + sentence-transformers)
- **LLM Synthesis:** LLM-generated explanations and secure rewrites (Gemini → Groq failover)
- **Dataset:** 300+ templated labeled samples with a benchmark harness (recall/precision per type)

## Project Structure

```
backend/               — FastAPI API server
  detection_engine/    — AST + regex scanning rules
frontend/              — Streamlit user interface
dataset/               — Labeled vulnerability samples + benchmark harness
retrieval_layer/       — Vector search over security docs (ChromaDB)
llm_synthesis/         — LLM explanation + patch generation (Gemini / Groq)
```

## Team

Built by a 10-person student team across 5 lanes: Detection Engine, Retrieval Layer, LLM/Prompting, Frontend/UX, and Dataset & Benchmarking.
