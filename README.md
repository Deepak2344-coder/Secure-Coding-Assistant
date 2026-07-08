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

## v0 — Skeletal Model

Current implementation (Weeks 1–2):
- **Detection Engine:** AST + regex rules for SQL injection, command injection, hardcoded secrets, and XSS
- **Backend:** FastAPI with `/scan` and `/health` endpoints
- **Frontend:** Streamlit UI with code input (paste or upload) and results display
- **Dataset:** 20 labeled samples (5 per vulnerability type)

Coming in Weeks 3–4:
- Semantic retrieval over OWASP/CWE knowledge base (ChromaDB + sentence-transformers)
- LLM-generated explanations and secure rewrites (Gemini → Groq failover)
- Enhanced UI with diff view and severity badges

## Project Structure

```
backend/               — FastAPI API server
  detection_engine/    — AST + regex scanning rules
frontend/              — Streamlit user interface
dataset/               — Labeled vulnerability samples
retrieval_layer/       — (WIP) Vector search over security docs
llm_synthesis/         — (WIP) LLM explanation + patch generation
```

## Team

Built by a 10-person student team across 5 lanes: Detection Engine, Retrieval Layer, LLM/Prompting, Frontend/UX, and Dataset & Benchmarking.
