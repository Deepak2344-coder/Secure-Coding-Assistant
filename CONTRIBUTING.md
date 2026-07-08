# Contributing to Secure Coding Assistant

## Team Structure (5 Lanes × 2 People)

| Lane | Focus | Directory |
|---|---|---|
| **1. Detection Engine** | AST/regex rules, expanding pattern coverage | `backend/detection_engine/` |
| **2. Retrieval Layer** | OWASP/CWE corpus, embedding, ChromaDB | `retrieval_layer/` |
| **3. LLM/Prompting** | Prompt templates, Gemini/Groq, failover | `llm_synthesis/` |
| **4. Frontend/UX** | Streamlit UI, diff view, severity badges | `frontend/` |
| **5. Dataset & Benchmark** | 300+ samples, accuracy tests, technical report | `dataset/` |

## The Golden Rule

**The data contract (`backend/schemas.py`) is sacred.** Every lane builds against it. Any change to the schemas requires a whole-team discussion.

## Getting Started

```bash
# Clone the repo
git clone https://github.com/Deepak2344-coder/Secure-Coding-Assistant.git
cd Secure-Coding-Assistant

# Create virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Start the backend (terminal 1)
uvicorn backend.main:app --reload --port 8000

# Start the frontend (terminal 2)
streamlit run frontend/app.py
```

## Git Workflow

1. Create a branch from `main` for your work:
   ```
   git checkout -b lane-1/improve-sql-detection
   ```
2. Make changes in your lane's directory.
3. Commit with a clear message:
   ```
   git commit -m "detection: add parameterized query pattern to SQL rules"
   ```
4. Push and open a Pull Request:
   ```
   git push origin lane-1/improve-sql-detection
   ```

## Adding a New Detection Rule

1. Open `backend/detection_engine/rules.py`
2. Write a `_check_<vuln_type>()` function returning `list[Issue]`
3. Register it in `check_all_vuln_types()` at the bottom of the file
4. Add 2–3 test samples to `dataset/samples_v0.json`

## Code Style

- No type annotations required for internal variables
- Functions return `list[Issue]` — never print or log results
- Keep rules focused: one pattern per helper function if possible
