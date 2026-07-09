from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import ScanRequest, ScanResponse, IssueCategory
from backend.detection_engine.scanner import run_scan

app = FastAPI(title="Secure Coding Assistant API", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/scan", response_model=ScanResponse)
def scan_code(request: ScanRequest):
    result = run_scan(request)

    for issue in result.issues:
        if issue.category != IssueCategory.SECURITY:
            continue

        try:
            from retrieval_layer.retriever import retrieve

            retrieval = retrieve(issue.vuln_type.value, issue.snippet)
            if retrieval is None:
                continue

            issue.source_url = retrieval.source_url
            issue.cwe_reference = retrieval.cwe_reference

            from llm_synthesis.synthesizer import synthesize

            fix = synthesize(issue, retrieval)
            if fix is None:
                continue

            issue.explanation = fix.explanation
            issue.secure_rewrite = fix.secure_rewrite
            issue.cwe_reference = fix.cwe_reference
        except Exception:
            continue

    return result


@app.get("/health")
def health():
    return {"status": "ok"}
