from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import ScanRequest, ScanResponse, Issue, IssueCategory
from backend.detection_engine.scanner import run_scan


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        from retrieval_layer.embedder import _get_model, _get_collection
        _get_model()
        _get_collection()
    except Exception:
        pass
    yield


app = FastAPI(title="Secure Coding Assistant API", version="0.3.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def _enrich_with_llm(issue: Issue) -> None:
    """Fetch retrieval context and LLM explanation for a security issue."""
    if issue.category != IssueCategory.SECURITY:
        return

    try:
        from retrieval_layer.retriever import retrieve

        retrieval = retrieve(issue.vuln_type.value, issue.snippet)
        if retrieval is None:
            return

        issue.source_url = retrieval.source_url
        issue.cwe_reference = retrieval.cwe_reference

        from llm_synthesis.synthesizer import synthesize

        fix = synthesize(issue, retrieval)
        if fix is None:
            return

        issue.explanation = fix.explanation
        issue.secure_rewrite = fix.secure_rewrite
        issue.cwe_reference = fix.cwe_reference
    except Exception:
        pass


@app.post("/scan", response_model=ScanResponse)
def scan_code(request: ScanRequest):
    result = run_scan(request)

    for issue in result.issues:
        _enrich_with_llm(issue)

    return result


@app.post("/scan-files", response_model=ScanResponse)
def scan_files(request: ScanRequest):
    if not request.files:
        return ScanResponse(issues=[])

    all_issues: list[Issue] = []
    for file_path, code in request.files.items():
        file_request = ScanRequest(code=code)
        result = run_scan(file_request)
        for issue in result.issues:
            issue.file_path = file_path
            _enrich_with_llm(issue)
        all_issues.extend(result.issues)

    all_issues.sort(key=lambda x: (x.file_path, x.line))
    return ScanResponse(issues=all_issues)


@app.get("/health")
def health():
    return {"status": "ok"}
