from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.schemas import ScanRequest, ScanResponse
from backend.detection_engine.scanner import run_scan

app = FastAPI(title="Secure Coding Assistant API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.post("/scan", response_model=ScanResponse)
def scan_code(request: ScanRequest):
    return run_scan(request)


@app.get("/health")
def health():
    return {"status": "ok"}
