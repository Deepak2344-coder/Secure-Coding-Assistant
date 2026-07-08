from backend.schemas import ScanRequest, ScanResponse, Issue
from backend.detection_engine.rules import check_all_vuln_types


def run_scan(request: ScanRequest) -> ScanResponse:
    issues: list[Issue] = check_all_vuln_types(request.code)
    return ScanResponse(issues=issues)
