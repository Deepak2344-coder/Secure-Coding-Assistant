from backend.schemas import ScanRequest, ScanResponse, Issue
from backend.detection_engine.rules import check_syntax_errors, check_logical_errors, check_all_vuln_types


def run_scan(request: ScanRequest) -> ScanResponse:
    code = request.code
    issues: list[Issue] = []

    syntax_issues = check_syntax_errors(code)
    if syntax_issues:
        return ScanResponse(issues=syntax_issues)

    issues.extend(check_all_vuln_types(code))
    issues.extend(check_logical_errors(code))
    issues.sort(key=lambda x: x.line)

    return ScanResponse(issues=issues)
