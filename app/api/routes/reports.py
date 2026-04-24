from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.responses import success_response
from app.api.routes.dependencies import get_report_service
from app.api.schemas import FailureReportRequest
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["reports"])


@router.post("/failure")
def build_failure_report(
    request: FailureReportRequest,
    service: ReportService = Depends(get_report_service),
) -> dict[str, object]:
    payload = service.build_failure_report(
        case_results_path=request.case_results_path,
        summary_path=request.summary_path,
        output_dir=request.output_dir,
    )
    return success_response({"artifacts": payload}, artifacts=payload)
