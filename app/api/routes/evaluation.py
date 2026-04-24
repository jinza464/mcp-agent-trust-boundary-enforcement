from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.responses import success_response
from app.api.routes.dependencies import get_evaluation_service
from app.api.schemas import (
    AblationReportRequest,
    EvaluationRunRequest,
    PlotAblationRequest,
)
from app.services.evaluation_service import EvaluationService

router = APIRouter(tags=["evaluation"])


@router.post("/evaluation/run")
def run_evaluation(
    request: EvaluationRunRequest,
    service: EvaluationService = Depends(get_evaluation_service),
) -> dict[str, object]:
    payload = service.run_local_evaluation(
        ablation_name=request.ablation_name,
        output_dir=request.output_dir,
        emit_failure_report=request.emit_failure_report,
    )
    artifacts = dict(payload.get("exported_paths", {}))
    return success_response(payload, artifacts=artifacts)


@router.post("/evaluation/ablation-report")
def export_ablation_report(
    request: AblationReportRequest,
    service: EvaluationService = Depends(get_evaluation_service),
) -> dict[str, object]:
    # Note: service-layer signature drift for ablation report export is handled in
    # phase-5 service alignment steps; route keeps dependency-injection only.
    payload = service.export_ablation_report(
        output_json=request.output_json,
        output_csv=request.output_csv,
    )
    return success_response(payload, artifacts=payload)


@router.post("/evaluation/plots")
def generate_plots(
    request: PlotAblationRequest,
    service: EvaluationService = Depends(get_evaluation_service),
) -> dict[str, object]:
    payload = service.plot_ablation(
        input_json=request.input_json,
        output_dir=request.output_dir,
    )
    return success_response(payload, artifacts=payload)
