from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.responses import success_response
from app.api.routes.dependencies import get_runtime_service
from app.api.schemas import RuntimeExecuteRequest
from app.services.runtime_service import RuntimeService

router = APIRouter(tags=["runtime"])


@router.post("/runtime/execute")
def execute_runtime(
    request: RuntimeExecuteRequest,
    service: RuntimeService = Depends(get_runtime_service),
) -> dict[str, object]:
    source_metadata = request.source_metadata.to_runtime_dict()
    sink_metadata = request.sink_metadata.to_runtime_dict()
    sink_payload = request.sink_payload.to_runtime_payload() if request.sink_payload else None
    result = service.handle_query(
        user_query=request.user_query,
        preferred_tool_name=request.preferred_tool_name,
        source_type=request.source_type,
        source_content=request.source_content,
        source_metadata=source_metadata,
        user_authorized=request.user_authorized,
        sink_payload=sink_payload,
        sink_metadata=sink_metadata,
    )

    payload = {
        "user_query": result.user_query,
        "final_status": result.final_status,
        "decision_action": result.decision_result.action.value,
        "decision_risk": result.decision_result.risk_level.value,
        "requires_user_confirmation": result.decision_result.requires_user_confirmation,
        "sink_action": result.sink_result.action.value if result.sink_result else None,
        "selected_tool": (
            {
                "tool_id": result.selected_tool.tool_id,
                "name": result.selected_tool.name,
                "version": result.selected_tool.version,
                "source_uri": result.selected_tool.source_uri,
            }
            if result.selected_tool
            else None
        ),
        "execution_started": result.execution_started,
        "execution_completed": result.execution_completed,
        "entered_execution_stage": result.entered_execution_stage,
        "completed_execution": result.completed_execution,
        "execution_degraded": result.execution_degraded,
        "output_restricted": result.output_restricted,
        "output_degraded": result.output_degraded,
        "output_replaced": result.output_replaced,
        "decision_result": result.decision_result.model_dump(mode="json"),
        "sink_result": result.sink_result.model_dump(mode="json") if result.sink_result else None,
        "final_execution_outcome": (
            result.final_execution_outcome.model_dump(mode="json")
            if result.final_execution_outcome
            else None
        ),
    }
    return success_response(payload)
