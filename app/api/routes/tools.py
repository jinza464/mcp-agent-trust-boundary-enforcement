from __future__ import annotations

from fastapi import APIRouter, Depends

from app.api.responses import success_response
from app.api.routes.dependencies import get_runtime_service
from app.services.runtime_service import RuntimeService

router = APIRouter(tags=["tools"])


@router.get("/tools")
def list_tools(
    service: RuntimeService = Depends(get_runtime_service),
) -> dict[str, object]:
    tools = service.list_tools()
    return success_response(
        {
            "items": tools,
            "total_tools": len(tools),
        }
    )
