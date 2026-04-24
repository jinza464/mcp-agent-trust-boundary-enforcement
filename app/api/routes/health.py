from __future__ import annotations

from fastapi import APIRouter

from app.api.responses import success_response
from app.api.schemas import HealthResponse
from app.config.settings import settings

router = APIRouter(tags=["health"])


@router.get("/health")
def health_check() -> dict[str, object]:
    payload = HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=settings.app_version,
        environment=settings.environment,
    )
    return success_response(payload.model_dump(mode="json"))
