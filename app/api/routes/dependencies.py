from __future__ import annotations

from collections.abc import Callable
from typing import TypeVar

from fastapi import Request

from app.services.evaluation_service import EvaluationService
from app.services.report_service import ReportService
from app.services.runtime_service import RuntimeService

ServiceT = TypeVar("ServiceT")


def _get_or_init_service(
    request: Request,
    *,
    state_key: str,
    factory: Callable[[], ServiceT],
) -> ServiceT:
    service = getattr(request.app.state, state_key, None)
    if service is None:
        service = factory()
        setattr(request.app.state, state_key, service)
    return service


def get_runtime_service(request: Request) -> RuntimeService:
    return _get_or_init_service(
        request,
        state_key="runtime_service",
        factory=RuntimeService,
    )


def get_evaluation_service(request: Request) -> EvaluationService:
    audit_service = getattr(request.app.state, "audit_service", None)
    return _get_or_init_service(
        request,
        state_key="evaluation_service",
        factory=lambda: EvaluationService(audit_service=audit_service),
    )


def get_report_service(request: Request) -> ReportService:
    audit_service = getattr(request.app.state, "audit_service", None)
    return _get_or_init_service(
        request,
        state_key="report_service",
        factory=lambda: ReportService(audit_service=audit_service),
    )
