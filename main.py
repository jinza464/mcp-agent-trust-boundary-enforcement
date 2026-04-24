from __future__ import annotations

import inspect
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.responses import error_response
from app.api.routes.evaluation import router as evaluation_router
from app.api.routes.health import router as health_router
from app.api.routes.reports import router as reports_router
from app.api.routes.runtime import router as runtime_router
from app.api.routes.tools import router as tools_router
from app.config.settings import settings
from app.core.exceptions import PlatformError
from app.services.audit_service import AuditService
from app.services.evaluation_service import EvaluationService
from app.services.report_service import ReportService
from app.services.runtime_service import RuntimeService


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # Startup: initialize shared platform services/resources once per app lifecycle.
        audit_service = AuditService()
        runtime_service = RuntimeService()
        evaluation_service = EvaluationService(
            audit_service=audit_service,
            output_root=settings.default_output_root,
        )
        report_service = ReportService(audit_service=audit_service)

        app.state.audit_service = audit_service
        app.state.runtime_service = runtime_service
        app.state.evaluation_service = evaluation_service
        app.state.report_service = report_service

        # Lightweight placeholders for upcoming shared resources in phase-5+.
        app.state.shared_tool_registry = getattr(getattr(runtime_service, "client", None), "registry", None)
        app.state.case_pack_cache = {}
        app.state.runtime_policy_kernel = None
        try:
            yield
        finally:
            # Prefer close() so buffered events flush exactly once and writer transitions to closed state.
            close_method = getattr(audit_service, "close", None)
            flush_method = getattr(audit_service, "flush", None)
            chosen = close_method if callable(close_method) else flush_method
            if callable(chosen):
                maybe_awaitable = chosen()
                if inspect.isawaitable(maybe_awaitable):
                    await maybe_awaitable

            app.state.runtime_service = None
            app.state.evaluation_service = None
            app.state.report_service = None
            app.state.audit_service = None
            app.state.shared_tool_registry = None
            app.state.case_pack_cache = None
            app.state.runtime_policy_kernel = None

    app = FastAPI(
        title="Client-side Trust Boundary Enforcement Platform",
        description=(
            "Platform-style FastAPI service for trust-boundary enforcement, runtime inspection, "
            "evaluation, and report generation."
        ),
        version=settings.app_version,
        lifespan=lifespan,
    )

    @app.exception_handler(PlatformError)
    async def handle_platform_error(_: Request, exc: PlatformError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response(
                code=exc.code,
                message=exc.message,
                details=exc.details,
            ),
        )

    @app.exception_handler(RequestValidationError)
    async def handle_request_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=error_response(
                code="request_validation_error",
                message="Request validation failed.",
                details={"errors": exc.errors()},
            ),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=500,
            content=error_response(
                code="internal_error",
                message="Unexpected internal platform error.",
                details={"exception_type": type(exc).__name__},
            ),
        )

    app.include_router(health_router)
    app.include_router(tools_router, prefix=settings.api_prefix)
    app.include_router(runtime_router, prefix=settings.api_prefix)
    app.include_router(evaluation_router, prefix=settings.api_prefix)
    app.include_router(reports_router, prefix=settings.api_prefix)
    return app


app = create_app()
