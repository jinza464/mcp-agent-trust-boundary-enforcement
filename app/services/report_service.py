from __future__ import annotations

from pathlib import Path

from app.config.settings import settings
from app.core.exceptions import ServiceError
from app.eval.failure_report import build_and_export_failure_report
from app.services.audit_service import AuditService


class ReportService:
    """Service layer for failure-analysis artifact generation."""

    def __init__(self, *, audit_service: AuditService | None = None) -> None:
        self.audit = audit_service if audit_service is not None else (AuditService() if settings.enable_audit_artifacts else None)

    def build_failure_report(
        self,
        *,
        case_results_path: str | Path,
        summary_path: str | Path,
        output_dir: str | Path | None = None,
    ) -> dict[str, str]:
        try:
            payload = build_and_export_failure_report(
                case_results_path=case_results_path,
                summary_path=summary_path,
                output_dir=output_dir,
            )
        except Exception as exc:  # pragma: no cover
            raise ServiceError(
                "Failure report generation failed.",
                details={
                    "case_results_path": str(case_results_path),
                    "summary_path": str(summary_path),
                },
            ) from exc
        exported_paths = payload.get("exported_paths", {})
        result = {k: str(v) for k, v in exported_paths.items()}
        if self.audit:
            result["audit_event"] = str(
                self.audit.write_event("failure_report_export", result)
            )
        return result
