from __future__ import annotations

from pathlib import Path

from app.config.settings import settings
from app.core.exceptions import ServiceError, ValidationError
from app.eval.ablation import run_ablation
from app.eval.ablation_report import build_and_export_ablation_report
from app.eval.plot_ablation import plot_ablation
from app.eval.run_local_eval import run_local_eval
from app.services.audit_service import AuditService


class EvaluationService:
    """Service facade for local evaluation, ablation reporting, and plotting."""

    def __init__(
        self,
        *,
        audit_service: AuditService | None = None,
        output_root: Path | None = None,
    ) -> None:
        self.audit = audit_service if audit_service is not None else (AuditService() if settings.enable_audit_artifacts else None)
        self.output_root = output_root or settings.default_output_root

    @staticmethod
    def _normalize_export_path(path_like: str | None, *, expected_suffix: str) -> Path | None:
        if path_like is None:
            return None
        path = Path(path_like)
        if path.suffix.lower() != expected_suffix:
            path = path.with_suffix(expected_suffix)
        return path

    def _resolve_ablation_report_target(
        self,
        *,
        output_json: str | None,
        output_csv: str | None,
    ) -> tuple[Path, str]:
        json_path = self._normalize_export_path(output_json, expected_suffix=".json")
        csv_path = self._normalize_export_path(output_csv, expected_suffix=".csv")

        if json_path is not None and csv_path is not None:
            if json_path.parent != csv_path.parent or json_path.stem != csv_path.stem:
                raise ValidationError(
                    "output_json and output_csv must share the same parent directory and base filename."
                )
            return json_path.parent, json_path.stem

        if json_path is not None:
            return json_path.parent, json_path.stem
        if csv_path is not None:
            return csv_path.parent, csv_path.stem
        return self.output_root, "ablation_summary_report"

    def run_local_evaluation(
        self,
        *,
        ablation_name: str = "baseline",
        output_dir: str | Path | None = None,
        emit_failure_report: bool = False,
    ) -> dict[str, object]:
        try:
            payload = run_local_eval(
                output_dir=output_dir,
                ablation_name=ablation_name,
                emit_failure_report=emit_failure_report,
            )
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        except Exception as exc:  # pragma: no cover - defensive platform boundary
            raise ServiceError("Local evaluation failed.", details={"ablation_name": ablation_name}) from exc

        exported_paths = dict(payload["exported_paths"])
        if emit_failure_report and "failure_report_paths" in payload:
            failure_outputs = payload["failure_report_paths"]
            exported_paths["failure_report_json"] = failure_outputs["json"]
            exported_paths["failure_report_markdown"] = failure_outputs["markdown"]

        if self.audit:
            audit_path = self.audit.write_event(
                "evaluation_run",
                {
                    "ablation_name": ablation_name,
                    "output_dir": str(output_dir) if output_dir is not None else None,
                    "emit_failure_report": emit_failure_report,
                },
            )
            exported_paths["audit_event"] = audit_path

        return {
            "ablation_name": payload["ablation_name"],
            "summary": payload["summary"].model_dump(mode="json"),
            "exported_paths": {k: str(v) for k, v in exported_paths.items()},
        }

    def run_ablation(
        self,
        *,
        config: dict | None = None,
    ) -> dict[str, object]:
        try:
            output = run_ablation(config=config)
        except Exception as exc:  # pragma: no cover - defensive platform boundary
            raise ServiceError("Ablation run failed.") from exc
        return {
            "config": output.config.model_dump(mode="json"),
            "summary": output.summary.model_dump(mode="json"),
            "case_results": [item.model_dump(mode="json") for item in output.case_results],
        }

    def export_ablation_report(
        self,
        *,
        output_json: str | None = None,
        output_csv: str | None = None,
        include_statistics: bool = False,
    ) -> dict[str, object]:
        try:
            output_dir, base_name = self._resolve_ablation_report_target(
                output_json=output_json,
                output_csv=output_csv,
            )
        except ValidationError:
            raise
        try:
            payload = build_and_export_ablation_report(
                output_dir=output_dir,
                base_name=base_name,
                include_statistics=include_statistics,
            )
            outputs = payload["exported_paths"]
        except Exception as exc:  # pragma: no cover
            raise ServiceError("Ablation report export failed.") from exc
        payload = {k: str(v) for k, v in outputs.items()}
        if self.audit:
            payload["audit_event"] = str(
                self.audit.write_event("ablation_report_export", payload)
            )
        return payload

    def plot_ablation(
        self,
        *,
        input_json: str = "data/eval_outputs/ablation_summary_report.json",
        output_dir: str = "data/eval_outputs/figures",
    ) -> dict[str, object]:
        try:
            outputs = plot_ablation(
                input_json=input_json,
                output_dir=output_dir,
            )
        except Exception as exc:  # pragma: no cover
            raise ServiceError(
                "Ablation plotting failed.",
                details={"input_json": input_json, "output_dir": output_dir},
            ) from exc
        payload = {k: str(v) for k, v in outputs.items()}
        if self.audit:
            payload["audit_event"] = str(
                self.audit.write_event("ablation_plot_export", payload)
            )
        return payload
