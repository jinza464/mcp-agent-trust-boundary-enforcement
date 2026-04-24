"""Local one-command evaluation entrypoint for default attack cases."""

from __future__ import annotations

import argparse
from pathlib import Path

from app.eval.attack_cases import default_attack_cases
from app.eval.metrics import export_results, resolve_case_semantics, summarize_results
from app.eval.failure_report import build_and_export_failure_report
from app.eval.runner import AblationConfig, run_all_cases


DEFAULT_OUTPUT_ROOT = Path("data/eval_outputs")
DEFAULT_ABLATION_NAME = "baseline"
RUNTIME_SEMANTICS_VERSION = "v1"
AblationName = str
ABLATION_PRESETS: dict[AblationName, AblationConfig] = {
    "baseline": AblationConfig(),
    "no_trust_tagging": AblationConfig(disable_trust_tagging=True),
    "no_metadata_validation": AblationConfig(disable_metadata_validation=True),
    "no_sink_guard": AblationConfig(disable_sink_guard=True),
}


def _runtime_semantics_snapshot(results) -> dict[str, int | float | str]:
    total = len(results)
    semantics = [resolve_case_semantics(item) for item in results]
    completed_count = sum(1 for item in semantics if item.completed_execution)
    intervention_count = sum(1 for item in semantics if item.intervention_triggered)
    hard_block_count = sum(1 for item in semantics if item.hard_blocked)
    confirmation_count = sum(1 for item in semantics if item.confirmation_required)
    escalation_count = sum(1 for item in semantics if item.escalation_triggered)
    return {
        "semantics_version": RUNTIME_SEMANTICS_VERSION,
        "semantics_source": "metrics.resolve_case_semantics",
        "total_cases": total,
        "completed_execution_count": completed_count,
        "intervention_count": intervention_count,
        "hard_block_count": hard_block_count,
        "confirmation_count": confirmation_count,
        "escalation_count": escalation_count,
        "completed_execution_rate": (completed_count / total) if total else 0.0,
        "intervention_rate": (intervention_count / total) if total else 0.0,
    }


def run_local_eval(
    output_dir: str | Path | None = None,
    *,
    ablation_name: AblationName = DEFAULT_ABLATION_NAME,
    ablation_config: AblationConfig | dict | None = None,
    emit_failure_report: bool = False,
) -> dict[str, object]:
    """Run default local evaluation loop and return summary/export metadata."""
    if ablation_name not in ABLATION_PRESETS:
        valid = ", ".join(sorted(ABLATION_PRESETS))
        raise ValueError(f"Unknown ablation_name '{ablation_name}'. Valid values: {valid}")

    cfg = (
        ablation_config
        if isinstance(ablation_config, AblationConfig)
        else AblationConfig.model_validate(ablation_config or ABLATION_PRESETS[ablation_name].model_dump())
    )
    out_dir = Path(output_dir) if output_dir is not None else DEFAULT_OUTPUT_ROOT / ablation_name

    cases = default_attack_cases()
    results = run_all_cases(cases, ablation_config=cfg)
    summary = summarize_results(results)
    exported = export_results(results, out_dir)
    failure_report_paths: dict[str, Path] | None = None
    if emit_failure_report:
        failure_report_paths = build_and_export_failure_report(
            case_results_path=exported["cases"],
            summary_path=exported["summary"],
            output_dir=out_dir,
        )

    payload = {
        "ablation_name": ablation_name,
        "ablation_config": cfg,
        "summary": summary,
        "exported_paths": exported,
        "runtime_semantics_snapshot": _runtime_semantics_snapshot(results),
    }
    if failure_report_paths is not None:
        payload["failure_report_paths"] = failure_report_paths
    return payload


def _print_summary(ablation_name: str, summary, exported_paths: dict[str, Path]) -> None:
    print("=== Local Evaluation Summary ===")
    print(f"ablation: {ablation_name}")
    print(f"total_cases: {summary.total_cases}")
    print(f"matched_cases: {summary.matched_cases}")
    print(f"match_rate: {summary.match_rate:.4f}")
    print(f"risk_level_distribution: {summary.risk_level_distribution}")
    print(f"decision_action_distribution: {summary.decision_action_distribution}")
    print(f"case_results_file: {exported_paths['cases']}")
    print(f"summary_file: {exported_paths['summary']}")


def main() -> None:
    """CLI entrypoint for `python -m app.eval.run_local_eval`."""
    parser = argparse.ArgumentParser(description="Run local evaluation with optional ablation switches.")
    parser.add_argument(
        "--ablation",
        default=DEFAULT_ABLATION_NAME,
        choices=sorted(ABLATION_PRESETS.keys()),
        help="Ablation preset name.",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Custom output directory. Default: data/eval_outputs/<ablation>",
    )
    parser.add_argument(
        "--emit-failure-report",
        action="store_true",
        help="Also export failure_report.json and failure_report.md for the selected run.",
    )
    args = parser.parse_args()

    payload = run_local_eval(
        output_dir=args.output_dir,
        ablation_name=args.ablation,
        emit_failure_report=args.emit_failure_report,
    )
    _print_summary(payload["ablation_name"], payload["summary"], payload["exported_paths"])


if __name__ == "__main__":
    main()
