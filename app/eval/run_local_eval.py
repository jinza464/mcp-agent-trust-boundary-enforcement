"""Local one-command evaluation entrypoint for default attack cases."""

from __future__ import annotations

import argparse
from pathlib import Path

from app.eval.attack_cases import default_attack_cases
from app.eval.metrics import export_results, summarize_results
from app.eval.runner import AblationConfig, run_all_cases


DEFAULT_OUTPUT_ROOT = Path("data/eval_outputs")
DEFAULT_ABLATION_NAME = "baseline"
AblationName = str
ABLATION_PRESETS: dict[AblationName, AblationConfig] = {
    "baseline": AblationConfig(),
    "no_trust_tagging": AblationConfig(disable_trust_tagging=True),
    "no_metadata_validation": AblationConfig(disable_metadata_validation=True),
    "no_sink_guard": AblationConfig(disable_sink_guard=True),
}


def run_local_eval(
    output_dir: str | Path | None = None,
    *,
    ablation_name: AblationName = DEFAULT_ABLATION_NAME,
    ablation_config: AblationConfig | dict | None = None,
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

    return {
        "ablation_name": ablation_name,
        "ablation_config": cfg,
        "summary": summary,
        "exported_paths": exported,
    }


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
    args = parser.parse_args()

    payload = run_local_eval(output_dir=args.output_dir, ablation_name=args.ablation)
    _print_summary(payload["ablation_name"], payload["summary"], payload["exported_paths"])


if __name__ == "__main__":
    main()
