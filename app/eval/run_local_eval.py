"""Local one-command evaluation entrypoint for default attack cases."""

from __future__ import annotations

from pathlib import Path

from app.eval.attack_cases import default_attack_cases
from app.eval.metrics import export_results, summarize_results
from app.eval.runner import run_all_cases


DEFAULT_OUTPUT_DIR = Path("data/eval_outputs/latest")


def run_local_eval(output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> dict[str, object]:
    """Run default local evaluation loop and return summary/export metadata."""
    cases = default_attack_cases()
    results = run_all_cases(cases)
    summary = summarize_results(results)
    exported = export_results(results, output_dir)

    return {
        "summary": summary,
        "exported_paths": exported,
    }


def _print_summary(summary, exported_paths: dict[str, Path]) -> None:
    print("=== Local Evaluation Summary ===")
    print(f"total_cases: {summary.total_cases}")
    print(f"matched_cases: {summary.matched_cases}")
    print(f"match_rate: {summary.match_rate:.4f}")
    print(f"risk_level_distribution: {summary.risk_level_distribution}")
    print(f"decision_action_distribution: {summary.decision_action_distribution}")
    print(f"case_results_file: {exported_paths['cases']}")
    print(f"summary_file: {exported_paths['summary']}")


def main() -> None:
    """CLI entrypoint for `python -m app.eval.run_local_eval`."""
    payload = run_local_eval()
    _print_summary(payload["summary"], payload["exported_paths"])


if __name__ == "__main__":
    main()
