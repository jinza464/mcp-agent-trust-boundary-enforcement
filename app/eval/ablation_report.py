"""Ablation summary aggregator for paper-ready table exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path


DEFAULT_SUMMARY_PATHS: dict[str, Path] = {
    "baseline": Path("data/eval_outputs/baseline/eval_summary.json"),
    "no_trust_tagging": Path("data/eval_outputs/no_trust_tagging/eval_summary.json"),
    "no_metadata_validation": Path("data/eval_outputs/no_metadata_validation/eval_summary.json"),
    "no_sink_guard": Path("data/eval_outputs/no_sink_guard/eval_summary.json"),
}

REPORT_COLUMNS: list[str] = [
    "configuration",
    "disabled_modules",
    "affected_cases_count",
    "affected_cases_ratio",
    "match_rate",
    "delta_match_rate",
    "attack_success_rate",
    "delta_attack_success_rate",
    "leak_rate",
    "delta_leak_rate",
    "false_positive_rate",
    "delta_false_positive_rate",
    "utility_loss",
    "delta_utility_loss",
    "escalation_rate",
    "delta_escalation_rate",
    "explanation",
]


METRIC_KEYS: list[str] = [
    "match_rate",
    "attack_success_rate",
    "leak_rate",
    "false_positive_rate",
    "utility_loss",
    "escalation_rate",
]


def _infer_disabled_modules(config_name: str) -> list[str]:
    mapping = {
        "baseline": [],
        "no_trust_tagging": ["trust_tagging"],
        "no_metadata_validation": ["metadata_validation"],
        "no_sink_guard": ["sink_guard"],
    }
    return mapping.get(config_name, [])


def _derive_case_results_path(summary_path: Path) -> Path:
    return summary_path.parent / "eval_case_results.json"


def _affected_case_count(case_results_path: Path) -> tuple[int, int]:
    if not case_results_path.exists():
        return 0, 0
    payload = json.loads(case_results_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return 0, 0

    total = len(payload)
    affected = 0
    for item in payload:
        if bool(item.get("affected_by_ablation")):
            affected += 1
            continue
        findings = [str(x) for x in item.get("findings", [])]
        if any(text.startswith("ablation:disable_") for text in findings):
            affected += 1
    return affected, total


def _build_explanation(
    config_name: str,
    disabled_modules: list[str],
    row: dict[str, float | str],
) -> str:
    if config_name == "baseline":
        return "Baseline reference with all trust-boundary modules enabled."

    parts: list[str] = []
    if disabled_modules:
        parts.append(f"Disabled module(s): {', '.join(disabled_modules)}.")

    if float(row.get("delta_attack_success_rate", 0.0)) > 0:
        parts.append("Attack success increased versus baseline, indicating weaker interception.")
    if float(row.get("delta_leak_rate", 0.0)) > 0:
        parts.append("Leak rate increased versus baseline, indicating weaker sink-side containment.")
    if float(row.get("delta_false_positive_rate", 0.0)) < 0:
        parts.append("False positives decreased, suggesting lower intervention aggressiveness.")
    if float(row.get("delta_utility_loss", 0.0)) < 0:
        parts.append("Utility loss decreased, suggesting smoother benign execution.")
    if float(row.get("delta_match_rate", 0.0)) < 0:
        parts.append("Overall expectation match fell relative to baseline.")

    return " ".join(parts) if parts else "No material metric shift observed relative to baseline."


def load_ablation_summaries(
    summary_paths: dict[str, str | Path] | None = None,
) -> list[dict[str, float | str]]:
    """Load summary JSONs and normalize into one table-like record list."""
    selected = summary_paths or DEFAULT_SUMMARY_PATHS
    rows: list[dict[str, float | str]] = []
    for config_name, path_like in selected.items():
        path = Path(path_like)
        if not path.exists():
            raise FileNotFoundError(f"Summary file not found for '{config_name}': {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        affected_cases_count, total_cases = _affected_case_count(_derive_case_results_path(path))
        affected_cases_ratio = (affected_cases_count / total_cases) if total_cases else 0.0
        disabled_modules = _infer_disabled_modules(config_name)
        row = {
            "configuration": config_name,
            "disabled_modules": ",".join(disabled_modules) if disabled_modules else "none",
            "affected_cases_count": affected_cases_count,
            "affected_cases_ratio": float(affected_cases_ratio),
            "match_rate": float(payload.get("match_rate", 0.0)),
            "attack_success_rate": float(payload.get("attack_success_rate", 0.0)),
            "leak_rate": float(payload.get("leak_rate", 0.0)),
            "false_positive_rate": float(payload.get("false_positive_rate", 0.0)),
            "utility_loss": float(payload.get("utility_loss", 0.0)),
            "escalation_rate": float(payload.get("escalation_rate", 0.0)),
        }
        rows.append(row)

    by_config = {str(item["configuration"]): item for item in rows}
    baseline = by_config.get("baseline", {})
    for row in rows:
        for metric in METRIC_KEYS:
            baseline_value = float(baseline.get(metric, 0.0))
            value = float(row.get(metric, 0.0))
            row[f"delta_{metric}"] = value - baseline_value
        row["explanation"] = _build_explanation(
            config_name=str(row.get("configuration", "")),
            disabled_modules=[
                item for item in str(row.get("disabled_modules", "")).split(",") if item and item != "none"
            ],
            row=row,
        )
    return rows


def export_ablation_report(
    rows: list[dict[str, float | str]],
    output_dir: str | Path = "data/eval_outputs",
    base_name: str = "ablation_summary_report",
) -> dict[str, Path]:
    """Export ablation report rows into JSON and CSV files."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{base_name}.json"
    csv_path = out_dir / f"{base_name}.csv"

    json_path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=REPORT_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    return {"json": json_path, "csv": csv_path}


def build_and_export_ablation_report(
    summary_paths: dict[str, str | Path] | None = None,
    output_dir: str | Path = "data/eval_outputs",
    base_name: str = "ablation_summary_report",
) -> dict[str, object]:
    """Load default ablation summaries and export a unified report."""
    rows = load_ablation_summaries(summary_paths=summary_paths)
    exported = export_ablation_report(rows, output_dir=output_dir, base_name=base_name)
    return {"rows": rows, "exported_paths": exported}


def main() -> None:
    payload = build_and_export_ablation_report()
    print(f"rows: {len(payload['rows'])}")
    print(f"json: {payload['exported_paths']['json']}")
    print(f"csv: {payload['exported_paths']['csv']}")


if __name__ == "__main__":
    main()
