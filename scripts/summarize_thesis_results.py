"""Build paper-ready thesis experiment summary tables from exported summaries.

The script reads existing ``eval_summary.json`` artifacts. It does not rerun
evaluation and does not recalculate metrics from case-level results.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_OUTPUT_ROOT = REPO_ROOT / "results" / "thesis_experiment_v1_final"
CONFIGURATIONS: tuple[str, ...] = (
    "baseline",
    "no_trust_tagging",
    "no_metadata_validation",
    "no_sink_guard",
)
METRIC_COLUMNS: tuple[str, ...] = (
    "match_rate",
    "attack_success_rate",
    "leak_rate",
    "false_positive_rate",
    "utility_loss",
    "execution_completion_rate",
    "intervention_rate",
    "hard_block_rate",
    "confirmation_rate",
)
TABLE_COLUMNS: tuple[str, ...] = ("configuration", *METRIC_COLUMNS)


def _load_summary(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    warnings: list[str] = []
    if not path.exists():
        return None, [f"Missing summary file: {path}"]
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return None, [f"Invalid JSON in {path}: {exc}"]
    if not isinstance(payload, dict):
        return None, [f"Summary is not a JSON object: {path}"]
    return payload, warnings


def _format_metric(value: object) -> str:
    if value is None:
        return "MISSING"
    if isinstance(value, int | float):
        return f"{float(value):.4f}"
    return str(value)


def _read_rows(output_root: Path) -> tuple[list[dict[str, str]], dict[str, dict[str, Any]], list[str]]:
    rows: list[dict[str, str]] = []
    summaries: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    for configuration in CONFIGURATIONS:
        summary_path = output_root / configuration / "eval_summary.json"
        summary, load_warnings = _load_summary(summary_path)
        warnings.extend(load_warnings)
        row: dict[str, str] = {"configuration": configuration}
        if summary is None:
            for metric in METRIC_COLUMNS:
                row[metric] = "MISSING"
            rows.append(row)
            continue

        summaries[configuration] = summary
        for metric in METRIC_COLUMNS:
            if metric not in summary:
                warnings.append(f"Missing metric '{metric}' in {summary_path}")
                row[metric] = "MISSING"
            else:
                row[metric] = _format_metric(summary[metric])
        rows.append(row)
    return rows, summaries, warnings


def _markdown_table(rows: list[dict[str, str]], columns: tuple[str, ...] = TABLE_COLUMNS) -> str:
    lines = [
        "| " + " | ".join(columns) + " |",
        "| " + " | ".join("---" for _ in columns) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row.get(column, "MISSING") for column in columns) + " |")
    return "\n".join(lines) + "\n"


def _delta_cell(candidate: dict[str, Any], baseline: dict[str, Any], metric: str) -> str:
    if metric not in candidate or metric not in baseline:
        return "MISSING"
    candidate_value = candidate[metric]
    baseline_value = baseline[metric]
    if not isinstance(candidate_value, int | float) or not isinstance(baseline_value, int | float):
        return "MISSING"
    return f"{float(candidate_value) - float(baseline_value):+.4f}"


def _build_ablation_comparison(summaries: dict[str, dict[str, Any]], warnings: list[str]) -> str:
    lines = [
        "# Ablation Comparison",
        "",
        "Baseline-relative deltas are computed from existing `eval_summary.json` fields only.",
        "No case-level metrics are recomputed in this report.",
        "",
    ]
    baseline = summaries.get("baseline")
    if baseline is None:
        lines.extend(
            [
                "## Warnings",
                "",
                "- Missing baseline summary; delta table cannot be generated.",
                "",
            ]
        )
        return "\n".join(lines)

    columns = ("configuration", *[f"delta_{metric}" for metric in METRIC_COLUMNS])
    rows: list[dict[str, str]] = []
    for configuration in CONFIGURATIONS:
        if configuration == "baseline":
            continue
        summary = summaries.get(configuration)
        row = {"configuration": configuration}
        if summary is None:
            for metric in METRIC_COLUMNS:
                row[f"delta_{metric}"] = "MISSING"
        else:
            for metric in METRIC_COLUMNS:
                row[f"delta_{metric}"] = _delta_cell(summary, baseline, metric)
        rows.append(row)

    lines.append(_markdown_table(rows, columns))
    if warnings:
        lines.extend(["", "## Warnings", ""])
        lines.extend(f"- {warning}" for warning in warnings)
        lines.append("")
    return "\n".join(lines)


def write_summary_reports(output_root: Path = DEFAULT_OUTPUT_ROOT) -> dict[str, Path]:
    rows, summaries, warnings = _read_rows(output_root)
    reports_dir = output_root / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    csv_path = reports_dir / "thesis_metrics_table.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(TABLE_COLUMNS))
        writer.writeheader()
        writer.writerows(rows)

    md_path = reports_dir / "thesis_metrics_table.md"
    md_lines = [
        "# Thesis Metrics Table",
        "",
        "This table reads metrics from existing `eval_summary.json` artifacts.",
        "Missing fields are shown as `MISSING` rather than silently filled.",
        "",
        _markdown_table(rows),
    ]
    if warnings:
        md_lines.extend(["", "## Warnings", ""])
        md_lines.extend(f"- {warning}" for warning in warnings)
        md_lines.append("")
    md_path.write_text("\n".join(md_lines), encoding="utf-8")

    ablation_path = reports_dir / "ablation_comparison.md"
    ablation_path.write_text(_build_ablation_comparison(summaries, warnings), encoding="utf-8")

    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)

    return {
        "csv": csv_path,
        "markdown": md_path,
        "ablation_comparison": ablation_path,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Summarize thesis experiment outputs.")
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Root directory containing per-configuration eval outputs.",
    )
    args = parser.parse_args()

    outputs = write_summary_reports(Path(args.output_root))
    print(f"metrics_csv: {outputs['csv']}")
    print(f"metrics_markdown: {outputs['markdown']}")
    print(f"ablation_comparison: {outputs['ablation_comparison']}")


if __name__ == "__main__":
    main()
