"""Ablation summary aggregator for paper-ready table exports."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from app.eval.attack_cases import default_attack_cases


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
    "affected_family_count",
    "top_affected_family",
    "affected_cases_by_family",
    "security_gain_interpretation",
    "utility_cost_interpretation",
    "dominant_changed_metric",
    "baseline_relative_rank",
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

SECURITY_METRIC_KEYS: list[str] = [
    "attack_success_rate",
    "leak_rate",
]

UTILITY_METRIC_KEYS: list[str] = [
    "false_positive_rate",
    "utility_loss",
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


def _is_case_affected(item: dict[str, object]) -> bool:
    if bool(item.get("affected_by_ablation")):
        return True
    findings = [str(x) for x in item.get("findings", [])]
    return any(text.startswith("ablation:disable_") for text in findings)


def _build_case_family_lookup() -> dict[str, str]:
    return {item.id: item.case_family for item in default_attack_cases()}


def _resolve_case_family(item: dict[str, object], case_family_lookup: dict[str, str]) -> str:
    explicit = str(item.get("case_family", "")).strip()
    if explicit:
        return explicit
    case_id = str(item.get("case_id", "")).strip()
    if case_id and case_id in case_family_lookup:
        return case_family_lookup[case_id]
    return "unknown"


def _affected_case_stats(case_results_path: Path) -> tuple[int, int, dict[str, dict[str, float | int]]]:
    if not case_results_path.exists():
        return 0, 0, {}
    payload = json.loads(case_results_path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        return 0, 0, {}

    total = len(payload)
    affected = 0
    case_family_lookup = _build_case_family_lookup()
    family_stats: dict[str, dict[str, float | int]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        family = _resolve_case_family(item, case_family_lookup)
        bucket = family_stats.setdefault(
            family,
            {"total_cases": 0, "affected_cases_count": 0, "affected_cases_ratio": 0.0},
        )
        bucket["total_cases"] = int(bucket["total_cases"]) + 1
        if _is_case_affected(item):
            affected += 1
            bucket["affected_cases_count"] = int(bucket["affected_cases_count"]) + 1

    ordered: dict[str, dict[str, float | int]] = {}
    for family in sorted(
        family_stats,
        key=lambda name: (
            -int(family_stats[name]["affected_cases_count"]),
            -int(family_stats[name]["total_cases"]),
            name,
        ),
    ):
        stats = family_stats[family]
        total_cases = int(stats["total_cases"])
        affected_cases = int(stats["affected_cases_count"])
        stats["affected_cases_ratio"] = (affected_cases / total_cases) if total_cases else 0.0
        ordered[family] = stats

    return affected, total, ordered


def _top_affected_family(family_stats: dict[str, dict[str, float | int]]) -> str:
    top_family = "none"
    top_count = -1
    top_ratio = -1.0
    for family, stats in family_stats.items():
        count = int(stats.get("affected_cases_count", 0))
        ratio = float(stats.get("affected_cases_ratio", 0.0))
        if count > top_count or (count == top_count and ratio > top_ratio):
            top_family = family
            top_count = count
            top_ratio = ratio
    return top_family if top_count > 0 else "none"


def _build_explanation(
    config_name: str,
    disabled_modules: list[str],
    row: dict[str, object],
) -> str:
    if config_name == "baseline":
        return (
            "Baseline reference with all trust-boundary modules enabled; this row anchors "
            "security-utility tradeoff interpretation and relative ablation attribution."
        )

    parts: list[str] = []
    if disabled_modules:
        parts.append(
            f"Ablation setting removes {', '.join(disabled_modules)}, isolating module-level contribution."
        )

    if float(row.get("delta_attack_success_rate", 0.0)) > 0:
        parts.append("Attack success increases relative to baseline, indicating reduced defensive interception.")
    if float(row.get("delta_leak_rate", 0.0)) > 0:
        parts.append("Leakage rises relative to baseline, indicating weaker sink-side containment.")
    if float(row.get("delta_false_positive_rate", 0.0)) < 0:
        parts.append("False-positive pressure drops, suggesting less aggressive intervention on benign traffic.")
    if float(row.get("delta_utility_loss", 0.0)) < 0:
        parts.append("Utility loss decreases, indicating smoother benign execution paths.")
    if float(row.get("delta_match_rate", 0.0)) < 0:
        parts.append("Overall benchmark agreement declines versus baseline.")
    top_family = str(row.get("top_affected_family", "none"))
    if top_family != "none":
        parts.append(f"Most affected case family is {top_family}, highlighting concentrated module impact.")

    return (
        " ".join(parts)
        if parts
        else "No material shift is observed relative to baseline across security and utility indicators."
    )


def _dominant_changed_metric(row: dict[str, object]) -> str:
    deltas = {metric: abs(float(row.get(f"delta_{metric}", 0.0))) for metric in METRIC_KEYS}
    if not deltas:
        return "none"
    metric, value = max(deltas.items(), key=lambda item: item[1])
    return metric if value > 0 else "none"


def _security_gain_interpretation(config_name: str, row: dict[str, object]) -> str:
    if config_name == "baseline":
        return "Security reference point: full module stack retained."
    delta_asr = float(row.get("delta_attack_success_rate", 0.0))
    delta_leak = float(row.get("delta_leak_rate", 0.0))
    security_drift = delta_asr + delta_leak
    if delta_asr > 0 and delta_leak > 0:
        return "Security weakens on both attack success and leakage, indicating broad defense contribution loss."
    if delta_leak > 0:
        return "Security degradation is leak-dominated, suggesting execution-plane containment dependence."
    if delta_asr > 0:
        return "Security degradation is attack-success dominated, suggesting upstream gating contribution loss."
    if security_drift < 0:
        return "Security indicators improve versus baseline, suggesting a conservative shift in this configuration."
    return "Security remains near baseline with limited measurable change."


def _utility_cost_interpretation(config_name: str, row: dict[str, object]) -> str:
    if config_name == "baseline":
        return "Utility reference point: baseline intervention burden."
    delta_fpr = float(row.get("delta_false_positive_rate", 0.0))
    delta_utility = float(row.get("delta_utility_loss", 0.0))
    utility_cost = delta_fpr + delta_utility
    if delta_fpr > 0 or delta_utility > 0:
        return "Utility cost increases, indicating higher benign intervention burden."
    if delta_fpr < 0 and delta_utility < 0:
        return "Utility cost decreases on both FPR and utility loss, indicating smoother benign throughput."
    if utility_cost < 0:
        return "Utility burden declines modestly relative to baseline."
    return "Utility profile remains close to baseline."


def _attach_baseline_relative_rank(rows: list[dict[str, object]]) -> None:
    scored: list[tuple[float, str]] = []
    for row in rows:
        config = str(row.get("configuration", ""))
        if config == "baseline":
            score = 0.0
        else:
            score = sum(abs(float(row.get(f"delta_{metric}", 0.0))) for metric in METRIC_KEYS)
        scored.append((score, config))

    rank_map: dict[str, int] = {}
    for idx, (_, config) in enumerate(sorted(scored, key=lambda item: (item[0], item[1]))):
        rank_map[config] = idx + 1

    for row in rows:
        row["baseline_relative_rank"] = rank_map.get(str(row.get("configuration", "")), len(rows))


def load_ablation_summaries(
    summary_paths: dict[str, str | Path] | None = None,
) -> list[dict[str, object]]:
    """Load summary JSONs and normalize into one table-like record list."""
    selected = summary_paths or DEFAULT_SUMMARY_PATHS
    rows: list[dict[str, object]] = []
    for config_name, path_like in selected.items():
        path = Path(path_like)
        if not path.exists():
            raise FileNotFoundError(f"Summary file not found for '{config_name}': {path}")
        payload = json.loads(path.read_text(encoding="utf-8"))
        affected_cases_count, total_cases, family_stats = _affected_case_stats(_derive_case_results_path(path))
        affected_cases_ratio = (affected_cases_count / total_cases) if total_cases else 0.0
        disabled_modules = _infer_disabled_modules(config_name)
        top_affected_family = _top_affected_family(family_stats)
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
            "affected_family_count": len(family_stats),
            "top_affected_family": top_affected_family,
            "affected_cases_by_family": family_stats,
        }
        rows.append(row)

    by_config = {str(item["configuration"]): item for item in rows}
    baseline = by_config.get("baseline", {})
    for row in rows:
        for metric in METRIC_KEYS:
            baseline_value = float(baseline.get(metric, 0.0))
            value = float(row.get(metric, 0.0))
            row[f"delta_{metric}"] = value - baseline_value
        row["dominant_changed_metric"] = _dominant_changed_metric(row)
        row["security_gain_interpretation"] = _security_gain_interpretation(
            config_name=str(row.get("configuration", "")),
            row=row,
        )
        row["utility_cost_interpretation"] = _utility_cost_interpretation(
            config_name=str(row.get("configuration", "")),
            row=row,
        )
        row["explanation"] = _build_explanation(
            config_name=str(row.get("configuration", "")),
            disabled_modules=[
                item for item in str(row.get("disabled_modules", "")).split(",") if item and item != "none"
            ],
            row=row,
        )
    _attach_baseline_relative_rank(rows)
    return rows


def export_ablation_report(
    rows: list[dict[str, object]],
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
        csv_rows: list[dict[str, object]] = []
        for row in rows:
            csv_row = dict(row)
            by_family = csv_row.get("affected_cases_by_family")
            if isinstance(by_family, dict):
                csv_row["affected_cases_by_family"] = json.dumps(by_family, ensure_ascii=False, sort_keys=True)
            csv_rows.append(csv_row)
        writer.writerows(csv_rows)

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
