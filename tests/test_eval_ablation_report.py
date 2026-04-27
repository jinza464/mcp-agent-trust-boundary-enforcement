"""Tests for ablation report family-level attribution fields."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from uuid import uuid4

from app.eval.ablation_report import build_and_export_ablation_report, export_ablation_report, load_ablation_summaries


def _write_summary(path: Path) -> None:
    payload = {
        "match_rate": 0.5,
        "attack_success_rate": 0.1,
        "leak_rate": 0.2,
        "false_positive_rate": 0.3,
        "utility_loss": 0.3,
        "escalation_rate": 0.1,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_cases(path: Path, items: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")


def test_load_ablation_summaries_includes_family_attribution() -> None:
    root = Path("data") / "test_outputs" / f"ablation-report-{uuid4().hex}"
    try:
        baseline_summary = root / "baseline" / "eval_summary.json"
        no_tt_summary = root / "no_trust_tagging" / "eval_summary.json"
        _write_summary(baseline_summary)
        _write_summary(no_tt_summary)

        _write_cases(
            root / "baseline" / "eval_case_results.json",
            [
                {"case_id": "baseline-c1", "case_family": "core_attack", "affected_by_ablation": False, "findings": []},
                {
                    "case_id": "baseline-c2",
                    "case_family": "gray_zone_benign",
                    "affected_by_ablation": False,
                    "findings": [],
                },
            ],
        )
        _write_cases(
            root / "no_trust_tagging" / "eval_case_results.json",
            [
                {
                    "case_id": "c1",
                    "case_family": "metadata_drift_security",
                    "affected_by_ablation": True,
                    "findings": [],
                },
                {
                    "case_id": "c2",
                    "case_family": "gray_zone_benign",
                    "affected_by_ablation": False,
                    "findings": ["ablation:disable_trust_tagging"],
                },
                {"case_id": "c3", "case_family": "gray_zone_benign", "affected_by_ablation": False, "findings": []},
            ],
        )

        rows = load_ablation_summaries(
            {
                "baseline": baseline_summary,
                "no_trust_tagging": no_tt_summary,
            }
        )
        by_config = {str(item["configuration"]): item for item in rows}

        baseline = by_config["baseline"]
        assert baseline["affected_cases_count"] == 0
        assert baseline["top_affected_family"] == "none"
        assert baseline["affected_family_count"] == 2
        assert baseline["security_gain_interpretation"] == "Security reference point: full module stack retained."
        assert baseline["utility_cost_interpretation"] == "Utility reference point: baseline intervention burden."
        assert baseline["dominant_changed_metric"] == "none"
        assert isinstance(baseline["baseline_relative_rank"], int)

        no_tt = by_config["no_trust_tagging"]
        assert no_tt["affected_cases_count"] == 2
        assert no_tt["top_affected_family"] == "metadata_drift_security"
        family_stats = no_tt["affected_cases_by_family"]
        assert isinstance(family_stats, dict)
        assert family_stats["metadata_drift_security"]["affected_cases_count"] == 1
        assert family_stats["gray_zone_benign"]["affected_cases_count"] == 1
        assert "Most affected case family" in str(no_tt["explanation"])
        assert "metadata_drift_security" in str(no_tt["explanation"])
        assert no_tt["dominant_changed_metric"] in {
            "none",
            "match_rate",
            "attack_success_rate",
            "leak_rate",
            "false_positive_rate",
            "utility_loss",
            "escalation_rate",
        }
        assert isinstance(no_tt["security_gain_interpretation"], str) and no_tt["security_gain_interpretation"]
        assert isinstance(no_tt["utility_cost_interpretation"], str) and no_tt["utility_cost_interpretation"]
        assert isinstance(no_tt["baseline_relative_rank"], int)
    finally:
        if root.exists():
            for child in root.glob("*"):
                if child.is_dir():
                    for item in child.glob("*"):
                        item.unlink()
                    child.rmdir()
            root.rmdir()


def test_load_ablation_summaries_falls_back_to_case_id_family_lookup() -> None:
    root = Path("data") / "test_outputs" / f"ablation-report-lookup-{uuid4().hex}"
    try:
        baseline_summary = root / "baseline" / "eval_summary.json"
        no_mv_summary = root / "no_metadata_validation" / "eval_summary.json"
        _write_summary(baseline_summary)
        _write_summary(no_mv_summary)

        _write_cases(root / "baseline" / "eval_case_results.json", [])
        _write_cases(
            root / "no_metadata_validation" / "eval_case_results.json",
            [
                {
                    "case_id": "case-tool-shadowing",
                    "affected_by_ablation": True,
                    "findings": [],
                }
            ],
        )

        rows = load_ablation_summaries(
            {
                "baseline": baseline_summary,
                "no_metadata_validation": no_mv_summary,
            }
        )
        by_config = {str(item["configuration"]): item for item in rows}
        no_mv = by_config["no_metadata_validation"]
        family_stats = no_mv["affected_cases_by_family"]
        assert isinstance(family_stats, dict)
        assert "metadata_drift_security" in family_stats
        assert no_mv["top_affected_family"] == "metadata_drift_security"
    finally:
        if root.exists():
            for child in root.glob("*"):
                if child.is_dir():
                    for item in child.glob("*"):
                        item.unlink()
                    child.rmdir()
            root.rmdir()


def test_export_ablation_report_serializes_family_stats_for_csv() -> None:
    root = Path("data") / "test_outputs" / f"ablation-report-export-{uuid4().hex}"
    try:
        rows = [
            {
                "configuration": "baseline",
                "disabled_modules": "none",
                "affected_cases_count": 0,
                "affected_cases_ratio": 0.0,
                "match_rate": 0.7,
                "delta_match_rate": 0.0,
                "attack_success_rate": 0.1,
                "delta_attack_success_rate": 0.0,
                "leak_rate": 0.2,
                "delta_leak_rate": 0.0,
                "false_positive_rate": 0.3,
                "delta_false_positive_rate": 0.0,
                "utility_loss": 0.3,
                "delta_utility_loss": 0.0,
                "escalation_rate": 0.1,
                "delta_escalation_rate": 0.0,
                "affected_family_count": 1,
                "top_affected_family": "none",
                "affected_cases_by_family": {
                    "core_attack": {"total_cases": 3, "affected_cases_count": 0, "affected_cases_ratio": 0.0}
                },
                "security_gain_interpretation": "security baseline",
                "utility_cost_interpretation": "utility baseline",
                "dominant_changed_metric": "none",
                "baseline_relative_rank": 1,
                "explanation": "baseline row",
            }
        ]

        exported = export_ablation_report(rows, output_dir=root)
        assert exported["json"].exists()
        assert exported["csv"].exists()

        with exported["csv"].open("r", encoding="utf-8", newline="") as handle:
            parsed = list(csv.DictReader(handle))
        assert len(parsed) == 1
        assert "affected_cases_by_family" in parsed[0]
        assert "\"core_attack\"" in parsed[0]["affected_cases_by_family"]
        assert "security_gain_interpretation" in parsed[0]
        assert "utility_cost_interpretation" in parsed[0]
        assert "dominant_changed_metric" in parsed[0]
        assert "baseline_relative_rank" in parsed[0]
    finally:
        if root.exists():
            for item in root.glob("*"):
                item.unlink()
            root.rmdir()


def _case_result(
    case_id: str,
    *,
    matched: bool,
    is_attack: bool,
    is_benign: bool,
    involves_sink: bool = False,
    intervention: bool = False,
    completed: bool = True,
    degraded: bool = False,
    leak_possible: bool = False,
    family: str = "metadata_drift_security",
    module: str = "metadata_validator",
) -> dict[str, object]:
    return {
        "case_id": case_id,
        "matched_expectation": matched,
        "is_attack": is_attack,
        "is_benign": is_benign,
        "involves_sink": involves_sink,
        "intervention_triggered": intervention,
        "completed_execution": completed,
        "execution_degraded": degraded,
        "leak_possible": leak_possible,
        "case_family": family,
        "primary_target_module": module,
    }


def test_build_and_export_ablation_report_default_omits_statistics(tmp_path: Path) -> None:
    baseline_summary = tmp_path / "baseline" / "eval_summary.json"
    candidate_summary = tmp_path / "no_trust_tagging" / "eval_summary.json"
    _write_summary(baseline_summary)
    _write_summary(candidate_summary)
    _write_cases(
        tmp_path / "baseline" / "eval_case_results.json",
        [_case_result("case-a", matched=True, is_attack=True, is_benign=False)],
    )
    _write_cases(
        tmp_path / "no_trust_tagging" / "eval_case_results.json",
        [_case_result("case-a", matched=False, is_attack=True, is_benign=False)],
    )

    payload = build_and_export_ablation_report(
        summary_paths={"baseline": baseline_summary, "no_trust_tagging": candidate_summary},
        output_dir=tmp_path / "out",
    )

    assert "statistics" not in payload
    assert "statistics" not in payload["exported_paths"]
    assert len(payload["rows"]) == 2
    assert payload["exported_paths"]["json"].exists()
    assert payload["exported_paths"]["csv"].exists()


def test_build_and_export_ablation_report_can_emit_statistics_appendix(tmp_path: Path) -> None:
    baseline_summary = tmp_path / "baseline" / "eval_summary.json"
    candidate_summary = tmp_path / "no_sink_guard" / "eval_summary.json"
    _write_summary(baseline_summary)
    _write_summary(candidate_summary)
    _write_cases(
        tmp_path / "baseline" / "eval_case_results.json",
        [
            _case_result(
                "case-a",
                matched=True,
                is_attack=True,
                is_benign=False,
                involves_sink=True,
                leak_possible=False,
            ),
            _case_result(
                "case-b",
                matched=True,
                is_attack=False,
                is_benign=True,
                intervention=False,
                completed=True,
                degraded=False,
                family="gray_zone_benign",
            ),
        ],
    )
    _write_cases(
        tmp_path / "no_sink_guard" / "eval_case_results.json",
        [
            _case_result(
                "case-a",
                matched=False,
                is_attack=True,
                is_benign=False,
                involves_sink=True,
                leak_possible=True,
            ),
            _case_result(
                "case-b",
                matched=True,
                is_attack=False,
                is_benign=True,
                intervention=True,
                completed=False,
                degraded=True,
                family="gray_zone_benign",
            ),
        ],
    )

    payload = build_and_export_ablation_report(
        summary_paths={"baseline": baseline_summary, "no_sink_guard": candidate_summary},
        output_dir=tmp_path / "out",
        include_statistics=True,
    )

    statistics = payload["statistics"]
    assert "bootstrap_confidence_intervals" in statistics
    assert "paired_comparisons" in statistics
    assert "family_groups" in statistics
    assert "module_groups" in statistics
    assert payload["exported_paths"]["statistics"].exists()
    assert len(payload["rows"]) == 2
    assert "match_rate" in payload["rows"][0]
