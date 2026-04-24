from __future__ import annotations

from app.eval.statistics import (
    bootstrap_confidence_interval,
    compare_configs_paired,
    group_metrics_by_family,
    group_metrics_by_primary_module,
)


def test_bootstrap_confidence_interval_returns_stable_shape_and_seeded_result() -> None:
    values = [0, 1, 1, 0, 1, 1]

    first = bootstrap_confidence_interval(values, n_bootstrap=100, seed=7)
    second = bootstrap_confidence_interval(values, n_bootstrap=100, seed=7)

    assert first == second
    assert first["mean"] == sum(values) / len(values)
    assert 0.0 <= first["lower"] <= first["upper"] <= 1.0
    assert first["confidence"] == 0.95
    assert first["n"] == len(values)


def test_compare_configs_paired_aligns_by_case_id_and_counts_outcomes() -> None:
    baseline = [
        {"case_id": "case-a", "matched_expectation": True},
        {"case_id": "case-b", "matched_expectation": False},
        {"case_id": "case-baseline-only", "matched_expectation": True},
    ]
    candidate = [
        {"case_id": "case-a", "matched_expectation": True},
        {"case_id": "case-b", "matched_expectation": True},
        {"case_id": "case-candidate-only", "matched_expectation": False},
    ]

    result = compare_configs_paired(baseline, candidate, "matched_expectation")

    assert result["paired_count"] == 2
    assert result["baseline_only_count"] == 1
    assert result["candidate_only_count"] == 1
    assert result["delta"] == 0.5
    assert result["wins"] == 1
    assert result["losses"] == 0
    assert result["ties"] == 1


def test_group_metrics_by_family_uses_case_family_or_attack_type() -> None:
    results = [
        {"case_id": "case-a", "case_family": "metadata_drift_security", "matched_expectation": True},
        {"case_id": "case-b", "case_family": "metadata_drift_security", "matched_expectation": False},
        {"case_id": "case-c", "attack_type": "sink exfiltration", "matched_expectation": True},
    ]

    grouped = group_metrics_by_family(results)

    assert grouped["metadata_drift_security"]["total_cases"] == 2
    assert grouped["metadata_drift_security"]["matched_cases"] == 1
    assert grouped["sink exfiltration"]["total_cases"] == 1


def test_group_metrics_by_primary_module_prefers_likely_responsible_module() -> None:
    results = [
        {
            "case_id": "case-a",
            "likely_responsible_module": "sink_guard",
            "primary_target_module": "metadata_validator",
            "matched_expectation": False,
        },
        {
            "case_id": "case-b",
            "primary_target_module": "metadata_validator",
            "matched_expectation": True,
        },
    ]

    grouped = group_metrics_by_primary_module(results)

    assert grouped["sink_guard"]["total_cases"] == 1
    assert grouped["metadata_validator"]["total_cases"] == 1
