"""Tests for evaluation ablation support."""

from __future__ import annotations

from app.core.models import DecisionAction
from app.eval.attack_cases import default_attack_cases
from app.eval.ablation import run_ablation
from app.eval.runner import run_case


def test_baseline_ablation_run_works() -> None:
    output = run_ablation()
    assert output.summary.total_cases == len(output.case_results)
    assert output.summary.total_cases > 0
    assert output.config.no_metadata_validation is False
    assert output.config.no_sink_guard is False
    assert output.config.no_trust_tagging is False


def test_no_metadata_validation_ablation_runs() -> None:
    output = run_ablation(config={"no_metadata_validation": True})
    assert output.summary.total_cases == len(output.case_results)
    assert output.config.no_metadata_validation is True


def test_no_metadata_validation_actually_skips_metadata_effect() -> None:
    case = next(item for item in default_attack_cases() if item.id == "case-tool-shadowing")
    baseline = run_case(case)
    no_mv = run_case(case, ablation_config={"disable_metadata_validation": True})
    assert baseline.decision_action == DecisionAction.REQUIRE_CONFIRMATION
    assert no_mv.decision_action == DecisionAction.ALLOW


def test_no_sink_guard_ablation_runs() -> None:
    output = run_ablation(config={"no_sink_guard": True})
    assert output.summary.total_cases == len(output.case_results)
    assert output.config.no_sink_guard is True
    sink_cases = [item for item in output.case_results if item.involves_sink]
    assert sink_cases
    assert all(item.sink_action is None for item in sink_cases)


def test_no_trust_tagging_ablation_runs() -> None:
    output = run_ablation(config={"no_trust_tagging": True})
    assert output.summary.total_cases == len(output.case_results)
    assert output.config.no_trust_tagging is True
