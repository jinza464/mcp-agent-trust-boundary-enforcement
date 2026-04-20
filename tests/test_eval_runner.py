"""Tests for minimal local evaluation runner."""

from __future__ import annotations

from app.core.models import DecisionAction, RiskLevel
from app.eval.attack_cases import default_attack_cases
from app.eval.runner import run_all_cases, run_case


def _case(case_id: str):
    cases = {item.id: item for item in default_attack_cases()}
    return cases[case_id]


def test_run_all_cases_executes_five_paths() -> None:
    results = run_all_cases()
    assert len(results) >= 5
    assert all(result.attack_type for result in results)
    assert {result.case_id for result in results}.issuperset(
        {
            "case-metadata-injection",
            "case-tool-shadowing",
            "case-rug-pull",
            "case-source-to-sink-exfiltration",
            "case-hidden-invocation",
        }
    )


def test_metadata_injection_path() -> None:
    result = run_case(_case("case-metadata-injection"))
    assert result.attack_type == "metadata injection"
    assert result.detected_risk_level == RiskLevel.HIGH
    assert result.decision_action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.matched_expectation is True


def test_tool_shadowing_path() -> None:
    result = run_case(_case("case-tool-shadowing"))
    assert result.attack_type == "tool shadowing"
    assert result.detected_risk_level == RiskLevel.HIGH
    assert result.decision_action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.matched_expectation is True


def test_rug_pull_path() -> None:
    result = run_case(_case("case-rug-pull"))
    assert result.attack_type == "rug pull"
    assert result.detected_risk_level == RiskLevel.HIGH
    assert result.decision_action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.matched_expectation is True


def test_source_to_sink_exfiltration_path() -> None:
    result = run_case(_case("case-source-to-sink-exfiltration"))
    assert result.attack_type == "source-to-sink exfiltration"
    assert result.detected_risk_level == RiskLevel.CRITICAL
    assert result.decision_action == DecisionAction.DENY
    assert result.sink_action == DecisionAction.DENY
    assert result.matched_expectation is True


def test_hidden_invocation_path() -> None:
    result = run_case(_case("case-hidden-invocation"))
    assert result.attack_type == "hidden invocation"
    assert result.detected_risk_level == RiskLevel.CRITICAL
    assert result.decision_action == DecisionAction.DENY
    assert result.matched_expectation is True
