"""Tests for evaluation metrics and export utilities."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.core.models import DecisionAction, RiskLevel
from app.eval.metrics import export_results, summarize_results
from app.eval.runner import EvalCaseResult


def _result(
    *,
    case_id: str,
    attack_type: str,
    risk: RiskLevel,
    decision: DecisionAction,
    matched: bool,
    sink_action: DecisionAction | None = None,
) -> EvalCaseResult:
    return EvalCaseResult(
        case_id=case_id,
        attack_type=attack_type,
        detected_risk_level=risk,
        decision_action=decision,
        sink_action=sink_action,
        matched_expectation=matched,
        reasons=["reason"],
        findings=["finding"],
    )


def test_summarize_results_empty() -> None:
    summary = summarize_results([])
    assert summary.total_cases == 0
    assert summary.matched_cases == 0
    assert summary.match_rate == 0.0
    assert summary.risk_level_distribution == {}
    assert summary.decision_action_distribution == {}
    assert summary.sink_action_distribution == {}


def test_summarize_results_normal() -> None:
    results = [
        _result(
            case_id="c1",
            attack_type="metadata injection",
            risk=RiskLevel.HIGH,
            decision=DecisionAction.REQUIRE_CONFIRMATION,
            matched=True,
            sink_action=None,
        ),
        _result(
            case_id="c2",
            attack_type="exfiltration",
            risk=RiskLevel.CRITICAL,
            decision=DecisionAction.DENY,
            matched=False,
            sink_action=DecisionAction.DENY,
        ),
    ]

    summary = summarize_results(results)
    assert summary.total_cases == 2
    assert summary.matched_cases == 1
    assert summary.match_rate == 0.5
    assert summary.risk_level_distribution == {"high": 1, "critical": 1}
    assert summary.decision_action_distribution == {"require_confirmation": 1, "deny": 1}
    assert summary.sink_action_distribution == {"none": 1, "deny": 1}


def test_export_results_to_json() -> None:
    results = [
        _result(
            case_id="c1",
            attack_type="hidden invocation",
            risk=RiskLevel.CRITICAL,
            decision=DecisionAction.DENY,
            matched=True,
            sink_action=DecisionAction.DENY,
        )
    ]
    out_dir = Path("data") / "test_outputs" / f"eval-metrics-{uuid4().hex}"
    try:
        paths = export_results(results, out_dir)

        assert paths["cases"].exists()
        assert paths["summary"].exists()

        case_data = json.loads(paths["cases"].read_text(encoding="utf-8"))
        summary_data = json.loads(paths["summary"].read_text(encoding="utf-8"))
        assert case_data[0]["case_id"] == "c1"
        assert summary_data["total_cases"] == 1
        assert summary_data["matched_cases"] == 1
    finally:
        if out_dir.exists():
            for item in out_dir.glob("*"):
                item.unlink()
            out_dir.rmdir()
