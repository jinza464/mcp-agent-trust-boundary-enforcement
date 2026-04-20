"""Evaluation metrics aggregation and JSON export utilities."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.eval.runner import EvalCaseResult


class EvalSummary(BaseModel):
    """Structured summary metrics for evaluation results."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int = Field(..., description="Total number of evaluated cases.")
    matched_cases: int = Field(..., description="Number of cases matched expected outcomes.")
    match_rate: float = Field(..., description="Matched ratio in [0.0, 1.0].")
    risk_level_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by detected risk level.",
    )
    decision_action_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by decision action.",
    )
    sink_action_distribution: dict[str, int] = Field(
        default_factory=dict,
        description="Counts by sink action (including 'none' when absent).",
    )


def _inc(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def summarize_results(results: list[EvalCaseResult]) -> EvalSummary:
    """Aggregate evaluation case results into summary metrics."""
    total_cases = len(results)
    matched_cases = sum(1 for item in results if item.matched_expectation)
    match_rate = (matched_cases / total_cases) if total_cases else 0.0

    risk_level_distribution: dict[str, int] = {}
    decision_action_distribution: dict[str, int] = {}
    sink_action_distribution: dict[str, int] = {}

    for item in results:
        _inc(risk_level_distribution, item.detected_risk_level.value)
        _inc(decision_action_distribution, item.decision_action.value)
        _inc(sink_action_distribution, item.sink_action.value if item.sink_action is not None else "none")

    return EvalSummary(
        total_cases=total_cases,
        matched_cases=matched_cases,
        match_rate=match_rate,
        risk_level_distribution=risk_level_distribution,
        decision_action_distribution=decision_action_distribution,
        sink_action_distribution=sink_action_distribution,
    )


def export_results(results: list[EvalCaseResult], output_dir: str | Path) -> dict[str, Path]:
    """Export case-level results and summary metrics to JSON files."""
    summary = summarize_results(results)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cases_path = out_dir / "eval_case_results.json"
    summary_path = out_dir / "eval_summary.json"

    case_payload = [item.model_dump(mode="json") for item in results]
    cases_path.write_text(json.dumps(case_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path.write_text(json.dumps(summary.model_dump(mode="json"), ensure_ascii=False, indent=2), encoding="utf-8")

    return {"cases": cases_path, "summary": summary_path}
