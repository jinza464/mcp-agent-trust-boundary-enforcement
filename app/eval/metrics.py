"""Evaluation metrics aggregation and JSON export utilities."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction
from app.eval.runtime_semantics import (
    CASE_PACK_VERSION,
    RUNTIME_SEMANTICS_VERSION,
    SEAL_TAG,
    ExecutionSemantics,
    artifact_metadata,
    compute_execution_semantics,
)
from app.eval.runner import EvalCaseResult


class EvalSummary(BaseModel):
    """Structured summary metrics for evaluation results."""

    model_config = ConfigDict(extra="forbid")

    semantics_version: str = Field(default=RUNTIME_SEMANTICS_VERSION)
    case_pack_version: str = Field(default=CASE_PACK_VERSION)
    seal_tag: str = Field(default=SEAL_TAG)
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
    # Prototype-level operational metrics for paper experiments:
    # - attack_success_rate: attack cases with no effective intervention.
    # - leak_rate: sink-involved cases that still complete without sink hard block.
    # - escalation_rate: fraction of all cases ending in ESCALATE.
    # - false_positive_rate (FPR): benign cases where intervention is triggered.
    # - utility_loss: benign cases that fail normal completion or run in degraded mode.
    attack_success_rate: float = Field(..., description="Attack Success Rate (ASR).")
    leak_rate: float = Field(..., description="Rate of sink-involved cases not blocked by sink guard.")
    escalation_rate: float = Field(..., description="Fraction of cases with decision action ESCALATE.")
    false_positive_rate: float = Field(..., description="False positive rate over benign/safe cases.")
    utility_loss: float = Field(..., description="Utility loss over benign/safe cases.")
    execution_completion_rate: float = Field(
        ...,
        description="Prototype operational metric: fraction of cases reaching normal execution completion.",
    )
    intervention_rate: float = Field(
        ...,
        description="Prototype operational metric: fraction of cases where policy/sink intervention was triggered.",
    )
    hard_block_rate: float = Field(
        ...,
        description="Prototype operational metric: fraction of cases directly hard-blocked (decision/sink DENY).",
    )
    confirmation_rate: float = Field(
        ...,
        description="Prototype operational metric: fraction of cases that enter confirmation gate.",
    )


def _inc(counter: dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def resolve_case_semantics(item: EvalCaseResult) -> ExecutionSemantics:
    """Resolve one normalized semantic view per case for all metric calculations."""
    semantics = compute_execution_semantics(
        item.decision_action,
        item.sink_action,
        runtime_completed_execution=item.completed_execution,
        runtime_execution_degraded=item.execution_degraded,
    )
    if item.intervention_triggered is not None:
        semantics = semantics.model_copy(update={"intervention_triggered": item.intervention_triggered})
    return semantics


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

    attack_cases = [item for item in results if item.is_attack]
    sink_cases = [item for item in results if item.involves_sink]
    benign_cases = [item for item in results if item.is_benign]
    semantics_by_case = {id(item): resolve_case_semantics(item) for item in results}

    attack_success_count = sum(1 for item in attack_cases if not semantics_by_case[id(item)].intervention_triggered)
    # Leak semantics are centralized in ExecutionSemantics.leak_possible.
    leak_count = sum(1 for item in sink_cases if semantics_by_case[id(item)].leak_possible)
    escalation_count = sum(1 for item in results if item.decision_action == DecisionAction.ESCALATE)
    # FPR: benign case with intervention signal, regardless of whether execution still completed.
    false_positive_count = sum(1 for item in benign_cases if semantics_by_case[id(item)].intervention_triggered)
    # Utility loss: benign case failed completion or completed in degraded mode.
    utility_loss_count = sum(
        1
        for item in benign_cases
        if (not semantics_by_case[id(item)].completed_execution) or semantics_by_case[id(item)].execution_degraded
    )
    completion_count = sum(1 for item in results if semantics_by_case[id(item)].completed_execution)
    intervention_count = sum(1 for item in results if semantics_by_case[id(item)].intervention_triggered)
    hard_block_count = sum(1 for item in results if semantics_by_case[id(item)].hard_blocked)
    confirmation_count = sum(1 for item in results if semantics_by_case[id(item)].confirmation_required)

    attack_success_rate = (attack_success_count / len(attack_cases)) if attack_cases else 0.0
    leak_rate = (leak_count / len(sink_cases)) if sink_cases else 0.0
    escalation_rate = (escalation_count / total_cases) if total_cases else 0.0
    false_positive_rate = (false_positive_count / len(benign_cases)) if benign_cases else 0.0
    utility_loss = (utility_loss_count / len(benign_cases)) if benign_cases else 0.0
    execution_completion_rate = (completion_count / total_cases) if total_cases else 0.0
    intervention_rate = (intervention_count / total_cases) if total_cases else 0.0
    hard_block_rate = (hard_block_count / total_cases) if total_cases else 0.0
    confirmation_rate = (confirmation_count / total_cases) if total_cases else 0.0

    return EvalSummary(
        total_cases=total_cases,
        matched_cases=matched_cases,
        match_rate=match_rate,
        risk_level_distribution=risk_level_distribution,
        decision_action_distribution=decision_action_distribution,
        sink_action_distribution=sink_action_distribution,
        attack_success_rate=attack_success_rate,
        leak_rate=leak_rate,
        escalation_rate=escalation_rate,
        false_positive_rate=false_positive_rate,
        utility_loss=utility_loss,
        execution_completion_rate=execution_completion_rate,
        intervention_rate=intervention_rate,
        hard_block_rate=hard_block_rate,
        confirmation_rate=confirmation_rate,
    )


def export_results(results: list[EvalCaseResult], output_dir: str | Path) -> dict[str, Path]:
    """Export case-level results and summary metrics to JSON files."""
    summary = summarize_results(results)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cases_path = out_dir / "eval_case_results.json"
    summary_path = out_dir / "eval_summary.json"

    case_payload = [item.model_dump(mode="json") for item in results]
    summary_payload = {**artifact_metadata(), **summary.model_dump(mode="json")}
    cases_path.write_text(json.dumps(case_payload, ensure_ascii=False, indent=2), encoding="utf-8")
    summary_path.write_text(json.dumps(summary_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return {"cases": cases_path, "summary": summary_path}
