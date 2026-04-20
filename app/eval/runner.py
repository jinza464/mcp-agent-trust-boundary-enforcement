"""Minimal local evaluation runner for security attack cases."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel
from app.decision.decision_engine import DecisionContext, decide
from app.eval.attack_cases import EvalAttackCase, default_attack_cases
from app.policy.capability_policy import classify_capabilities
from app.sink.sink_guard import inspect_sink
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import validate_metadata


class EvalCaseResult(BaseModel):
    """Structured per-case evaluation result."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Attack case id.")
    attack_type: str = Field(..., description="Attack category of the evaluated case.")
    detected_risk_level: RiskLevel = Field(..., description="Detected risk level from decision engine.")
    decision_action: DecisionAction = Field(..., description="Decision action from decision engine.")
    sink_action: DecisionAction | None = Field(default=None, description="Sink guard action when sink is present.")
    matched_expectation: bool = Field(..., description="Whether result matched expected action/risk/(sink action).")
    reasons: list[str] = Field(default_factory=list, description="Decision reasons.")
    findings: list[str] = Field(default_factory=list, description="Combined findings from pipeline.")


def run_case(case: EvalAttackCase) -> EvalCaseResult:
    """Execute one attack case through the minimal local security evaluation loop."""
    source_trust = tag_source("user_query", case.user_query)
    capability_result = classify_capabilities(case.tool_metadata)
    metadata_result = validate_metadata(case.old_snapshot, case.tool_metadata) if case.old_snapshot else None

    decision_result = decide(
        DecisionContext(
            tool_metadata=case.tool_metadata,
            source_trust_label=source_trust,
            source_type="user_query",
            source_content=case.user_query,
            capability_result=capability_result,
            metadata_validation_result=metadata_result,
            old_snapshot=case.old_snapshot,
        )
    )

    sink_action: DecisionAction | None = None
    sink_findings: list[str] = []
    if case.sink_plan is not None:
        sink_result = inspect_sink(
            planned_action=case.sink_plan.planned_action,
            payload=case.sink_plan.payload,
            metadata=case.sink_plan.metadata,
        )
        sink_action = sink_result.action
        sink_findings = sink_result.findings + sink_result.blocked_reasons

    matched = (
        decision_result.action == case.expected_action
        and decision_result.risk_level == case.expected_risk
        and (case.expected_sink_action is None or sink_action == case.expected_sink_action)
    )

    return EvalCaseResult(
        case_id=case.id,
        attack_type=case.attack_type,
        detected_risk_level=decision_result.risk_level,
        decision_action=decision_result.action,
        sink_action=sink_action,
        matched_expectation=matched,
        reasons=decision_result.reasons,
        findings=decision_result.findings + sink_findings,
    )


def run_all_cases(cases: list[EvalAttackCase] | None = None) -> list[EvalCaseResult]:
    """Execute all provided cases, or built-in defaults when omitted."""
    selected = cases or default_attack_cases()
    return [run_case(case) for case in selected]
