"""Minimal local evaluation runner for security attack cases."""

from __future__ import annotations

from collections.abc import Mapping

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, TrustLabel
from app.decision.decision_engine import DecisionContext, decide
from app.eval.attack_cases import EvalAttackCase, default_attack_cases
from app.eval.runtime_semantics import compute_execution_semantics
from app.policy.capability_policy import classify_capabilities
from app.sink.sink_guard import inspect_sink
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import validate_metadata


class EvalCaseResult(BaseModel):
    """Structured per-case evaluation result."""

    model_config = ConfigDict(extra="forbid")

    case_id: str = Field(..., description="Attack case id.")
    attack_type: str = Field(..., description="Attack category of the evaluated case.")
    is_attack: bool = Field(default=True, description="Whether this evaluated case is an attack case.")
    is_benign: bool = Field(default=False, description="Whether this evaluated case is benign.")
    involves_sink: bool = Field(default=False, description="Whether sink checks are involved for this case.")
    disabled_modules: list[str] = Field(default_factory=list, description="Disabled modules under current ablation configuration.")
    affected_by_ablation: bool = Field(default=False, description="Whether this case is structurally affected by disabled modules.")
    detected_risk_level: RiskLevel = Field(..., description="Detected risk level from decision engine.")
    decision_action: DecisionAction = Field(..., description="Decision action from decision engine.")
    sink_action: DecisionAction | None = Field(default=None, description="Sink guard action when sink is present.")
    matched_expectation: bool = Field(..., description="Whether result matched expected action/risk/(sink action).")
    intervention_triggered: bool | None = Field(default=None)
    completed_execution: bool | None = Field(default=None)
    execution_degraded: bool | None = Field(default=None)
    reasons: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class AblationConfig(BaseModel):
    """Ablation switches for selectively disabling trust-boundary modules."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    disable_trust_tagging: bool = Field(default=False, validation_alias=AliasChoices("disable_trust_tagging", "no_trust_tagging"))
    disable_metadata_validation: bool = Field(default=False, validation_alias=AliasChoices("disable_metadata_validation", "no_metadata_validation"))
    disable_sink_guard: bool = Field(default=False, validation_alias=AliasChoices("disable_sink_guard", "no_sink_guard"))

    @property
    def no_trust_tagging(self) -> bool:
        return self.disable_trust_tagging

    @property
    def no_metadata_validation(self) -> bool:
        return self.disable_metadata_validation

    @property
    def no_sink_guard(self) -> bool:
        return self.disable_sink_guard


class RuntimeExecutionHints(BaseModel):
    """Optional runtime truth hints used to override inferred execution semantics."""

    model_config = ConfigDict(extra="forbid")

    runtime_executed: bool | None = Field(default=None)
    runtime_completed_execution: bool | None = Field(default=None)
    runtime_execution_degraded: bool | None = Field(default=None)


def _disabled_modules(cfg: AblationConfig) -> list[str]:
    disabled: list[str] = []
    if cfg.disable_trust_tagging:
        disabled.append("trust_tagging")
    if cfg.disable_metadata_validation:
        disabled.append("metadata_validation")
    if cfg.disable_sink_guard:
        disabled.append("sink_guard")
    return disabled


def _case_affected_by_ablation(case: EvalAttackCase, cfg: AblationConfig, baseline_source_trust: TrustLabel) -> bool:
    affected = False
    if cfg.disable_trust_tagging and baseline_source_trust != TrustLabel.TRUSTED:
        affected = True
    if cfg.disable_metadata_validation and case.old_snapshot is not None:
        affected = True
    if cfg.disable_sink_guard and (case.sink_plan is not None or case.involves_sink):
        affected = True
    return affected


def _normalize_action_for_expectation(action: DecisionAction) -> DecisionAction:
    if action == DecisionAction.SANDBOX:
        return DecisionAction.ALLOW
    return action


def _extract_bool(source: object, *keys: str) -> bool | None:
    for key in keys:
        value: object | None = None
        if isinstance(source, Mapping):
            if key in source:
                value = source.get(key)
        elif hasattr(source, key):
            value = getattr(source, key)
        if isinstance(value, bool):
            return value
    return None


def _extract_runtime_hints_from_result(runtime_result: object | None) -> RuntimeExecutionHints:
    if runtime_result is None:
        return RuntimeExecutionHints()

    root = runtime_result
    nested: object | None = None
    if isinstance(root, Mapping):
        nested = root.get("final_execution_outcome")
    else:
        nested = getattr(root, "final_execution_outcome", None)
    if nested is not None:
        root = nested

    return RuntimeExecutionHints(
        runtime_executed=_extract_bool(root, "executed"),
        runtime_completed_execution=_extract_bool(root, "completed_execution", "execution_completed"),
        runtime_execution_degraded=_extract_bool(root, "execution_degraded"),
    )


def _resolve_runtime_hints(
    case: EvalAttackCase,
    runtime_result: object | None = None,
) -> RuntimeExecutionHints:
    if runtime_result is not None:
        return _extract_runtime_hints_from_result(runtime_result)

    runtime_candidate = case.source_metadata.get("runtime_result")
    if runtime_candidate is not None:
        return _extract_runtime_hints_from_result(runtime_candidate)

    return RuntimeExecutionHints(
        runtime_executed=_extract_bool(case.source_metadata, "runtime_executed"),
        runtime_completed_execution=_extract_bool(
            case.source_metadata,
            "runtime_completed_execution",
        ),
        runtime_execution_degraded=_extract_bool(
            case.source_metadata,
            "runtime_execution_degraded",
        ),
    )


def run_case(
    case: EvalAttackCase,
    ablation_config: AblationConfig | dict | None = None,
    *,
    runtime_result: object | None = None,
) -> EvalCaseResult:
    """Execute one attack case through the minimal local security evaluation loop."""
    cfg = ablation_config if isinstance(ablation_config, AblationConfig) else AblationConfig.model_validate(ablation_config or {})
    ablation_notes: list[str] = []

    baseline_source_trust = tag_source(case.source_type, case.source_content, metadata=case.source_metadata)
    source_trust = TrustLabel.TRUSTED if cfg.disable_trust_tagging else baseline_source_trust
    if cfg.disable_trust_tagging:
        ablation_notes.append("ablation:disable_trust_tagging (source trust fixed to trusted)")

    capability_result = classify_capabilities(case.tool_metadata)
    metadata_result = None if cfg.disable_metadata_validation else (validate_metadata(case.old_snapshot, case.tool_metadata) if case.old_snapshot else None)
    if cfg.disable_metadata_validation:
        ablation_notes.append("ablation:disable_metadata_validation (metadata checks skipped)")

    decision_result = decide(
        DecisionContext(
            tool_metadata=case.tool_metadata,
            source_trust_label=source_trust,
            source_type=case.source_type,
            source_content=case.source_content,
            source_metadata=case.source_metadata,
            capability_result=capability_result,
            metadata_validation_result=metadata_result,
            old_snapshot=None if cfg.disable_metadata_validation else case.old_snapshot,
        )
    )

    sink_action: DecisionAction | None = None
    sink_findings: list[str] = []
    if case.sink_plan is not None and not cfg.disable_sink_guard:
        sink_result = inspect_sink(
            planned_action=case.sink_plan.planned_action,
            payload=case.sink_plan.payload,
            metadata=case.sink_plan.metadata,
        )
        sink_action = sink_result.action
        sink_findings = sink_result.findings + sink_result.blocked_reasons
    elif case.sink_plan is not None and cfg.disable_sink_guard:
        ablation_notes.append("ablation:disable_sink_guard (sink checks skipped)")

    decision_action_for_match = _normalize_action_for_expectation(decision_result.action)
    expected_action_for_match = _normalize_action_for_expectation(case.expected_action)
    matched = (
        decision_action_for_match == expected_action_for_match
        and decision_result.risk_level == case.expected_risk
        and (case.expected_sink_action is None or sink_action == case.expected_sink_action)
    )

    runtime_hints = _resolve_runtime_hints(case, runtime_result=runtime_result)
    semantics = compute_execution_semantics(
        decision_result.action,
        sink_action,
        runtime_executed=runtime_hints.runtime_executed,
        runtime_completed_execution=runtime_hints.runtime_completed_execution,
        runtime_execution_degraded=runtime_hints.runtime_execution_degraded,
    )
    disabled = _disabled_modules(cfg)
    affected_by_ablation = _case_affected_by_ablation(case, cfg, baseline_source_trust)

    return EvalCaseResult(
        case_id=case.id,
        attack_type=case.attack_type,
        is_attack=case.is_attack,
        is_benign=case.is_benign,
        involves_sink=case.involves_sink or case.sink_plan is not None,
        disabled_modules=disabled,
        affected_by_ablation=affected_by_ablation,
        detected_risk_level=decision_result.risk_level,
        decision_action=decision_result.action,
        sink_action=sink_action,
        matched_expectation=matched,
        intervention_triggered=semantics.intervention_triggered,
        completed_execution=semantics.completed_execution,
        execution_degraded=semantics.execution_degraded,
        reasons=decision_result.reasons,
        findings=decision_result.findings + sink_findings + ablation_notes,
    )


def run_all_cases(
    cases: list[EvalAttackCase] | None = None,
    ablation_config: AblationConfig | dict | None = None,
    *,
    runtime_results_by_case: Mapping[str, object] | None = None,
) -> list[EvalCaseResult]:
    selected = cases or default_attack_cases()
    return [
        run_case(
            case,
            ablation_config=ablation_config,
            runtime_result=runtime_results_by_case.get(case.id) if runtime_results_by_case else None,
        )
        for case in selected
    ]
