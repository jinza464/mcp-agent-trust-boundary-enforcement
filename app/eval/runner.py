"""Minimal local evaluation runner for security attack cases."""

from __future__ import annotations

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, TrustLabel
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
    is_attack: bool = Field(default=True, description="Whether this evaluated case is an attack case.")
    is_benign: bool = Field(default=False, description="Whether this evaluated case is benign.")
    involves_sink: bool = Field(default=False, description="Whether sink checks are involved for this case.")
    detected_risk_level: RiskLevel = Field(..., description="Detected risk level from decision engine.")
    decision_action: DecisionAction = Field(..., description="Decision action from decision engine.")
    sink_action: DecisionAction | None = Field(default=None, description="Sink guard action when sink is present.")
    matched_expectation: bool = Field(..., description="Whether result matched expected action/risk/(sink action).")
    reasons: list[str] = Field(default_factory=list, description="Decision reasons.")
    findings: list[str] = Field(default_factory=list, description="Combined findings from pipeline.")


class AblationConfig(BaseModel):
    """Ablation switches for selectively disabling trust-boundary modules."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    disable_trust_tagging: bool = Field(
        default=False,
        validation_alias=AliasChoices("disable_trust_tagging", "no_trust_tagging"),
    )
    disable_metadata_validation: bool = Field(
        default=False,
        validation_alias=AliasChoices("disable_metadata_validation", "no_metadata_validation"),
    )
    disable_sink_guard: bool = Field(
        default=False,
        validation_alias=AliasChoices("disable_sink_guard", "no_sink_guard"),
    )

    @property
    def no_trust_tagging(self) -> bool:
        """Backward-compatible alias."""
        return self.disable_trust_tagging

    @property
    def no_metadata_validation(self) -> bool:
        """Backward-compatible alias."""
        return self.disable_metadata_validation

    @property
    def no_sink_guard(self) -> bool:
        """Backward-compatible alias."""
        return self.disable_sink_guard


def run_case(case: EvalAttackCase, ablation_config: AblationConfig | dict | None = None) -> EvalCaseResult:
    """Execute one attack case through the minimal local security evaluation loop."""
    cfg = (
        ablation_config
        if isinstance(ablation_config, AblationConfig)
        else AblationConfig.model_validate(ablation_config or {})
    )

    ablation_notes: list[str] = []

    source_trust = (
        TrustLabel.TRUSTED
        if cfg.disable_trust_tagging
        else tag_source(case.source_type, case.source_content, metadata=case.source_metadata)
    )
    if cfg.disable_trust_tagging:
        ablation_notes.append("ablation:disable_trust_tagging (source trust fixed to trusted)")
    capability_result = classify_capabilities(case.tool_metadata)
    metadata_result = (
        None
        if cfg.disable_metadata_validation
        else (validate_metadata(case.old_snapshot, case.tool_metadata) if case.old_snapshot else None)
    )
    if cfg.disable_metadata_validation:
        ablation_notes.append("ablation:disable_metadata_validation (metadata checks skipped)")

    old_snapshot_for_decision = None if cfg.disable_metadata_validation else case.old_snapshot

    decision_result = decide(
        DecisionContext(
            tool_metadata=case.tool_metadata,
            source_trust_label=source_trust,
            source_type=case.source_type,
            source_content=case.source_content,
            source_metadata=case.source_metadata,
            capability_result=capability_result,
            metadata_validation_result=metadata_result,
            old_snapshot=old_snapshot_for_decision,
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

    matched = (
        decision_result.action == case.expected_action
        and decision_result.risk_level == case.expected_risk
        and (case.expected_sink_action is None or sink_action == case.expected_sink_action)
    )

    return EvalCaseResult(
        case_id=case.id,
        attack_type=case.attack_type,
        is_attack=case.is_attack,
        is_benign=case.is_benign,
        involves_sink=case.involves_sink or case.sink_plan is not None,
        detected_risk_level=decision_result.risk_level,
        decision_action=decision_result.action,
        sink_action=sink_action,
        matched_expectation=matched,
        reasons=decision_result.reasons,
        findings=decision_result.findings + sink_findings + ablation_notes,
    )


def run_all_cases(
    cases: list[EvalAttackCase] | None = None,
    ablation_config: AblationConfig | dict | None = None,
) -> list[EvalCaseResult]:
    """Execute all provided cases, or built-in defaults when omitted."""
    selected = cases or default_attack_cases()
    return [run_case(case, ablation_config=ablation_config) for case in selected]
