"""Rule-based Decision Engine for client-side trust boundary enforcement."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import (
    DecisionAction,
    DecisionResult,
    ModuleAssessmentResult,
    RecommendationAction,
    RiskLevel,
    ToolMetadata,
    ToolSnapshot,
    TrustLabel,
)
from app.policy.capability_policy import (
    CapabilityClassificationResult,
    classify_capabilities,
)
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import (
    MetadataValidationResult,
    validate_metadata,
)


class DecisionContext(BaseModel):
    """Input context for policy decision."""

    model_config = ConfigDict(extra="forbid")

    tool_metadata: ToolMetadata = Field(
        ...,
        description="Current tool metadata under decision.",
    )
    source_trust_label: TrustLabel | None = Field(
        default=None,
        description="Optional source trust label. When absent, inferred from source_type/content/metadata.",
    )
    source_type: str = Field(
        default="external_document",
        description="Input source type for trust tagging.",
    )
    source_content: str = Field(
        default="",
        description="Raw source content for trust tagging.",
    )
    source_metadata: dict[str, object] = Field(
        default_factory=dict,
        description="Auxiliary source metadata for trust tagging.",
    )
    capability_result: CapabilityClassificationResult | None = Field(
        default=None,
        description="Optional precomputed capability classification result.",
    )
    metadata_validation_result: MetadataValidationResult | None = Field(
        default=None,
        description="Optional precomputed metadata validation result.",
    )
    old_snapshot: ToolSnapshot | None = Field(
        default=None,
        description="Optional previous snapshot used to compute metadata validation when result is absent.",
    )
    user_authorized: bool = Field(
        default=False,
        description="Whether user explicitly authorized a risky operation in current decision flow.",
    )


class EngineDecisionResult(BaseModel):
    """Decision engine output with explanation fields for downstream enforcement."""

    model_config = ConfigDict(extra="forbid")

    action: DecisionAction = Field(..., description="Final action for this request.")
    risk_level: RiskLevel = Field(..., description="Aggregated decision risk level.")
    reasons: list[str] = Field(
        default_factory=list,
        description="Top-level decision reasons.",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="Detailed supporting findings.",
    )
    requires_user_confirmation: bool = Field(
        default=False,
        description="Whether explicit user confirmation is required before execution.",
    )
    decision_result: DecisionResult = Field(
        ...,
        description="Normalized DecisionResult payload.",
    )


class PolicyStageResult(BaseModel):
    """One policy stage evaluation result for composition traceability."""

    model_config = ConfigDict(extra="forbid")

    stage: str = Field(..., description="Policy stage name.")
    proposed_action: DecisionAction = Field(..., description="Stage-local action proposal.")
    risk_level: RiskLevel = Field(..., description="Stage-local risk estimate.")
    triggered: bool = Field(..., description="Whether this stage materially triggered.")
    reasons: list[str] = Field(default_factory=list, description="Stage-local reasons.")


class PolicyCompositionState(BaseModel):
    """Intermediate policy composition state before final enforcement."""

    model_config = ConfigDict(extra="forbid")

    source_risk: RiskLevel
    capability_risk: RiskLevel
    metadata_risk: RiskLevel
    stage_results: list[PolicyStageResult] = Field(default_factory=list)


def _risk_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }[level]


def _max_risk(*levels: RiskLevel) -> RiskLevel:
    return max(levels, key=_risk_rank)


def _source_risk_label(source_trust: TrustLabel) -> RiskLevel:
    if source_trust == TrustLabel.TRUSTED:
        return RiskLevel.LOW
    if source_trust == TrustLabel.SEMI_TRUSTED:
        return RiskLevel.MEDIUM
    return RiskLevel.HIGH


def _recommendation_from_risk(risk: RiskLevel) -> RecommendationAction:
    if risk in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
        return RecommendationAction.BLOCK
    if risk == RiskLevel.MEDIUM:
        return RecommendationAction.REVIEW
    return RecommendationAction.ALLOW


def _action_rank(action: DecisionAction) -> int:
    return {
        DecisionAction.ALLOW: 1,
        DecisionAction.SANDBOX: 2,
        DecisionAction.REQUIRE_CONFIRMATION: 3,
        DecisionAction.ESCALATE: 4,
        DecisionAction.DENY: 5,
    }[action]


def _default_metadata_validation() -> MetadataValidationResult:
    return MetadataValidationResult(
        passed=True,
        findings=[],
        risk_level=RiskLevel.LOW,
        recommended_action=DecisionAction.ALLOW,
        changed_fields=[],
    )


def _module_recommendations(
    *,
    source_trust: TrustLabel,
    source_risk: RiskLevel,
    capability_result: CapabilityClassificationResult,
    metadata_result: MetadataValidationResult,
) -> list[ModuleAssessmentResult]:
    return [
        ModuleAssessmentResult(
            module_name="trust_tagger",
            recommendation=_recommendation_from_risk(source_risk),
            risk_level=source_risk,
            reasons=[f"Source trust label={source_trust.value}."],
            findings=[f"Source trust label: {source_trust.value}."],
            evidence={"source_trust_label": source_trust.value},
        ),
        ModuleAssessmentResult(
            module_name="capability_policy",
            recommendation=_recommendation_from_risk(capability_result.risk_level),
            risk_level=capability_result.risk_level,
            reasons=["Capability policy risk evaluation result."],
            findings=capability_result.findings,
            evidence={"detected_capabilities": sorted(set(capability_result.detected_capabilities))},
        ),
        ModuleAssessmentResult(
            module_name="metadata_validator",
            recommendation=_recommendation_from_risk(metadata_result.risk_level),
            risk_level=metadata_result.risk_level,
            reasons=["Metadata validator risk evaluation result."],
            findings=metadata_result.findings,
            evidence={
                "changed_fields": metadata_result.changed_fields,
                "change_categories": getattr(metadata_result, "change_categories", []),
            },
        ),
    ]


def _policy_hard_block(detected_caps: set[str], metadata_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW
    risk = RiskLevel.LOW

    if "hidden_invocation" in detected_caps:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        reasons.append("Hidden invocation capability triggers hard block.")
    elif "read_secret" in detected_caps and "network_send" in detected_caps:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        reasons.append("Read-secret + network-send combination triggers hard block.")
    elif metadata_risk == RiskLevel.CRITICAL:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        reasons.append("Metadata validator marked update as critical risk.")

    return PolicyStageResult(
        stage="hard_block_policy",
        proposed_action=proposed,
        risk_level=risk,
        triggered=triggered,
        reasons=reasons,
    )


def _policy_metadata(metadata_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW

    if metadata_risk == RiskLevel.HIGH:
        triggered = True
        proposed = DecisionAction.REQUIRE_CONFIRMATION
        reasons.append("High metadata risk requires explicit confirmation.")
    elif metadata_risk == RiskLevel.MEDIUM:
        triggered = True
        proposed = DecisionAction.SANDBOX
        reasons.append("Medium metadata risk suggests sandboxing.")

    return PolicyStageResult(
        stage="metadata_policy",
        proposed_action=proposed,
        risk_level=metadata_risk,
        triggered=triggered,
        reasons=reasons,
    )


def _policy_source_trust(
    source_trust: TrustLabel,
    source_risk: RiskLevel,
    capability_risk: RiskLevel,
    metadata_risk: RiskLevel,
) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW

    if source_trust == TrustLabel.UNTRUSTED and _max_risk(source_risk, capability_risk, metadata_risk) in {
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    }:
        triggered = True
        proposed = DecisionAction.ESCALATE
        reasons.append("Untrusted source with non-low risk requires escalation.")

    return PolicyStageResult(
        stage="source_trust_policy",
        proposed_action=proposed,
        risk_level=source_risk,
        triggered=triggered,
        reasons=reasons,
    )


def _policy_capability(capability_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW

    if capability_risk == RiskLevel.HIGH:
        triggered = True
        proposed = DecisionAction.REQUIRE_CONFIRMATION
        reasons.append("High capability risk requires explicit confirmation.")
    elif capability_risk == RiskLevel.MEDIUM:
        triggered = True
        proposed = DecisionAction.SANDBOX
        reasons.append("Medium capability risk suggests sandboxing.")

    return PolicyStageResult(
        stage="capability_policy",
        proposed_action=proposed,
        risk_level=capability_risk,
        triggered=triggered,
        reasons=reasons,
    )


def _compose_action(stage_results: list[PolicyStageResult]) -> tuple[DecisionAction, list[str]]:
    stage_map = {item.stage: item for item in stage_results}
    reasons: list[str] = []

    hard_block = stage_map["hard_block_policy"]
    if hard_block.triggered:
        return DecisionAction.DENY, hard_block.reasons or ["Hard-block policy triggered."]

    metadata_stage = stage_map["metadata_policy"]
    # Preserve baseline behavior: high metadata risk gate takes priority over source escalation.
    if metadata_stage.proposed_action == DecisionAction.REQUIRE_CONFIRMATION:
        return DecisionAction.REQUIRE_CONFIRMATION, metadata_stage.reasons

    source_stage = stage_map["source_trust_policy"]
    capability_stage = stage_map["capability_policy"]

    candidate_actions = [source_stage.proposed_action, capability_stage.proposed_action, metadata_stage.proposed_action]
    action = max(candidate_actions, key=_action_rank)

    if source_stage.triggered:
        reasons.extend(source_stage.reasons)
    if capability_stage.triggered:
        reasons.extend(capability_stage.reasons)
    if metadata_stage.triggered:
        reasons.extend(metadata_stage.reasons)

    if not reasons:
        reasons = ["No blocking risk signal detected under current policy rules."]
    return action, reasons


def decide(context: DecisionContext | dict) -> EngineDecisionResult:
    """Make a composed enforcement decision via staged policy evaluation."""
    ctx = context if isinstance(context, DecisionContext) else DecisionContext.model_validate(context)

    source_trust = ctx.source_trust_label or tag_source(
        ctx.source_type,
        ctx.source_content,
        metadata=ctx.source_metadata,
    )

    capability_result = ctx.capability_result or classify_capabilities(ctx.tool_metadata)

    if ctx.metadata_validation_result is not None:
        metadata_result = ctx.metadata_validation_result
    elif ctx.old_snapshot is not None:
        metadata_result = validate_metadata(ctx.old_snapshot, ctx.tool_metadata)
    else:
        metadata_result = _default_metadata_validation()

    findings: list[str] = []
    reasons: list[str] = []

    findings.extend(capability_result.findings)
    findings.extend(metadata_result.findings)
    findings.append(f"Source trust label: {source_trust.value}.")

    detected_caps = set(capability_result.detected_capabilities)
    source_risk = _source_risk_label(source_trust)
    capability_risk = capability_result.risk_level
    metadata_risk = metadata_result.risk_level

    state = PolicyCompositionState(
        source_risk=source_risk,
        capability_risk=capability_risk,
        metadata_risk=metadata_risk,
        stage_results=[
            _policy_hard_block(detected_caps, metadata_risk),
            _policy_metadata(metadata_risk),
            _policy_source_trust(source_trust, source_risk, capability_risk, metadata_risk),
            _policy_capability(capability_risk),
        ],
    )

    action, composition_reasons = _compose_action(state.stage_results)
    reasons.extend(composition_reasons)

    aggregate_risk = _max_risk(capability_risk, metadata_risk, source_risk)

    # User authorization can only relax confirmation gates in v1.
    # It never overrides DENY or ESCALATE.
    if ctx.user_authorized and action == DecisionAction.REQUIRE_CONFIRMATION:
        action = DecisionAction.ALLOW
        reasons.append("User authorization relaxation policy: confirmation gate lifted.")

    requires_user_confirmation = action == DecisionAction.REQUIRE_CONFIRMATION

    module_recommendations = _module_recommendations(
        source_trust=source_trust,
        source_risk=source_risk,
        capability_result=capability_result,
        metadata_result=metadata_result,
    )

    decision_result = DecisionResult(
        decision_id=f"dec-{uuid4().hex}",
        action=action,
        risk_level=aggregate_risk,
        trust_label=source_trust,
        module_recommendations=module_recommendations,
        reasons=reasons,
        findings=findings,
        confidence=0.9,
        applied_policies=[
            "trust_tagger_v1",
            "capability_policy_v1",
            "metadata_validator_v1",
            "decision_engine_v1",
        ],
        required_controls=["explicit_user_confirmation"] if requires_user_confirmation else [],
        evidence={
            "source_trust_label": source_trust.value,
            "source_risk": source_risk.value,
            "capability_risk": capability_risk.value,
            "metadata_risk": metadata_risk.value,
            "detected_capabilities": sorted(detected_caps),
            "metadata_risk_level": metadata_result.risk_level.value,
            "metadata_changed_fields": metadata_result.changed_fields,
            "user_authorized": ctx.user_authorized,
            "policy_trace": [stage.model_dump(mode="json") for stage in state.stage_results],
        },
    )

    return EngineDecisionResult(
        action=action,
        risk_level=aggregate_risk,
        reasons=reasons,
        findings=findings,
        requires_user_confirmation=requires_user_confirmation,
        decision_result=decision_result,
    )

