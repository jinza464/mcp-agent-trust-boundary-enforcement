"""Rule-based Decision Engine for client-side trust boundary enforcement.

Phase-1 revision goals:
- preserve the currently validated v2 baseline semantics
- reduce ambiguity between stage-local advice and final enforcement
- strengthen structured evidence for downstream analysis and audit
"""

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
from app.policy.capability_policy import CapabilityClassificationResult, classify_capabilities
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import MetadataValidationResult, validate_metadata


class DecisionContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_metadata: ToolMetadata = Field(...)
    source_trust_label: TrustLabel | None = Field(default=None)
    source_type: str = Field(default="external_document")
    source_content: str = Field(default="")
    source_metadata: dict[str, object] = Field(default_factory=dict)
    capability_result: CapabilityClassificationResult | None = Field(default=None)
    metadata_validation_result: MetadataValidationResult | None = Field(default=None)
    old_snapshot: ToolSnapshot | None = Field(default=None)
    user_authorized: bool = Field(default=False)


class EngineDecisionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: DecisionAction = Field(...)
    risk_level: RiskLevel = Field(...)
    reasons: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    requires_user_confirmation: bool = Field(default=False)
    decision_result: DecisionResult = Field(...)


class PolicyStageResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: str = Field(...)
    rule_tag: str | None = Field(default=None)
    proposed_action: DecisionAction = Field(...)
    risk_level: RiskLevel = Field(...)
    triggered: bool = Field(...)
    reasons: list[str] = Field(default_factory=list)
    advisory_only: bool = Field(default=False)


class PolicyCompositionState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_risk: RiskLevel
    capability_risk: RiskLevel
    metadata_risk: RiskLevel
    stage_results: list[PolicyStageResult] = Field(default_factory=list)


class RuleNode(BaseModel):
    """Structured evidence node for one rule/stage evaluation."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(...)
    stage: str = Field(...)
    triggered: bool = Field(...)
    severity: RiskLevel = Field(...)
    proposed_action: DecisionAction = Field(...)
    reasons: list[str] = Field(default_factory=list)
    children: list["RuleNode"] = Field(default_factory=list)


class DecisionEvidenceTree(BaseModel):
    """Structured decision evidence tree for explainability/export."""

    model_config = ConfigDict(extra="forbid")

    root_action: DecisionAction = Field(...)
    aggregate_risk: RiskLevel = Field(...)
    nodes: list[RuleNode] = Field(default_factory=list)


RuleNode.model_rebuild()


def _risk_rank(level: RiskLevel) -> int:
    return {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}[level]


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


def _default_metadata_validation() -> MetadataValidationResult:
    return MetadataValidationResult(
        passed=True,
        findings=[],
        risk_level=RiskLevel.LOW,
        recommended_action=DecisionAction.ALLOW,
        changed_fields=[],
        change_categories=[],
        drift_domains=[],
        structured_findings=[],
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
            evidence={"detected_capabilities": sorted({item.value for item in capability_result.detected_capabilities})},
        ),
        ModuleAssessmentResult(
            module_name="metadata_validator",
            recommendation=_recommendation_from_risk(metadata_result.risk_level),
            risk_level=metadata_result.risk_level,
            reasons=["Metadata validator risk evaluation result."],
            findings=metadata_result.findings,
            evidence={
                "changed_fields": metadata_result.changed_fields,
                "change_categories": metadata_result.change_categories,
            },
        ),
    ]


def _policy_hard_block(detected_caps: set[str], metadata_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW
    risk = RiskLevel.LOW
    rule_tag = "hard_block:not_triggered"
    if "hidden_invocation" in detected_caps:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        rule_tag = "hard_block:hidden_invocation"
        reasons.append("Hidden invocation capability triggers hard block.")
    elif "read_secret" in detected_caps and "network_send" in detected_caps:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        rule_tag = "hard_block:direct_exfiltration_combo"
        reasons.append("Read-secret + network-send combination triggers hard block.")
    elif metadata_risk == RiskLevel.CRITICAL:
        triggered = True
        proposed = DecisionAction.DENY
        risk = RiskLevel.CRITICAL
        rule_tag = "hard_block:critical_metadata_drift"
        reasons.append("Metadata validator marked update as critical risk.")
    return PolicyStageResult(
        stage="hard_block_policy",
        rule_tag=rule_tag,
        proposed_action=proposed,
        risk_level=risk,
        triggered=triggered,
        reasons=reasons,
    )


def _policy_metadata(metadata_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW
    advisory_only = False
    rule_tag = "metadata:low_risk_or_no_drift"
    if metadata_risk == RiskLevel.HIGH:
        triggered = True
        proposed = DecisionAction.REQUIRE_CONFIRMATION
        rule_tag = "metadata:high_risk_drift"
        reasons.append("High metadata risk requires explicit confirmation.")
    elif metadata_risk == RiskLevel.MEDIUM:
        triggered = True
        proposed = DecisionAction.SANDBOX
        advisory_only = True
        rule_tag = "metadata:medium_risk_advisory"
        reasons.append("Medium metadata risk suggests sandboxing (advisory in v2 baseline unless reinforced).")
    return PolicyStageResult(
        stage="metadata_policy",
        rule_tag=rule_tag,
        proposed_action=proposed,
        risk_level=metadata_risk,
        triggered=triggered,
        reasons=reasons,
        advisory_only=advisory_only,
    )


def _policy_source_trust(source_trust: TrustLabel, source_risk: RiskLevel, capability_risk: RiskLevel, metadata_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW
    rule_tag = "source_trust:no_escalation"
    if source_trust == TrustLabel.UNTRUSTED and _max_risk(source_risk, capability_risk, metadata_risk) in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}:
        triggered = True
        proposed = DecisionAction.ESCALATE
        rule_tag = "source_trust:untrusted_non_low_risk"
        reasons.append("Untrusted source with non-low risk requires escalation.")
    return PolicyStageResult(
        stage="source_trust_policy",
        rule_tag=rule_tag,
        proposed_action=proposed,
        risk_level=source_risk,
        triggered=triggered,
        reasons=reasons,
    )


def _policy_capability(capability_risk: RiskLevel) -> PolicyStageResult:
    reasons: list[str] = []
    triggered = False
    proposed = DecisionAction.ALLOW
    advisory_only = False
    rule_tag = "capability:low_risk_or_no_gate"
    if capability_risk == RiskLevel.HIGH:
        triggered = True
        proposed = DecisionAction.REQUIRE_CONFIRMATION
        rule_tag = "capability:high_risk_confirmation"
        reasons.append("High capability risk requires explicit confirmation.")
    elif capability_risk == RiskLevel.MEDIUM:
        triggered = True
        proposed = DecisionAction.SANDBOX
        advisory_only = True
        rule_tag = "capability:medium_risk_advisory"
        reasons.append("Medium capability risk suggests sandboxing (advisory in v2 baseline unless reinforced).")
    return PolicyStageResult(
        stage="capability_policy",
        rule_tag=rule_tag,
        proposed_action=proposed,
        risk_level=capability_risk,
        triggered=triggered,
        reasons=reasons,
        advisory_only=advisory_only,
    )


def _compose_action(stage_results: list[PolicyStageResult]) -> tuple[DecisionAction, list[str]]:
    stage_map = {item.stage: item for item in stage_results}
    hard_block = stage_map["hard_block_policy"]
    if hard_block.triggered:
        return DecisionAction.DENY, hard_block.reasons or ["Hard-block policy triggered."]

    metadata_stage = stage_map["metadata_policy"]
    if metadata_stage.proposed_action == DecisionAction.REQUIRE_CONFIRMATION:
        return DecisionAction.REQUIRE_CONFIRMATION, metadata_stage.reasons

    source_stage = stage_map["source_trust_policy"]
    capability_stage = stage_map["capability_policy"]
    if source_stage.triggered:
        return DecisionAction.ESCALATE, source_stage.reasons
    if capability_stage.proposed_action == DecisionAction.REQUIRE_CONFIRMATION:
        return DecisionAction.REQUIRE_CONFIRMATION, capability_stage.reasons

    metadata_medium = metadata_stage.proposed_action == DecisionAction.SANDBOX
    capability_medium = capability_stage.proposed_action == DecisionAction.SANDBOX
    reasons: list[str] = []
    if metadata_medium and capability_medium and source_stage.risk_level == RiskLevel.LOW:
        reasons.extend(metadata_stage.reasons)
        reasons.extend(capability_stage.reasons)
        reasons.append("Reinforced medium-risk signals from metadata and capability policies; sandbox enforced.")
        return DecisionAction.SANDBOX, reasons

    if metadata_medium or capability_medium:
        reasons.extend(metadata_stage.reasons if metadata_medium else [])
        reasons.extend(capability_stage.reasons if capability_medium else [])
        reasons.append("Medium-risk signals recorded as advisory; no sandbox enforcement in v2 baseline.")
        return DecisionAction.ALLOW, reasons

    return DecisionAction.ALLOW, ["No blocking risk signal detected under current policy rules."]


def _rule_id_from_stage(stage: PolicyStageResult) -> str:
    if stage.rule_tag:
        return stage.rule_tag

    if stage.stage == "hard_block_policy":
        joined = " ".join(stage.reasons).lower()
        if "hidden invocation" in joined:
            return "hard_block:hidden_invocation"
        if "read-secret + network-send" in joined:
            return "hard_block:direct_exfiltration_combo"
        if "critical risk" in joined:
            return "hard_block:critical_metadata_drift"
        return "hard_block:not_triggered"
    if stage.stage == "metadata_policy":
        if stage.proposed_action == DecisionAction.REQUIRE_CONFIRMATION:
            return "metadata:high_risk_drift"
        if stage.proposed_action == DecisionAction.SANDBOX:
            return "metadata:medium_risk_advisory"
        return "metadata:low_risk_or_no_drift"
    if stage.stage == "source_trust_policy":
        if stage.triggered:
            return "source_trust:untrusted_non_low_risk"
        return "source_trust:no_escalation"
    if stage.stage == "capability_policy":
        if stage.proposed_action == DecisionAction.REQUIRE_CONFIRMATION:
            return "capability:high_risk_confirmation"
        if stage.proposed_action == DecisionAction.SANDBOX:
            return "capability:medium_risk_advisory"
        return "capability:low_risk_or_no_gate"
    return f"rule:{stage.stage}"


def _build_rule_node_from_stage(stage: PolicyStageResult) -> RuleNode:
    return RuleNode(
        rule_id=_rule_id_from_stage(stage),
        stage=stage.stage,
        triggered=stage.triggered,
        severity=stage.risk_level,
        proposed_action=stage.proposed_action,
        reasons=stage.reasons,
    )


def _evaluate_dual_medium_rule(stage_results: list[PolicyStageResult]) -> RuleNode:
    stage_map = {item.stage: item for item in stage_results}
    metadata_stage = stage_map["metadata_policy"]
    source_stage = stage_map["source_trust_policy"]
    capability_stage = stage_map["capability_policy"]
    metadata_medium = metadata_stage.proposed_action == DecisionAction.SANDBOX
    capability_medium = capability_stage.proposed_action == DecisionAction.SANDBOX
    source_low = source_stage.risk_level == RiskLevel.LOW

    if metadata_medium and capability_medium and source_low:
        return RuleNode(
            rule_id="aggregation:dual_medium_to_sandbox",
            stage="aggregation_policy",
            triggered=True,
            severity=RiskLevel.MEDIUM,
            proposed_action=DecisionAction.SANDBOX,
            reasons=[
                *metadata_stage.reasons,
                *capability_stage.reasons,
                "Reinforced medium-risk signals from metadata and capability policies; sandbox enforced.",
            ],
        )

    if metadata_medium or capability_medium:
        return RuleNode(
            rule_id="aggregation:dual_medium_to_sandbox",
            stage="aggregation_policy",
            triggered=False,
            severity=RiskLevel.MEDIUM,
            proposed_action=DecisionAction.ALLOW,
            reasons=[
                *(metadata_stage.reasons if metadata_medium else []),
                *(capability_stage.reasons if capability_medium else []),
                "Medium-risk signals recorded as advisory; no sandbox enforcement in v2 baseline.",
            ],
        )

    return RuleNode(
        rule_id="aggregation:dual_medium_to_sandbox",
        stage="aggregation_policy",
        triggered=False,
        severity=RiskLevel.LOW,
        proposed_action=DecisionAction.ALLOW,
        reasons=["No reinforced dual-medium pattern detected."],
    )


def _build_decision_evidence_tree(
    *,
    state: PolicyCompositionState,
    action: DecisionAction,
    aggregate_risk: RiskLevel,
    reasons: list[str],
    pre_authorization_action: DecisionAction,
    user_authorization_lifted: bool,
) -> DecisionEvidenceTree:
    stage_nodes = [_build_rule_node_from_stage(stage) for stage in state.stage_results]
    dual_medium_node = _evaluate_dual_medium_rule(state.stage_results)
    authorization_node = RuleNode(
        rule_id="aggregation:user_authorization_lift",
        stage="authorization_policy",
        triggered=user_authorization_lifted,
        severity=aggregate_risk,
        proposed_action=action,
        reasons=(
            [
                (
                    f"User authorization lifted decision action from "
                    f"{pre_authorization_action.value} to {action.value}; "
                    f"aggregate risk remains {aggregate_risk.value}."
                )
            ]
            if user_authorization_lifted
            else ["No authorization-based action lifting applied."]
        ),
    )
    final_aggregation_node = RuleNode(
        rule_id="aggregation:final_action",
        stage="final_aggregation",
        triggered=True,
        severity=aggregate_risk,
        proposed_action=action,
        reasons=reasons,
        children=[*stage_nodes, dual_medium_node, authorization_node],
    )
    return DecisionEvidenceTree(
        root_action=action,
        aggregate_risk=aggregate_risk,
        nodes=[*stage_nodes, dual_medium_node, authorization_node, final_aggregation_node],
    )


def decide(context: DecisionContext | dict) -> EngineDecisionResult:
    ctx = context if isinstance(context, DecisionContext) else DecisionContext.model_validate(context)
    source_trust = ctx.source_trust_label or tag_source(ctx.source_type, ctx.source_content, metadata=ctx.source_metadata)
    capability_result = ctx.capability_result or classify_capabilities(ctx.tool_metadata)
    if ctx.metadata_validation_result is not None:
        metadata_result = ctx.metadata_validation_result
    elif ctx.old_snapshot is not None:
        metadata_result = validate_metadata(ctx.old_snapshot, ctx.tool_metadata)
    else:
        metadata_result = _default_metadata_validation()

    findings = [*capability_result.findings, *metadata_result.findings, f"Source trust label: {source_trust.value}."]
    detected_caps = {item.value for item in capability_result.detected_capabilities}
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
    action, reasons = _compose_action(state.stage_results)
    pre_authorization_action = action
    aggregate_risk = _max_risk(capability_risk, metadata_risk, source_risk)
    user_authorization_lifted = False

    if ctx.user_authorized and action == DecisionAction.REQUIRE_CONFIRMATION:
        action = DecisionAction.ALLOW
        reasons = [*reasons, "User authorization relaxation policy: confirmation gate lifted."]
        user_authorization_lifted = True

    requires_user_confirmation = action == DecisionAction.REQUIRE_CONFIRMATION
    decision_evidence_tree = _build_decision_evidence_tree(
        state=state,
        action=action,
        aggregate_risk=aggregate_risk,
        reasons=reasons,
        pre_authorization_action=pre_authorization_action,
        user_authorization_lifted=user_authorization_lifted,
    )
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
            "trust_tagger_v2_kernel",
            "capability_policy_v2_kernel",
            "metadata_validator_v2_kernel",
            "decision_engine_v2_kernel",
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
            "metadata_change_categories": metadata_result.change_categories,
            "user_authorized": ctx.user_authorized,
            "pre_authorization_action": pre_authorization_action.value,
            "user_authorization_lifted": user_authorization_lifted,
            "policy_trace": [stage.model_dump(mode="json") for stage in state.stage_results],
            "evidence_tree": decision_evidence_tree.model_dump(mode="json"),
            "decision_evidence_tree": decision_evidence_tree.model_dump(mode="json"),
            "final_action_source": action.value,
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
