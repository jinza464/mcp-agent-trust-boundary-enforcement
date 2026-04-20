"""Rule-based Decision Engine for client-side trust boundary enforcement."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import (
    DecisionAction,
    DecisionResult,
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


def _default_metadata_validation() -> MetadataValidationResult:
    return MetadataValidationResult(
        passed=True,
        findings=[],
        risk_level=RiskLevel.LOW,
        recommended_action=DecisionAction.ALLOW,
        changed_fields=[],
    )


def decide(context: DecisionContext | dict) -> EngineDecisionResult:
    """Make an allow/intercept/escalate/deny decision using explicit deterministic rules."""
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

    hard_block = (
        "hidden_invocation" in detected_caps
        or ("read_secret" in detected_caps and "network_send" in detected_caps)
    )

    aggregate_risk = _max_risk(
        capability_result.risk_level,
        metadata_result.risk_level,
        _source_risk_label(source_trust),
    )

    # Primary deterministic policy
    if hard_block:
        action = DecisionAction.DENY
        reasons.append("Hard-block rule triggered by critical capability pattern.")
    elif metadata_result.risk_level == RiskLevel.CRITICAL:
        action = DecisionAction.DENY
        reasons.append("Metadata validation marked this update as critical risk.")
    elif metadata_result.risk_level == RiskLevel.HIGH:
        action = DecisionAction.REQUIRE_CONFIRMATION
        reasons.append("High-risk metadata change requires explicit user confirmation.")
    elif (
        source_trust == TrustLabel.UNTRUSTED
        and aggregate_risk in {RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL}
    ):
        action = DecisionAction.ESCALATE
        reasons.append("Untrusted source combined with non-low risk requires escalation.")
    elif aggregate_risk == RiskLevel.HIGH:
        action = DecisionAction.REQUIRE_CONFIRMATION
        reasons.append("High aggregate risk requires explicit user confirmation.")
    else:
        action = DecisionAction.ALLOW
        reasons.append("No blocking risk signal detected under current policy rules.")

    # User authorization can only relax confirmation gates in v1.
    # It never overrides DENY or ESCALATE.
    if ctx.user_authorized and action == DecisionAction.REQUIRE_CONFIRMATION:
        action = DecisionAction.ALLOW
        reasons.append("User explicitly authorized this operation; confirmation gate lifted.")

    requires_user_confirmation = action == DecisionAction.REQUIRE_CONFIRMATION

    decision_result = DecisionResult(
        decision_id=f"dec-{uuid4().hex}",
        action=action,
        risk_level=aggregate_risk,
        trust_label=source_trust,
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
            "detected_capabilities": sorted(detected_caps),
            "metadata_risk_level": metadata_result.risk_level.value,
            "metadata_changed_fields": metadata_result.changed_fields,
            "user_authorized": ctx.user_authorized,
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


