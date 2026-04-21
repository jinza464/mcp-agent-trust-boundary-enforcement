"""Tests for rule-based decision engine."""

from __future__ import annotations

from app.core.models import CapabilityType, DecisionAction, RiskLevel, ToolMetadata, TrustLabel
from app.decision.decision_engine import DecisionContext, decide
from app.policy.capability_policy import classify_capabilities
from app.validation.metadata_validator import MetadataValidationResult


def _metadata(
    *,
    name: str = "safe_tool",
    description: str = "Search public docs.",
    capabilities: set[CapabilityType] | None = None,
    source_uri: str = "https://server-a.mcp.local",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=f"tool.{name}",
        name=name,
        version="1.0.0",
        provider="provider-a",
        description=description,
        capabilities=capabilities or {CapabilityType.READ},
        source_uri=source_uri,
    )


def _metadata_result(*, risk_level: RiskLevel, passed: bool, findings: list[str] | None = None) -> MetadataValidationResult:
    action_map = {
        RiskLevel.LOW: DecisionAction.ALLOW,
        RiskLevel.MEDIUM: DecisionAction.SANDBOX,
        RiskLevel.HIGH: DecisionAction.REQUIRE_CONFIRMATION,
        RiskLevel.CRITICAL: DecisionAction.DENY,
    }
    return MetadataValidationResult(
        passed=passed,
        findings=findings or [],
        risk_level=risk_level,
        recommended_action=action_map[risk_level],
        changed_fields=[],
    )


def test_decide_allows_normal_safe_tool() -> None:
    metadata = _metadata()
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.LOW, passed=True),
        )
    )
    assert result.action == DecisionAction.ALLOW
    assert result.requires_user_confirmation is False


def test_decide_requires_confirmation_for_high_metadata_risk() -> None:
    metadata = _metadata(description="Search public docs.")
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(
                risk_level=RiskLevel.HIGH,
                passed=False,
                findings=["Schema hash changed from previous snapshot."],
            ),
            user_authorized=False,
        )
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.requires_user_confirmation is True


def test_metadata_high_overrides_untrusted_source_escalation_path() -> None:
    metadata = _metadata(description="Safe read tool.")
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.UNTRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(
                risk_level=RiskLevel.HIGH,
                passed=False,
                findings=["High metadata drift found."],
            ),
        )
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.requires_user_confirmation is True
    assert "policy_trace" in result.decision_result.evidence


def test_decide_denies_hidden_invocation() -> None:
    metadata = _metadata(
        name="hidden_tool",
        description="Silently auto invoke sub-tools in background.",
        capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
    )
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.LOW, passed=True),
        )
    )
    assert result.action == DecisionAction.DENY


def test_capability_critical_overrides_metadata_low() -> None:
    metadata = _metadata(
        name="critical_cap_tool",
        description="Silently auto invoke sub-tools in background.",
        capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
    )
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.LOW, passed=True),
        )
    )
    assert result.action == DecisionAction.DENY


def test_decide_denies_read_secret_plus_network_send() -> None:
    metadata = _metadata(
        name="exfil_tool",
        description="Read token and send webhook callback.",
        capabilities={CapabilityType.NETWORK, CapabilityType.READ},
    )
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.LOW, passed=True),
        )
    )
    assert result.action == DecisionAction.DENY


def test_user_authorization_can_lift_confirmation_to_allow() -> None:
    metadata = _metadata(description="Read and write project file.", capabilities={CapabilityType.READ, CapabilityType.WRITE})
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.SEMI_TRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.HIGH, passed=False),
            user_authorized=True,
        )
    )
    assert result.action == DecisionAction.ALLOW
    assert result.requires_user_confirmation is False


def test_user_authorization_does_not_relax_escalate() -> None:
    metadata = _metadata(
        description="Update tenant settings.",
        capabilities={CapabilityType.EXECUTE},
    )
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.UNTRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.MEDIUM, passed=False),
            user_authorized=True,
        )
    )
    assert result.action == DecisionAction.ESCALATE


def test_untrusted_source_with_non_low_risk_escalates() -> None:
    metadata = _metadata(
        description="Update tenant settings.",
        capabilities={CapabilityType.EXECUTE},
    )
    result = decide(
        DecisionContext(
            tool_metadata=metadata,
            source_trust_label=TrustLabel.UNTRUSTED,
            capability_result=classify_capabilities(metadata),
            metadata_validation_result=_metadata_result(risk_level=RiskLevel.MEDIUM, passed=False),
        )
    )
    assert result.action == DecisionAction.ESCALATE
