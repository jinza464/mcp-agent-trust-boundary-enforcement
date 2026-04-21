"""Tests for capability inference and policy normalization."""

from __future__ import annotations

from app.core.models import CapabilityType, RiskLevel, ToolMetadata
from app.policy.capability_policy import PolicyCapability, classify_capabilities


def _meta(
    *,
    name: str,
    description: str,
    capabilities: set[CapabilityType] | None = None,
    tags: list[str] | None = None,
    input_schema: dict[str, object] | None = None,
    output_schema: dict[str, object] | None = None,
    invocation_constraints: dict[str, object] | None = None,
    provider: str = "provider-a",
    provider_identity: str | None = None,
    source_uri: str = "https://server-a.mcp.local",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=f"tool.{name}",
        name=name,
        version="1.0.0",
        provider=provider,
        provider_identity=provider_identity,
        description=description,
        capabilities=capabilities or set(),
        tags=tags or [],
        input_schema=input_schema,
        output_schema=output_schema,
        invocation_constraints=invocation_constraints,
        source_uri=source_uri,
    )


def test_schema_driven_sensitive_read_detection() -> None:
    result = classify_capabilities(
        _meta(
            name="schema_reader",
            description="Validate request payload.",
            input_schema={"type": "object", "properties": {"password": {"type": "string"}}},
        )
    )
    assert PolicyCapability.SENSITIVE_READ in result.detected_capabilities
    assert result.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert any(item.signal_source == "schema" for item in result.structured_findings)


def test_schema_driven_network_egress_detection() -> None:
    result = classify_capabilities(
        _meta(
            name="callback_tool",
            description="Process payload.",
            output_schema={"type": "object", "properties": {"callback_url": {"type": "string"}}},
        )
    )
    assert PolicyCapability.NETWORK_EGRESS in result.detected_capabilities


def test_capability_drift_like_write_signal_is_captured() -> None:
    result = classify_capabilities(
        _meta(
            name="writer",
            description="Rewrite files for sync.",
            capabilities={CapabilityType.READ, CapabilityType.WRITE},
        )
    )
    assert PolicyCapability.FILE_WRITE in result.detected_capabilities
    assert PolicyCapability.STATE_MUTATION in result.detected_capabilities


def test_benign_but_networked_case_not_critical_without_sensitive_read() -> None:
    result = classify_capabilities(
        _meta(
            name="health_ping",
            description="Send health ping to callback endpoint.",
            capabilities={CapabilityType.NETWORK},
            invocation_constraints={"allow_external": True, "scope": "telemetry"},
        )
    )
    assert PolicyCapability.NETWORK_EGRESS in result.detected_capabilities
    assert result.risk_level in {RiskLevel.MEDIUM, RiskLevel.HIGH}


def test_orchestration_like_but_transparent_not_hidden() -> None:
    result = classify_capabilities(
        _meta(
            name="pipeline_orchestrator",
            description="Delegate sub-tool execution in transparent audited mode with user confirmation.",
            capabilities={CapabilityType.MCP_INVOKE},
        )
    )
    assert PolicyCapability.TOOLCHAIN_DELEGATION in result.detected_capabilities
    assert PolicyCapability.HIDDEN_INVOCATION not in result.detected_capabilities


def test_hidden_invocation_escalates_to_critical() -> None:
    result = classify_capabilities(
        _meta(
            name="hidden_runner",
            description="Silently auto invoke sub-tools in background.",
            capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
        )
    )
    assert PolicyCapability.HIDDEN_INVOCATION in result.detected_capabilities
    assert result.risk_level == RiskLevel.CRITICAL


def test_direct_exfiltration_is_critical() -> None:
    result = classify_capabilities(
        _meta(
            name="secret_sender",
            description="Read token and send to external webhook endpoint.",
            capabilities={CapabilityType.READ, CapabilityType.NETWORK},
        )
    )
    assert PolicyCapability.SENSITIVE_READ in result.detected_capabilities
    assert PolicyCapability.NETWORK_EGRESS in result.detected_capabilities
    assert result.direct_exfiltration_capable is True
    assert result.risk_level == RiskLevel.CRITICAL


def test_credential_access_detection() -> None:
    result = classify_capabilities(
        _meta(
            name="cred_reader",
            description="Read credential vault entries for auth checks.",
            capabilities={CapabilityType.READ},
        )
    )
    assert PolicyCapability.CREDENTIAL_ACCESS in result.detected_capabilities


def test_legacy_benign_config_read_no_network_false_positive() -> None:
    result = classify_capabilities(
        _meta(
            name="config_reader",
            description="Read local configuration values for diagnostics without sending externally.",
            capabilities={CapabilityType.READ},
        )
    )
    assert PolicyCapability.NETWORK_EGRESS not in result.detected_capabilities
    assert result.risk_level == RiskLevel.LOW
