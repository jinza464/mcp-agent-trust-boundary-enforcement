"""Tests for rule-based capability policy classification."""

from __future__ import annotations

from app.core.models import CapabilityType, RiskLevel, ToolMetadata
from app.policy.capability_policy import classify_capabilities


def _meta(
    *,
    name: str,
    description: str,
    capabilities: set[CapabilityType] | None = None,
    tags: list[str] | None = None,
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=f"tool.{name}",
        name=name,
        version="1.0.0",
        provider="test-provider",
        description=description,
        capabilities=capabilities or set(),
        tags=tags or [],
    )


def test_benign_read_classification() -> None:
    result = classify_capabilities(
        _meta(
            name="doc_search",
            description="Search and list public documentation.",
            capabilities={CapabilityType.READ},
        )
    )
    assert "benign_read" in result.detected_capabilities
    assert result.risk_level == RiskLevel.LOW


def test_read_secret_classification() -> None:
    result = classify_capabilities(
        _meta(name="secret_reader", description="Read API key and password from .env")
    )
    assert "read_secret" in result.detected_capabilities
    assert result.risk_level == RiskLevel.HIGH


def test_file_write_classification() -> None:
    result = classify_capabilities(
        _meta(
            name="file_writer",
            description="Write and overwrite local report files.",
            capabilities={CapabilityType.WRITE},
        )
    )
    assert "file_write" in result.detected_capabilities
    assert result.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}


def test_network_send_classification() -> None:
    result = classify_capabilities(
        _meta(
            name="webhook_sender",
            description="Send webhook callback to external endpoint.",
            capabilities={CapabilityType.NETWORK},
        )
    )
    assert "network_send" in result.detected_capabilities
    assert result.risk_level == RiskLevel.HIGH


def test_state_change_classification() -> None:
    result = classify_capabilities(
        _meta(
            name="setting_updater",
            description="Update and configure tenant settings.",
            capabilities={CapabilityType.EXECUTE},
        )
    )
    assert "state_change" in result.detected_capabilities
    assert result.risk_level == RiskLevel.MEDIUM


def test_hidden_invocation_classification() -> None:
    result = classify_capabilities(
        _meta(
            name="background_invoker",
            description="Silently auto invoke sub-tools in background without user confirmation.",
            capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
        )
    )
    assert "hidden_invocation" in result.detected_capabilities
    assert result.risk_level == RiskLevel.CRITICAL


def test_secret_plus_network_escalates_to_critical() -> None:
    result = classify_capabilities(
        _meta(
            name="secret_exfil",
            description="Read token and send to webhook endpoint.",
            capabilities={CapabilityType.NETWORK},
        )
    )
    assert "read_secret" in result.detected_capabilities
    assert "network_send" in result.detected_capabilities
    assert result.risk_level == RiskLevel.CRITICAL


def test_schema_tag_can_trigger_secret_detection() -> None:
    result = classify_capabilities(
        _meta(
            name="schema_driven_tool",
            description="Validate request payload.",
            tags=['schema: {"properties":{"password":{"type":"string"}}}'],
        )
    )
    assert "read_secret" in result.detected_capabilities
    assert result.risk_level == RiskLevel.HIGH


def test_no_signal_defaults_to_low() -> None:
    result = classify_capabilities(
        _meta(name="plain_tool", description="Render markdown text.")
    )
    assert result.detected_capabilities == []
    assert result.risk_level == RiskLevel.LOW
