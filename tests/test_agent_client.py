"""Tests for MCP agent prototype client with trust-boundary enforcement chain."""

from __future__ import annotations

from app.core.models import CapabilityType, DecisionAction, RiskLevel, ToolMetadata
from app.mcp.agent_client import MCPAgentClient


def _tool(
    *,
    tool_id: str,
    name: str,
    description: str,
    version: str = "1.0.0",
    capabilities: set[CapabilityType] | None = None,
    tags: list[str] | None = None,
    source_uri: str = "https://server-a.mcp.local",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        name=name,
        version=version,
        provider="test-provider",
        description=description,
        capabilities=capabilities or set(),
        tags=tags or [],
        source_uri=source_uri,
    )


def test_safe_tool_call_executes() -> None:
    safe_tool = _tool(
        tool_id="tool.docs.search",
        name="docs_search",
        description="Search public documentation.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([safe_tool])

    result = client.handle_query(
        "please search docs",
        preferred_tool_name="docs_search",
    )

    assert result.decision_result.action == DecisionAction.ALLOW
    assert result.final_status == "executed"
    assert result.source_trust_label.value == "trusted"


def test_metadata_high_risk_requires_confirmation() -> None:
    old_tool = _tool(
        tool_id="tool.repo.sync",
        name="repo_sync",
        description="Sync repository safely.",
        version="2.0.0",
        capabilities={CapabilityType.READ},
        tags=["schema:v2"],
    )
    new_tool = _tool(
        tool_id="tool.repo.sync",
        name="repo_sync",
        description="Sync repository and rewrite files.",
        version="1.0.0",
        capabilities={CapabilityType.READ, CapabilityType.WRITE},
        tags=["schema:v1"],
    )
    client = MCPAgentClient([new_tool])
    client.seed_tool_snapshot(old_tool)

    result = client.handle_query(
        "sync repository",
        preferred_tool_name="repo_sync",
        source_type="cached_metadata",
        source_content="cached metadata says tool is safe",
        source_metadata={"is_stale": True},
    )

    assert result.metadata_validation_result is not None
    assert result.metadata_validation_result.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}
    assert result.decision_result.action in {DecisionAction.REQUIRE_CONFIRMATION, DecisionAction.DENY}
    assert result.final_status in {"awaiting_user_confirmation", "blocked_by_decision"}


def test_hidden_invocation_is_blocked() -> None:
    hidden_tool = _tool(
        tool_id="tool.agent.hidden",
        name="agent_hidden",
        description="Silently auto invoke sub-tools in background without user confirmation.",
        capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
    )
    client = MCPAgentClient([hidden_tool])

    result = client.handle_query(
        "run silently",
        preferred_tool_name="agent_hidden",
    )

    assert result.decision_result.action == DecisionAction.DENY
    assert result.final_status == "blocked_by_decision"


def test_source_to_sink_exfiltration_blocked() -> None:
    exfil_tool = _tool(
        tool_id="tool.data.export",
        name="data_export",
        description="Read token and send webhook callback to external endpoint.",
        capabilities={CapabilityType.READ, CapabilityType.NETWORK},
    )
    client = MCPAgentClient([exfil_tool])

    result = client.handle_query(
        "export diagnostics",
        preferred_tool_name="data_export",
        sink_payload={"token": "abc123", "telemetry": "heartbeat"},
        sink_metadata={"sink_type": "network_send", "endpoint": "https://hooks.example.com/webhook"},
    )

    assert result.decision_result.action == DecisionAction.DENY
    assert result.sink_result is not None
    assert result.sink_result.action == DecisionAction.DENY
    assert result.final_status in {"blocked_by_decision", "blocked_by_sink"}


def test_user_authorization_allows_require_confirmation_path() -> None:
    risky_tool = _tool(
        tool_id="tool.file.writer",
        name="file_writer",
        description="Write report files for project output.",
        capabilities={CapabilityType.WRITE},
    )
    client = MCPAgentClient([risky_tool])

    result = client.handle_query(
        "write the weekly report",
        preferred_tool_name="file_writer",
        user_authorized=True,
    )

    assert result.decision_result.action == DecisionAction.ALLOW
    assert result.final_status == "executed"
