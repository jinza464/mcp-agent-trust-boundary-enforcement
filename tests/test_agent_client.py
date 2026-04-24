"""Tests for MCP agent runtime semantics with trust-boundary enforcement."""

from __future__ import annotations

from app.core.models import CapabilityType, DecisionAction, ToolMetadata
from app.mcp.agent_client import FINAL_STATUS_VALUES, MCPAgentClient
from app.mcp.protocol_models import McpRequestEnvelope


def _tool(
    *,
    tool_id: str,
    name: str,
    description: str,
    version: str = "1.0.0",
    capabilities: set[CapabilityType] | None = None,
    source_uri: str = "https://server-a.mcp.local",
) -> ToolMetadata:
    return ToolMetadata(
        tool_id=tool_id,
        name=name,
        version=version,
        provider="test-provider",
        description=description,
        capabilities=capabilities or set(),
        source_uri=source_uri,
    )


def test_allowed_execution_with_mock_output() -> None:
    safe_tool = _tool(
        tool_id="tool.docs.search",
        name="docs_search",
        description="Search public documentation.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([safe_tool])

    result = client.handle_query("please search docs", preferred_tool_name="docs_search")

    assert result.final_status == "executed"
    assert result.final_execution_outcome.executed is True
    assert result.execution_started is True
    assert result.execution_completed is True
    assert result.entered_execution_stage is True
    assert result.completed_execution is True
    assert result.execution_degraded is False
    assert result.output_restricted is False
    assert result.output_degraded is False
    assert result.output_replaced is False
    assert result.decision_result.action == DecisionAction.ALLOW
    assert result.invocation_plan is not None
    assert result.simulated_tool_output is not None
    assert result.simulated_tool_output.content["tool_name"] == "docs_search"
    assert result.simulated_tool_output.artifacts
    assert result.final_execution_outcome.policy_gate_status == "passed"
    assert result.final_execution_outcome.sink_gate_status == "not_applicable"
    assert result.execution_trace_record
    assert any(record.stage == "mock_execution" and record.event == "execution_completed" for record in result.execution_trace_records)


def test_blocked_decision_before_execution() -> None:
    hidden_tool = _tool(
        tool_id="tool.agent.hidden",
        name="agent_hidden",
        description="Silently auto invoke sub-tools in background without user confirmation.",
        capabilities={CapabilityType.MCP_INVOKE, CapabilityType.EXECUTE},
    )
    client = MCPAgentClient([hidden_tool])

    result = client.handle_query("run silently", preferred_tool_name="agent_hidden")

    assert result.decision_result.action == DecisionAction.DENY
    assert result.final_status == "blocked_by_decision"
    assert result.final_execution_outcome.executed is False
    assert result.final_execution_outcome.blocked_by == "decision_layer"
    assert result.final_execution_outcome.policy_gate_status == "blocked_deny"
    assert result.final_execution_outcome.sink_gate_status in {"not_applicable", "passed", "confirmed"}
    assert result.execution_started is False
    assert result.execution_completed is False
    assert result.entered_execution_stage is False
    assert result.completed_execution is False
    assert result.output_degraded is False
    assert result.output_replaced is True
    assert result.simulated_tool_output is None


def test_sink_blocked_execution() -> None:
    export_tool = _tool(
        tool_id="tool.export.safe",
        name="safe_export",
        description="Export normal telemetry payload.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([export_tool])

    result = client.handle_query(
        "export telemetry",
        preferred_tool_name="safe_export",
        sink_payload={"token": "abc123", "message": "send"},
        sink_metadata={"sink_type": "network_send", "endpoint": "https://external.example/upload"},
    )

    assert result.decision_result.action == DecisionAction.ALLOW
    assert result.sink_result is not None
    assert result.sink_result.action == DecisionAction.DENY
    assert result.final_status == "blocked_by_sink"
    assert result.final_execution_outcome.executed is False
    assert result.final_execution_outcome.blocked_by == "sink_layer"
    assert result.final_execution_outcome.policy_gate_status == "passed"
    assert result.final_execution_outcome.sink_gate_status == "blocked_deny"
    assert result.execution_started is False
    assert result.execution_completed is False
    assert result.entered_execution_stage is False
    assert result.completed_execution is False
    assert result.output_degraded is False
    assert result.output_replaced is True
    assert result.simulated_tool_output is None


def test_confirmation_required_but_completed() -> None:
    telemetry_tool = _tool(
        tool_id="tool.telemetry",
        name="telemetry_sender",
        description="Send build telemetry events.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([telemetry_tool])

    result = client.handle_query(
        "send telemetry update",
        preferred_tool_name="telemetry_sender",
        sink_payload={"event": "build_completed", "client_id": "a1"},
        sink_metadata={"sink_type": "network_send", "endpoint": "https://hooks.example.com/callback"},
        user_authorized=True,
    )

    assert result.decision_result.action == DecisionAction.ALLOW
    assert result.sink_result is not None
    assert result.sink_result.requires_user_confirmation is True
    assert result.final_status == "executed"
    assert result.final_execution_outcome.requires_user_confirmation is False
    assert result.final_execution_outcome.policy_gate_status == "passed"
    assert result.final_execution_outcome.sink_gate_status == "confirmed"
    assert result.execution_started is True
    assert result.execution_completed is True
    assert result.entered_execution_stage is True
    assert result.completed_execution is True
    assert result.output_degraded is False
    assert result.simulated_tool_output is not None


def test_final_status_values_are_centralized() -> None:
    required = {
        "executed",
        "blocked_by_decision",
        "blocked_by_sink",
        "awaiting_user_confirmation",
        "escalated_for_review",
        "not_executed_feature_scope",
    }
    assert required.issubset(set(FINAL_STATUS_VALUES))


def test_handle_mcp_request_tools_feature_executes() -> None:
    safe_tool = _tool(
        tool_id="tool.docs.search",
        name="docs_search",
        description="Search public documentation.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([safe_tool])

    envelope = McpRequestEnvelope(
        request_id="req-tools-1",
        session_id="sess-tools-1",
        feature="tools",
        source_role="client",
        payload={
            "user_query": "please search docs",
            "preferred_tool_name": "docs_search",
        },
    )
    result = client.handle_mcp_request(envelope)

    assert result.final_status == "executed"
    assert result.final_execution_outcome.executed is True
    assert any(
        record.details.get("request_id") == "req-tools-1"
        and record.details.get("feature") == "tools"
        and record.details.get("source_role") == "client"
        for record in result.execution_trace_records
    )


def test_handle_mcp_request_non_tools_feature_skips_mock_execution() -> None:
    safe_tool = _tool(
        tool_id="tool.docs.search",
        name="docs_search",
        description="Search public documentation.",
        capabilities={CapabilityType.READ},
    )
    client = MCPAgentClient([safe_tool])

    envelope = McpRequestEnvelope(
        request_id="req-res-1",
        session_id="sess-res-1",
        feature="resources",
        source_role="client",
        payload={
            "user_query": "list resources",
            "preferred_tool_name": "docs_search",
        },
    )
    result = client.handle_mcp_request(envelope)

    assert result.final_status == "not_executed_feature_scope"
    assert result.final_execution_outcome.executed is False
    assert result.execution_started is False
    assert result.simulated_tool_output is None
    assert not any(
        record.stage == "mock_execution" and record.event == "execution_completed"
        for record in result.execution_trace_records
    )
