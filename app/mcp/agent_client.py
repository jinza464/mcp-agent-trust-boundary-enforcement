"""Minimal MCP Agent prototype client with trust-boundary enforcement pipeline."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, ToolMetadata, TrustLabel
from app.decision.decision_engine import DecisionContext, EngineDecisionResult, decide
from app.policy.capability_policy import CapabilityClassificationResult, classify_capabilities
from app.registry.tool_registry import ToolRegistry
from app.sink.sink_guard import SinkInspectionResult, inspect_sink
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import MetadataValidationResult, validate_metadata


class SelectedToolInfo(BaseModel):
    """Selected tool descriptor returned by the prototype client."""

    model_config = ConfigDict(extra="forbid")

    tool_id: str
    name: str
    version: str
    source_uri: str | None = None


class AgentExecutionResult(BaseModel):
    """Structured execution result for one user request."""

    model_config = ConfigDict(extra="forbid")

    user_query: str
    selected_tool: SelectedToolInfo | None = None
    source_trust_label: TrustLabel
    capability_result: CapabilityClassificationResult | None = None
    metadata_validation_result: MetadataValidationResult | None = None
    decision_result: EngineDecisionResult
    sink_result: SinkInspectionResult | None = None
    final_status: str
    logs: list[str] = Field(default_factory=list)


def default_mock_tools() -> list[ToolMetadata]:
    """Return minimal local mock metadata set for prototype runs."""
    return [
        ToolMetadata(
            tool_id="tool.docs.search",
            name="docs_search",
            version="1.0.0",
            provider="local-mock",
            description="Search public documentation.",
            source_uri="https://server-a.mcp.local",
        ),
        ToolMetadata(
            tool_id="tool.agent.hidden",
            name="agent_hidden",
            version="1.0.0",
            provider="local-mock",
            description="Silently auto invoke sub-tools in background without user confirmation.",
            source_uri="https://server-a.mcp.local",
        ),
        ToolMetadata(
            tool_id="tool.data.export",
            name="data_export",
            version="1.0.0",
            provider="local-mock",
            description="Read token and send webhook callback to external endpoint.",
            source_uri="https://server-a.mcp.local",
        ),
    ]


class MCPAgentClient:
    """Client-side MCP agent prototype wired with trust-boundary enforcement controls."""

    def __init__(self, tools: list[ToolMetadata] | None = None) -> None:
        self.registry = ToolRegistry()
        self._tools: list[ToolMetadata] = tools or default_mock_tools()

    def load_tools(self, tools: list[ToolMetadata]) -> None:
        """Replace current local tool metadata list."""
        self._tools = list(tools)

    def seed_tool_snapshot(self, metadata: ToolMetadata) -> None:
        """Seed registry baseline for metadata drift/rug-pull simulation."""
        self.registry.register_tool(metadata)

    def select_tool(self, user_query: str, preferred_tool_name: str | None = None) -> ToolMetadata | None:
        """Select tool by explicit name first, otherwise simple keyword match."""
        if preferred_tool_name:
            for tool in self._tools:
                if tool.name == preferred_tool_name:
                    return tool

        query = user_query.lower()
        best: ToolMetadata | None = None
        best_score = -1
        for tool in self._tools:
            score = 0
            name_tokens = tool.name.lower().replace("_", " ").split()
            score += sum(2 for token in name_tokens if token in query)
            score += sum(1 for token in tool.description.lower().split() if token in query)
            if score > best_score:
                best_score = score
                best = tool
        return best

    @staticmethod
    def _infer_sink_type(capability_result: CapabilityClassificationResult) -> str | None:
        caps = set(capability_result.detected_capabilities)
        if "network_send" in caps:
            return "network_send"
        if "file_write" in caps:
            return "file_write"
        if "read_secret" in caps:
            return "secret_read"
        if "state_change" in caps:
            return "state_change"
        return None

    def handle_query(
        self,
        user_query: str,
        *,
        preferred_tool_name: str | None = None,
        source_type: str = "user_query",
        source_content: str | None = None,
        source_metadata: dict[str, object] | None = None,
        user_authorized: bool = False,
        sink_payload: dict | str | None = None,
        sink_metadata: dict[str, object] | None = None,
    ) -> AgentExecutionResult:
        """Execute one request with full trust-boundary enforcement chain."""
        logs: list[str] = []
        src_content = source_content if source_content is not None else user_query
        src_meta = source_metadata or {}
        sink_meta = sink_metadata or {}

        tool = self.select_tool(user_query, preferred_tool_name=preferred_tool_name)
        if tool is None:
            raise ValueError("No tool available for selection.")
        logs.append(f"selected_tool={tool.name}")

        source_trust = tag_source(source_type, src_content, metadata=src_meta)
        logs.append(f"source_trust={source_trust.value}")

        capability_result = classify_capabilities(tool)
        logs.append(f"capabilities={capability_result.detected_capabilities}")

        old_snapshot = self.registry.get_tool_snapshot(tool.name, tool.source_uri or "unknown")
        metadata_result = validate_metadata(old_snapshot, tool) if old_snapshot else None
        logs.append("metadata_validation=executed" if old_snapshot else "metadata_validation=skipped_no_baseline")

        decision_result = decide(
            DecisionContext(
                tool_metadata=tool,
                source_trust_label=source_trust,
                source_type=source_type,
                source_content=src_content,
                source_metadata=src_meta,
                capability_result=capability_result,
                metadata_validation_result=metadata_result,
                old_snapshot=old_snapshot,
                user_authorized=user_authorized,
            )
        )
        logs.append(
            f"decision={decision_result.action.value},risk={decision_result.risk_level.value}"
        )

        sink_result: SinkInspectionResult | None = None
        inferred_sink_type = self._infer_sink_type(capability_result)
        if sink_payload is not None or inferred_sink_type is not None:
            merged_sink_meta = dict(sink_meta)
            if inferred_sink_type and "sink_type" not in merged_sink_meta:
                merged_sink_meta["sink_type"] = inferred_sink_type
            sink_result = inspect_sink(
                planned_action=merged_sink_meta.get("sink_type", "local_output"),
                payload=sink_payload if sink_payload is not None else {"query": user_query},
                metadata=merged_sink_meta,
            )
            logs.append(
                f"sink={sink_result.action.value},sink_risk={sink_result.risk_level.value}"
            )

        if decision_result.action == DecisionAction.DENY:
            final_status = "blocked_by_decision"
        elif decision_result.action == DecisionAction.ESCALATE:
            final_status = "escalated_for_review"
        elif decision_result.requires_user_confirmation and not user_authorized:
            final_status = "awaiting_user_confirmation"
        elif sink_result and sink_result.action == DecisionAction.DENY:
            final_status = "blocked_by_sink"
        elif sink_result and sink_result.requires_user_confirmation and not user_authorized:
            final_status = "awaiting_user_confirmation"
        else:
            final_status = "executed"
        logs.append(f"final_status={final_status}")

        self.registry.register_tool(tool)

        return AgentExecutionResult(
            user_query=user_query,
            selected_tool=SelectedToolInfo(
                tool_id=tool.tool_id,
                name=tool.name,
                version=tool.version,
                source_uri=tool.source_uri,
            ),
            source_trust_label=source_trust,
            capability_result=capability_result,
            metadata_validation_result=metadata_result,
            decision_result=decision_result,
            sink_result=sink_result,
            final_status=final_status,
            logs=logs,
        )
