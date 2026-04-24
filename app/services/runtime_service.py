from __future__ import annotations

from app.core.models import ToolMetadata
from app.mcp.agent_client import AgentExecutionResult, MCPAgentClient
from app.mcp.protocol_models import McpRequestEnvelope


class RuntimeService:
    """Thin service wrapper around the prototype MCP runtime."""

    def __init__(self, client: MCPAgentClient | None = None) -> None:
        # Keep default construction for backward compatibility while allowing
        # lifespan/app.state to inject a shared client instance.
        self.client = client or MCPAgentClient()

    def list_registered_tools(self) -> list[ToolMetadata]:
        """Return tool metadata through MCPAgentClient's public interface."""
        return self.client.list_registered_tools()

    def list_tools(self) -> list[dict[str, object]]:
        return [
            {
                "tool_id": tool.tool_id,
                "name": tool.name,
                "version": tool.version,
                "provider": tool.provider,
                "source_uri": tool.source_uri,
            }
            for tool in self.list_registered_tools()
        ]

    def handle_query(self, **kwargs: object) -> AgentExecutionResult:
        return self.client.handle_query(**kwargs)

    def handle_mcp_request(self, envelope: McpRequestEnvelope) -> AgentExecutionResult:
        return self.client.handle_mcp_request(envelope)
