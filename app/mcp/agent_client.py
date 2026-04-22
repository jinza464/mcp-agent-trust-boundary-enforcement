"""Minimal MCP Agent prototype client with trust-boundary enforcement pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

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


class InvocationPlan(BaseModel):
    """Planned invocation representation before any execution happens."""

    model_config = ConfigDict(extra="forbid")

    invocation_id: str
    planned_action: str
    tool_name: str
    tool_version: str
    tool_source_uri: str | None = None
    user_query: str
    input_payload: dict[str, object] = Field(default_factory=dict)
    sink_metadata: dict[str, object] = Field(default_factory=dict)


class SimulatedToolOutput(BaseModel):
    """Mock execution artifact produced by prototype client execution."""

    model_config = ConfigDict(extra="forbid")

    output_type: str = "mock_tool_output"
    content: dict[str, object] = Field(default_factory=dict)
    artifacts: list[dict[str, object]] = Field(default_factory=list)
    generated_at: datetime


class FinalExecutionOutcome(BaseModel):
    """Explicit final runtime execution outcome after policy and sink gates."""

    model_config = ConfigDict(extra="forbid")

    status: str
    executed: bool
    blocked_by: str | None = None
    requires_user_confirmation: bool = False
    decision_layer_action: DecisionAction | None = None
    sink_layer_action: DecisionAction | None = None
    entered_execution_stage: bool = False
    completed_execution: bool = False
    execution_degraded: bool = False
    output_restricted: bool = False
    output_degraded: bool = False
    output_replaced: bool = False
    policy_gate_status: str = "unknown"
    sink_gate_status: str = "not_applicable"
    execution_started: bool = False
    execution_blocked: bool = False
    execution_completed: bool = False


class ExecutionTraceRecord(BaseModel):
    """Structured runtime trace record for audit and analysis."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    stage: str
    event: str
    details: dict[str, object] = Field(default_factory=dict)


# Backward-compatibility alias for earlier prototype naming.
TraceRecord = ExecutionTraceRecord


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
    invocation_plan: InvocationPlan | None = None
    simulated_tool_output: SimulatedToolOutput | None = None
    final_execution_outcome: FinalExecutionOutcome | None = None
    execution_started: bool = False
    execution_completed: bool = False
    entered_execution_stage: bool = False
    completed_execution: bool = False
    execution_degraded: bool = False
    output_restricted: bool = False
    output_degraded: bool = False
    output_replaced: bool = False
    final_status: str
    execution_trace_record: list[ExecutionTraceRecord] = Field(default_factory=list)
    execution_trace_records: list[ExecutionTraceRecord] = Field(default_factory=list)
    trace_records: list[ExecutionTraceRecord] = Field(default_factory=list)
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

    @staticmethod
    def _build_mock_output(tool: ToolMetadata, plan: InvocationPlan) -> SimulatedToolOutput:
        """Return deterministic mock output to make prototype execution semantics explicit."""
        return SimulatedToolOutput(
            generated_at=datetime.now(UTC),
            content={
                "tool_name": tool.name,
                "tool_version": tool.version,
                "planned_action": plan.planned_action,
                "result_summary": f"Mock execution completed for {tool.name}.",
                "echo_query": plan.user_query,
            },
            artifacts=[
                {
                    "artifact_type": "runtime_execution_record",
                    "artifact_id": f"artifact-{plan.invocation_id}",
                    "label": f"{tool.name}_execution_summary.json",
                }
            ],
        )

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
        trace_records: list[ExecutionTraceRecord] = []
        src_content = source_content if source_content is not None else user_query
        src_meta = source_metadata or {}
        sink_meta = sink_metadata or {}

        def add_trace(stage: str, event: str, **details: object) -> None:
            record = ExecutionTraceRecord(
                timestamp=datetime.now(UTC),
                stage=stage,
                event=event,
                details={str(k): v for k, v in details.items()},
            )
            trace_records.append(record)
            def _is_non_empty(value: object) -> bool:
                if value is None:
                    return False
                if isinstance(value, str):
                    return value != ""
                if isinstance(value, (list, dict, tuple, set)):
                    return len(value) > 0
                return True
            details_preview = ", ".join(
                f"{k}={v}" for k, v in record.details.items() if _is_non_empty(v)
            )
            logs.append(f"{record.stage}:{record.event}" + (f" [{details_preview}]" if details_preview else ""))

        def resolve_policy_gate(decision: EngineDecisionResult) -> tuple[str, str | None, bool]:
            if decision.action == DecisionAction.DENY:
                return "blocked_deny", "decision_layer", False
            if decision.action == DecisionAction.ESCALATE:
                return "blocked_escalate", "decision_layer", False
            if decision.requires_user_confirmation and not user_authorized:
                return "awaiting_confirmation", "decision_layer", True
            if decision.requires_user_confirmation and user_authorized:
                return "confirmed", None, False
            return "passed", None, False

        def resolve_sink_gate(sink: SinkInspectionResult | None) -> tuple[str, str | None, bool]:
            if sink is None:
                return "not_applicable", None, False
            if sink.action == DecisionAction.DENY:
                return "blocked_deny", "sink_layer", False
            if sink.requires_user_confirmation and not user_authorized:
                return "awaiting_confirmation", "sink_layer", True
            if sink.requires_user_confirmation and user_authorized:
                return "confirmed", None, False
            return "passed", None, False

        def resolve_final_status(policy_gate_status: str, sink_gate_status: str) -> tuple[str, str | None, bool, bool]:
            policy_blocked = policy_gate_status in {"blocked_deny", "blocked_escalate", "awaiting_confirmation"}
            sink_blocked = sink_gate_status in {"blocked_deny", "awaiting_confirmation"}
            if policy_blocked:
                if policy_gate_status == "blocked_escalate":
                    return "escalated_for_review", "decision_layer", False, False
                if policy_gate_status == "awaiting_confirmation":
                    return "awaiting_user_confirmation", "decision_layer", False, True
                return "blocked_by_decision", "decision_layer", False, False
            if sink_blocked:
                if sink_gate_status == "awaiting_confirmation":
                    return "awaiting_user_confirmation", "sink_layer", False, True
                return "blocked_by_sink", "sink_layer", False, False
            return "executed", None, True, False

        add_trace("runtime", "request_received", user_query=user_query)
        add_trace("tool_selection", "selection_started", preferred_tool_name=preferred_tool_name or "")
        tool = self.select_tool(user_query, preferred_tool_name=preferred_tool_name)
        if tool is None:
            raise ValueError("No tool available for selection.")
        add_trace("tool_selection", "selection_completed", selected_tool=tool.name, tool_id=tool.tool_id)

        add_trace("policy_evaluation", "trust_tagging_started", source_type=source_type)
        source_trust = tag_source(source_type, src_content, metadata=src_meta)
        add_trace("policy_evaluation", "trust_tagging_completed", source_trust_label=source_trust.value)

        add_trace("policy_evaluation", "capability_classification_started")
        capability_result = classify_capabilities(tool)
        add_trace(
            "policy_evaluation",
            "capability_classification_completed",
            detected_capabilities=list(capability_result.detected_capabilities),
            capability_risk=capability_result.risk_level.value,
        )

        old_snapshot = self.registry.get_tool_snapshot(tool.name, tool.source_uri or "unknown")
        add_trace("policy_evaluation", "metadata_validation_started", has_old_snapshot=old_snapshot is not None)
        metadata_result = validate_metadata(old_snapshot, tool) if old_snapshot else None
        add_trace(
            "policy_evaluation",
            "metadata_validation_completed",
            metadata_risk=metadata_result.risk_level.value if metadata_result else "none",
        )

        add_trace("policy_evaluation", "decision_engine_started")
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
        add_trace(
            "policy_evaluation",
            "decision_engine_completed",
            decision_action=decision_result.action.value,
            decision_risk=decision_result.risk_level.value,
            requires_user_confirmation=decision_result.requires_user_confirmation,
        )
        policy_gate_status, policy_blocked_by, _ = resolve_policy_gate(decision_result)
        add_trace(
            "policy_evaluation",
            "policy_gate_resolved",
            policy_gate_status=policy_gate_status,
            blocked_by=policy_blocked_by or "",
        )

        sink_result: SinkInspectionResult | None = None
        inferred_sink_type = self._infer_sink_type(capability_result)
        planned_action = (
            str(sink_meta.get("sink_type"))
            if sink_meta.get("sink_type")
            else (inferred_sink_type or "local_output")
        )
        plan = InvocationPlan(
            invocation_id=f"inv-{uuid4().hex}",
            planned_action=planned_action,
            tool_name=tool.name,
            tool_version=tool.version,
            tool_source_uri=tool.source_uri,
            user_query=user_query,
            input_payload={"query": user_query, "source_type": source_type},
            sink_metadata=dict(sink_meta),
        )
        add_trace("invocation_planning", "plan_created", invocation_id=plan.invocation_id, planned_action=plan.planned_action)

        if sink_payload is not None or inferred_sink_type is not None:
            merged_sink_meta = dict(sink_meta)
            if inferred_sink_type and "sink_type" not in merged_sink_meta:
                merged_sink_meta["sink_type"] = inferred_sink_type
            add_trace("sink_inspection", "sink_inspection_started", sink_type=str(merged_sink_meta.get("sink_type", "")))
            sink_result = inspect_sink(
                planned_action=merged_sink_meta.get("sink_type", "local_output"),
                payload=sink_payload if sink_payload is not None else {"query": user_query},
                metadata=merged_sink_meta,
            )
            add_trace(
                "sink_inspection",
                "sink_inspection_completed",
                sink_action=sink_result.action.value,
                sink_risk=sink_result.risk_level.value,
                endpoint_class=sink_result.endpoint_class,
                payload_sensitivity_class=sink_result.payload_sensitivity_class,
            )

        sink_gate_status, sink_blocked_by, _ = resolve_sink_gate(sink_result)
        add_trace(
            "sink_inspection",
            "sink_gate_resolved",
            sink_gate_status=sink_gate_status,
            blocked_by=sink_blocked_by or "",
        )
        final_status, blocked_by, executed, requires_confirmation = resolve_final_status(
            policy_gate_status=policy_gate_status,
            sink_gate_status=sink_gate_status,
        )
        add_trace(
            "execution_outcome",
            "final_status_resolved",
            final_status=final_status,
            blocked_by=blocked_by or "",
            policy_gate_status=policy_gate_status,
            sink_gate_status=sink_gate_status,
        )

        simulated_output: SimulatedToolOutput | None = None
        execution_started = executed
        execution_completed = executed
        entered_execution_stage = execution_started
        completed_execution = execution_completed
        output_restricted = decision_result.action in {DecisionAction.SANDBOX, DecisionAction.REDACT}
        output_degraded = output_restricted
        execution_degraded = output_degraded or (not execution_completed)
        output_replaced = not executed

        if executed:
            add_trace("mock_execution", "execution_started", invocation_id=plan.invocation_id, tool_name=tool.name)
            simulated_output = self._build_mock_output(tool, plan)
            if output_restricted:
                simulated_output.content["result_summary"] = "Mock execution completed with restricted output."
                simulated_output.content["output_restricted"] = True
                simulated_output.content["output_degraded"] = True
            add_trace(
                "mock_execution",
                "execution_completed",
                output_type=simulated_output.output_type,
                artifact_count=len(simulated_output.artifacts),
            )
        else:
            add_trace("mock_execution", "execution_not_started", blocked_by=blocked_by or "")

        outcome = FinalExecutionOutcome(
            status=final_status,
            executed=executed,
            blocked_by=blocked_by,
            requires_user_confirmation=requires_confirmation,
            decision_layer_action=decision_result.action,
            sink_layer_action=sink_result.action if sink_result else None,
            entered_execution_stage=entered_execution_stage,
            completed_execution=completed_execution,
            execution_degraded=execution_degraded,
            output_restricted=output_restricted,
            output_degraded=output_degraded,
            output_replaced=output_replaced,
            policy_gate_status=policy_gate_status,
            sink_gate_status=sink_gate_status,
            execution_started=execution_started,
            execution_blocked=not executed,
            execution_completed=execution_completed,
        )

        self.registry.register_tool(tool)
        add_trace("audit", "tool_snapshot_registered", tool_name=tool.name)

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
            invocation_plan=plan,
            simulated_tool_output=simulated_output,
            final_execution_outcome=outcome,
            execution_started=execution_started,
            execution_completed=execution_completed,
            entered_execution_stage=entered_execution_stage,
            completed_execution=completed_execution,
            execution_degraded=execution_degraded,
            output_restricted=output_restricted,
            output_degraded=output_degraded,
            output_replaced=output_replaced,
            final_status=final_status,
            execution_trace_record=trace_records,
            execution_trace_records=trace_records,
            trace_records=trace_records,
            logs=logs,
        )
