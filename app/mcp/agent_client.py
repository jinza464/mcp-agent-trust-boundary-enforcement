"""Minimal MCP Agent prototype client with trust-boundary enforcement pipeline."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Callable, Literal, TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, ToolMetadata, ToolSnapshot, TrustLabel
from app.decision.decision_engine import DecisionContext, EngineDecisionResult, decide
from app.mcp.protocol_models import McpRequestEnvelope, RequestLineage
from app.policy.capability_policy import CapabilityClassificationResult, classify_capabilities
from app.registry.tool_registry import ToolRegistry
from app.sink.sink_guard import SinkInspectionResult, inspect_sink
from app.tagging.trust_tagger import tag_source
from app.validation.metadata_validator import MetadataValidationResult, validate_metadata

# Centralized final status values for runtime compatibility and traceability.
FinalStatus: TypeAlias = Literal[
    "executed",
    "blocked_by_decision",
    "blocked_by_sink",
    "awaiting_user_confirmation",
    "escalated_for_review",
    "not_executed_feature_scope",
]
FINAL_STATUS_VALUES: tuple[FinalStatus, ...] = (
    "executed",
    "blocked_by_decision",
    "blocked_by_sink",
    "awaiting_user_confirmation",
    "escalated_for_review",
    "not_executed_feature_scope",
)
FINAL_STATUS_EXECUTED: FinalStatus = "executed"
FINAL_STATUS_BLOCKED_BY_DECISION: FinalStatus = "blocked_by_decision"
FINAL_STATUS_BLOCKED_BY_SINK: FinalStatus = "blocked_by_sink"
FINAL_STATUS_AWAITING_USER_CONFIRMATION: FinalStatus = "awaiting_user_confirmation"
FINAL_STATUS_ESCALATED_FOR_REVIEW: FinalStatus = "escalated_for_review"
FINAL_STATUS_NOT_EXECUTED_FEATURE_SCOPE: FinalStatus = "not_executed_feature_scope"


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

    status: FinalStatus
    executed: bool
    blocked_by: str | None = None
    requires_user_confirmation: bool = False
    decision_layer_action: DecisionAction | None = None
    sink_layer_action: DecisionAction | None = None

    policy_gate_status: str = "unknown"
    sink_gate_status: str = "not_applicable"

    entered_execution_stage: bool = False
    execution_started: bool = False
    execution_blocked: bool = False
    execution_completed: bool = False

    completed_execution: bool = False
    execution_degraded: bool = False
    output_restricted: bool = False
    output_degraded: bool = False
    output_replaced: bool = False


class ExecutionTraceRecord(BaseModel):
    """Structured runtime trace record for audit and analysis."""

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime
    stage: str
    event: str
    details: dict[str, object] = Field(default_factory=dict)


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
    final_execution_outcome: FinalExecutionOutcome

    execution_started: bool = False
    execution_completed: bool = False
    entered_execution_stage: bool = False
    completed_execution: bool = False
    execution_degraded: bool = False
    output_restricted: bool = False
    output_degraded: bool = False
    output_replaced: bool = False

    final_status: FinalStatus
    execution_trace_record: list[ExecutionTraceRecord] = Field(default_factory=list)
    execution_trace_records: list[ExecutionTraceRecord] = Field(default_factory=list)
    trace_records: list[ExecutionTraceRecord] = Field(default_factory=list)
    logs: list[str] = Field(default_factory=list)


class RequestRuntimeContext(BaseModel):
    """Normalized request context shared by stage methods."""

    model_config = ConfigDict(extra="forbid")

    envelope: McpRequestEnvelope
    request_lineage: RequestLineage
    user_query: str
    preferred_tool_name: str | None = None
    source_type: str = "user_query"
    source_content: str
    source_metadata: dict[str, object] = Field(
        default_factory=dict,
        description="Protocol payload boundary object for source-side hints consumed by trust/policy modules.",
    )
    sink_payload: dict[str, object] | str | None = Field(
        default=None,
        description="Protocol payload boundary object/string passed to sink inspection and mock execution planning.",
    )
    sink_metadata: dict[str, object] = Field(
        default_factory=dict,
        description="Protocol payload boundary object for sink-routing hints (sink_type/endpoint/allowlist/etc.).",
    )
    user_authorized: bool = False
    selected_tool: ToolMetadata


class PolicyEvaluationBundle(BaseModel):
    """Policy-stage outputs carried into sink/runtime stages."""

    model_config = ConfigDict(extra="forbid")

    source_trust_label: TrustLabel
    capability_result: CapabilityClassificationResult
    metadata_validation_result: MetadataValidationResult | None = None
    decision_result: EngineDecisionResult
    old_snapshot: ToolSnapshot | None = None
    policy_gate_status: str
    policy_blocked_by: str | None = None
    policy_requires_confirmation: bool = False
    request_lineage: RequestLineage


class SinkEvaluationBundle(BaseModel):
    """Sink-stage outputs carried into runtime/finalization stages."""

    model_config = ConfigDict(extra="forbid")

    sink_result: SinkInspectionResult | None = None
    inferred_sink_type: str | None = None
    planned_action: str = "local_output"
    sink_gate_status: str = "not_applicable"
    sink_blocked_by: str | None = None


class MockExecutionBundle(BaseModel):
    """Mock runtime execution stage outputs."""

    model_config = ConfigDict(extra="forbid")

    invocation_plan: InvocationPlan
    simulated_tool_output: SimulatedToolOutput | None = None
    executed: bool
    entered_execution_stage: bool
    execution_started: bool


class FinalizationBundle(BaseModel):
    """Final status and execution flags projected to public result model."""

    model_config = ConfigDict(extra="forbid")

    final_status: FinalStatus
    final_execution_outcome: FinalExecutionOutcome
    simulated_tool_output: SimulatedToolOutput | None = None
    execution_started: bool
    execution_completed: bool
    entered_execution_stage: bool
    completed_execution: bool
    execution_degraded: bool
    output_restricted: bool
    output_degraded: bool
    output_replaced: bool


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
        self._tools: list[ToolMetadata] = list(tools or default_mock_tools())

    def load_tools(self, tools: list[ToolMetadata]) -> None:
        """Replace current local tool metadata list."""
        self._tools = list(tools)

    def list_registered_tools(self) -> list[ToolMetadata]:
        """Return a read-only snapshot of loaded tool metadata."""
        return [tool.model_copy(deep=True) for tool in self._tools]

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
        detected = {str(item) for item in capability_result.detected_capabilities}
        if "PolicyCapability.NETWORK_EGRESS" in detected or "network_send" in detected:
            return "network_send"
        if "PolicyCapability.FILE_WRITE" in detected or "file_write" in detected:
            return "file_write"
        if "PolicyCapability.SENSITIVE_READ" in detected or "read_secret" in detected:
            return "secret_read"
        if "PolicyCapability.CREDENTIAL_ACCESS" in detected or "credential_access" in detected:
            return "credential_access"
        if "PolicyCapability.STATE_MUTATION" in detected or "state_change" in detected:
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

    @staticmethod
    def _resolve_policy_gate(
        decision: EngineDecisionResult,
        *,
        user_authorized: bool,
    ) -> tuple[str, str | None, bool]:
        if decision.action == DecisionAction.DENY:
            return "blocked_deny", "decision_layer", False
        if decision.action == DecisionAction.ESCALATE:
            return "blocked_escalate", "decision_layer", False
        if decision.requires_user_confirmation and not user_authorized:
            return "awaiting_confirmation", "decision_layer", True
        if decision.requires_user_confirmation and user_authorized:
            return "confirmed", None, False
        return "passed", None, False

    @staticmethod
    def _resolve_sink_gate(
        sink: SinkInspectionResult | None,
        *,
        user_authorized: bool,
    ) -> tuple[str, str | None, bool]:
        if sink is None:
            return "not_applicable", None, False
        if sink.action == DecisionAction.DENY:
            return "blocked_deny", "sink_layer", False
        if sink.requires_user_confirmation and not user_authorized:
            return "awaiting_confirmation", "sink_layer", True
        if sink.requires_user_confirmation and user_authorized:
            return "confirmed", None, False
        return "passed", None, False

    @staticmethod
    def _as_object_dict(value: object) -> dict[str, object]:
        if not isinstance(value, dict):
            return {}
        return {str(key): item for key, item in value.items()}

    @staticmethod
    def _as_optional_string(value: object) -> str | None:
        if not isinstance(value, str):
            return None
        text = value.strip()
        return text or None

    @classmethod
    def _derive_root_user_request_id(cls, envelope: McpRequestEnvelope) -> str:
        payload_root = cls._as_optional_string(envelope.payload.get("root_user_request_id"))
        if payload_root:
            return payload_root
        payload_lineage_root = cls._as_optional_string(envelope.payload.get("lineage_root_request_id"))
        if payload_lineage_root:
            return payload_lineage_root
        if envelope.parent_request_id:
            return envelope.parent_request_id
        return envelope.request_id

    def build_request_context(
        self,
        envelope: McpRequestEnvelope,
        *,
        add_trace: Callable[..., None],
    ) -> RequestRuntimeContext:
        """Normalize envelope payload into a typed runtime context and select tool."""
        payload = envelope.payload
        user_query_raw = payload.get("user_query")
        user_query = str(user_query_raw) if user_query_raw is not None else ""
        if not user_query:
            raise ValueError("MCP request payload must include non-empty user_query.")

        preferred_tool_name = self._as_optional_string(payload.get("preferred_tool_name"))
        source_type = str(payload.get("source_type")) if payload.get("source_type") is not None else "user_query"
        source_content_raw = payload.get("source_content")
        source_content = str(source_content_raw) if source_content_raw is not None else user_query

        source_metadata = self._as_object_dict(payload.get("source_metadata"))
        sink_metadata = self._as_object_dict(payload.get("sink_metadata"))
        user_authorized = bool(payload.get("user_authorized", False))

        sink_payload_raw = payload.get("sink_payload")
        sink_payload: dict[str, object] | str | None
        if sink_payload_raw is None or isinstance(sink_payload_raw, str):
            sink_payload = sink_payload_raw
        elif isinstance(sink_payload_raw, dict):
            sink_payload = {str(key): item for key, item in sink_payload_raw.items()}
        else:
            sink_payload = str(sink_payload_raw)

        root_user_request_id = self._derive_root_user_request_id(envelope)
        lineage_kwargs: dict[str, object] = {
            "request_id": envelope.request_id,
            "parent_request_id": envelope.parent_request_id,
            "root_user_request_id": root_user_request_id,
            "source_role": envelope.source_role,
            "feature": envelope.feature,
            "trust_label": TrustLabel.UNKNOWN,
        }
        # Keep construction aligned with protocol_models.RequestLineage real fields.
        if "session_id" in RequestLineage.model_fields:
            lineage_kwargs["session_id"] = envelope.session_id
        if "server_origin" in RequestLineage.model_fields:
            lineage_kwargs["server_origin"] = envelope.server_origin
        request_lineage = RequestLineage.model_validate(lineage_kwargs)

        add_trace("runtime", "request_received", user_query=user_query)
        add_trace("tool_selection", "selection_started", preferred_tool_name=preferred_tool_name or "")
        tool = self.select_tool(user_query, preferred_tool_name=preferred_tool_name)
        if tool is None:
            raise ValueError("No tool available for selection.")
        add_trace("tool_selection", "selection_completed", selected_tool=tool.name, tool_id=tool.tool_id)

        return RequestRuntimeContext(
            envelope=envelope,
            request_lineage=request_lineage,
            user_query=user_query,
            preferred_tool_name=preferred_tool_name,
            source_type=source_type,
            source_content=source_content,
            source_metadata=source_metadata,
            sink_payload=sink_payload,
            sink_metadata=sink_metadata,
            user_authorized=user_authorized,
            selected_tool=tool,
        )

    def evaluate_policy(
        self,
        context: RequestRuntimeContext,
        *,
        add_trace: Callable[..., None],
    ) -> PolicyEvaluationBundle:
        """Run trust/capability/metadata/decision stages and return policy bundle."""
        add_trace("policy_evaluation", "trust_tagging_started", source_type=context.source_type)
        source_trust = tag_source(context.source_type, context.source_content, metadata=context.source_metadata)
        add_trace("policy_evaluation", "trust_tagging_completed", source_trust_label=source_trust.value)

        add_trace("policy_evaluation", "capability_classification_started")
        capability_result = classify_capabilities(context.selected_tool)
        add_trace(
            "policy_evaluation",
            "capability_classification_completed",
            detected_capabilities=[str(item) for item in capability_result.detected_capabilities],
            capability_risk=capability_result.risk_level.value,
        )

        old_snapshot = self.registry.get_tool_snapshot(context.selected_tool.name, context.selected_tool.source_uri or "unknown")
        add_trace("policy_evaluation", "metadata_validation_started", has_old_snapshot=old_snapshot is not None)
        metadata_result = validate_metadata(old_snapshot, context.selected_tool) if old_snapshot else None
        add_trace(
            "policy_evaluation",
            "metadata_validation_completed",
            metadata_risk=metadata_result.risk_level.value if metadata_result else "none",
        )

        add_trace("policy_evaluation", "decision_engine_started")
        decision_result = decide(
            DecisionContext(
                tool_metadata=context.selected_tool,
                source_trust_label=source_trust,
                source_type=context.source_type,
                source_content=context.source_content,
                source_metadata=context.source_metadata,
                capability_result=capability_result,
                metadata_validation_result=metadata_result,
                old_snapshot=old_snapshot,
                user_authorized=context.user_authorized,
            )
        )
        add_trace(
            "policy_evaluation",
            "decision_engine_completed",
            decision_action=decision_result.action.value,
            decision_risk=decision_result.risk_level.value,
            requires_user_confirmation=decision_result.requires_user_confirmation,
        )

        policy_gate_status, policy_blocked_by, policy_requires_confirmation = self._resolve_policy_gate(
            decision_result,
            user_authorized=context.user_authorized,
        )
        add_trace(
            "policy_evaluation",
            "policy_gate_resolved",
            policy_gate_status=policy_gate_status,
            blocked_by=policy_blocked_by or "",
        )

        enriched_lineage = context.request_lineage.model_copy(update={"trust_label": source_trust})
        return PolicyEvaluationBundle(
            source_trust_label=source_trust,
            capability_result=capability_result,
            metadata_validation_result=metadata_result,
            decision_result=decision_result,
            old_snapshot=old_snapshot,
            policy_gate_status=policy_gate_status,
            policy_blocked_by=policy_blocked_by,
            policy_requires_confirmation=policy_requires_confirmation,
            request_lineage=enriched_lineage,
        )

    def evaluate_sink(
        self,
        context: RequestRuntimeContext,
        policy_bundle: PolicyEvaluationBundle,
        *,
        add_trace: Callable[..., None],
    ) -> SinkEvaluationBundle:
        """Run sink inspection for sink-relevant requests and return sink bundle."""
        inferred_sink_type = self._infer_sink_type(policy_bundle.capability_result)
        planned_action = (
            str(context.sink_metadata.get("sink_type"))
            if context.sink_metadata.get("sink_type")
            else (inferred_sink_type or "local_output")
        )

        if context.envelope.feature != "tools":
            add_trace(
                "sink_inspection",
                "sink_inspection_skipped",
                reason="feature_without_sink_runtime",
                feature=context.envelope.feature,
                recognized_feature=True,
                sink_semantics_supported=False,
            )
            add_trace(
                "sink_inspection",
                "sink_gate_resolved",
                sink_gate_status="not_applicable",
                blocked_by="",
                feature=context.envelope.feature,
                note="recognized_feature_but_sink_semantics_not_executed_in_current_prototype",
            )
            return SinkEvaluationBundle(
                sink_result=None,
                inferred_sink_type=inferred_sink_type,
                planned_action=planned_action,
                sink_gate_status="not_applicable",
                sink_blocked_by=None,
            )

        sink_result: SinkInspectionResult | None = None
        policy_hard_blocked = policy_bundle.policy_gate_status in {"blocked_deny", "blocked_escalate"}
        if not policy_hard_blocked and (context.sink_payload is not None or inferred_sink_type is not None):
            merged_sink_meta = dict(context.sink_metadata)
            if inferred_sink_type and "sink_type" not in merged_sink_meta:
                merged_sink_meta["sink_type"] = inferred_sink_type
            add_trace("sink_inspection", "sink_inspection_started", sink_type=str(merged_sink_meta.get("sink_type", "")))
            sink_result = inspect_sink(
                planned_action=merged_sink_meta.get("sink_type", "local_output"),
                payload=context.sink_payload if context.sink_payload is not None else {"query": context.user_query},
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
            sink_gate_status, sink_blocked_by, _ = self._resolve_sink_gate(
                sink_result,
                user_authorized=context.user_authorized,
            )
        else:
            sink_gate_status = "not_applicable"
            sink_blocked_by = None
            add_trace(
                "sink_inspection",
                "sink_inspection_skipped",
                reason="policy_hard_block" if policy_hard_blocked else "no_sink_path",
            )

        add_trace(
            "sink_inspection",
            "sink_gate_resolved",
            sink_gate_status=sink_gate_status,
            blocked_by=sink_blocked_by or "",
        )
        return SinkEvaluationBundle(
            sink_result=sink_result,
            inferred_sink_type=inferred_sink_type,
            planned_action=planned_action,
            sink_gate_status=sink_gate_status,
            sink_blocked_by=sink_blocked_by,
        )

    def execute_mock_runtime(
        self,
        context: RequestRuntimeContext,
        policy_bundle: PolicyEvaluationBundle,
        sink_bundle: SinkEvaluationBundle,
        *,
        add_trace: Callable[..., None],
    ) -> MockExecutionBundle:
        """Create invocation plan and execute mock runtime only after gate results are known."""
        plan = InvocationPlan(
            invocation_id=f"inv-{uuid4().hex}",
            planned_action=sink_bundle.planned_action,
            tool_name=context.selected_tool.name,
            tool_version=context.selected_tool.version,
            tool_source_uri=context.selected_tool.source_uri,
            user_query=context.user_query,
            input_payload={"query": context.user_query, "source_type": context.source_type},
            sink_metadata=dict(context.sink_metadata),
        )
        add_trace("invocation_planning", "plan_created", invocation_id=plan.invocation_id, planned_action=plan.planned_action)

        if context.envelope.feature != "tools":
            add_trace(
                "mock_execution",
                "execution_not_started",
                blocked_by="feature_scope",
                feature=context.envelope.feature,
                reason="recognized_feature_but_mock_runtime_executes_tools_only",
            )
            return MockExecutionBundle(
                invocation_plan=plan,
                simulated_tool_output=None,
                executed=False,
                entered_execution_stage=False,
                execution_started=False,
            )

        policy_blocked = policy_bundle.policy_gate_status in {"blocked_deny", "blocked_escalate", "awaiting_confirmation"}
        sink_blocked = sink_bundle.sink_gate_status in {"blocked_deny", "awaiting_confirmation"}
        executed = not policy_blocked and not sink_blocked
        entered_execution_stage = executed
        execution_started = executed

        simulated_output: SimulatedToolOutput | None = None
        if executed:
            add_trace("mock_execution", "execution_started", invocation_id=plan.invocation_id, tool_name=context.selected_tool.name)
            simulated_output = self._build_mock_output(context.selected_tool, plan)
            add_trace(
                "mock_execution",
                "execution_completed",
                output_type=simulated_output.output_type,
                artifact_count=len(simulated_output.artifacts),
            )
        else:
            blocked_by = "decision_layer" if policy_blocked else ("sink_layer" if sink_blocked else "")
            add_trace("mock_execution", "execution_not_started", blocked_by=blocked_by)

        return MockExecutionBundle(
            invocation_plan=plan,
            simulated_tool_output=simulated_output,
            executed=executed,
            entered_execution_stage=entered_execution_stage,
            execution_started=execution_started,
        )

    def finalize_outcome(
        self,
        context: RequestRuntimeContext,
        policy_bundle: PolicyEvaluationBundle,
        sink_bundle: SinkEvaluationBundle,
        execution_bundle: MockExecutionBundle,
        *,
        add_trace: Callable[..., None],
    ) -> FinalizationBundle:
        """Assemble final status, outcome flags, and output degradation/restriction semantics."""
        policy_gate_status = policy_bundle.policy_gate_status
        sink_gate_status = sink_bundle.sink_gate_status

        policy_blocked = policy_gate_status in {"blocked_deny", "blocked_escalate", "awaiting_confirmation"}
        sink_blocked = sink_gate_status in {"blocked_deny", "awaiting_confirmation"}

        if policy_blocked:
            if policy_gate_status == "blocked_escalate":
                final_status = FINAL_STATUS_ESCALATED_FOR_REVIEW
                blocked_by = "decision_layer"
                executed = False
                requires_confirmation = False
            elif policy_gate_status == "awaiting_confirmation":
                final_status = FINAL_STATUS_AWAITING_USER_CONFIRMATION
                blocked_by = "decision_layer"
                executed = False
                requires_confirmation = True
            else:
                final_status = FINAL_STATUS_BLOCKED_BY_DECISION
                blocked_by = "decision_layer"
                executed = False
                requires_confirmation = False
        elif sink_blocked:
            if sink_gate_status == "awaiting_confirmation":
                final_status = FINAL_STATUS_AWAITING_USER_CONFIRMATION
                blocked_by = "sink_layer"
                executed = False
                requires_confirmation = True
            else:
                final_status = FINAL_STATUS_BLOCKED_BY_SINK
                blocked_by = "sink_layer"
                executed = False
                requires_confirmation = False
        else:
            executed = execution_bundle.executed
            final_status = FINAL_STATUS_EXECUTED if executed else FINAL_STATUS_NOT_EXECUTED_FEATURE_SCOPE
            blocked_by = None
            requires_confirmation = False

        add_trace(
            "execution_outcome",
            "final_status_resolved",
            final_status=final_status,
            blocked_by=blocked_by or "",
            policy_gate_status=policy_gate_status,
            sink_gate_status=sink_gate_status,
        )

        simulated_output = execution_bundle.simulated_tool_output
        entered_execution_stage = execution_bundle.entered_execution_stage
        execution_started = execution_bundle.execution_started
        execution_completed = executed
        completed_execution = executed
        output_restricted = executed and policy_bundle.decision_result.action in {DecisionAction.SANDBOX, DecisionAction.REDACT}
        output_degraded = output_restricted
        execution_degraded = (not executed) or output_restricted
        output_replaced = not executed

        if simulated_output is not None and output_restricted:
            simulated_output.content["result_summary"] = "Mock execution completed with restricted output."
            simulated_output.content["output_restricted"] = True
            simulated_output.content["output_degraded"] = True

        outcome = FinalExecutionOutcome(
            status=final_status,
            executed=executed,
            blocked_by=blocked_by,
            requires_user_confirmation=requires_confirmation,
            decision_layer_action=policy_bundle.decision_result.action,
            sink_layer_action=sink_bundle.sink_result.action if sink_bundle.sink_result else None,
            policy_gate_status=policy_gate_status,
            sink_gate_status=sink_gate_status,
            entered_execution_stage=entered_execution_stage,
            execution_started=execution_started,
            execution_blocked=not executed,
            execution_completed=execution_completed,
            completed_execution=completed_execution,
            execution_degraded=execution_degraded,
            output_restricted=output_restricted,
            output_degraded=output_degraded,
            output_replaced=output_replaced,
        )
        return FinalizationBundle(
            final_status=final_status,
            final_execution_outcome=outcome,
            simulated_tool_output=simulated_output,
            execution_started=execution_started,
            execution_completed=execution_completed,
            entered_execution_stage=entered_execution_stage,
            completed_execution=completed_execution,
            execution_degraded=execution_degraded,
            output_restricted=output_restricted,
            output_degraded=output_degraded,
            output_replaced=output_replaced,
        )

    def handle_mcp_request(self, envelope: McpRequestEnvelope) -> AgentExecutionResult:
        """Protocol-aware runtime entrypoint driven by MCP request envelope."""
        logs: list[str] = []
        trace_records: list[ExecutionTraceRecord] = []
        protocol_context: dict[str, object] = {
            "request_id": envelope.request_id,
            "session_id": envelope.session_id,
            "feature": envelope.feature,
            "source_role": envelope.source_role,
            "parent_request_id": envelope.parent_request_id,
            "root_user_request_id": self._derive_root_user_request_id(envelope),
        }

        def add_trace(stage: str, event: str, **details: object) -> None:
            merged_details: dict[str, object] = {**protocol_context, **{str(k): v for k, v in details.items()}}
            record = ExecutionTraceRecord(
                timestamp=datetime.now(UTC),
                stage=stage,
                event=event,
                details=merged_details,
            )
            trace_records.append(record)
            preview_parts: list[str] = []
            for key, value in record.details.items():
                if value is None:
                    continue
                if isinstance(value, str) and value == "":
                    continue
                if isinstance(value, (list, dict, tuple, set)) and len(value) == 0:
                    continue
                preview_parts.append(f"{key}={value}")
            logs.append(f"{record.stage}:{record.event}" + (f" [{', '.join(preview_parts)}]" if preview_parts else ""))

        runtime_context = self.build_request_context(envelope, add_trace=add_trace)
        policy_bundle = self.evaluate_policy(runtime_context, add_trace=add_trace)
        protocol_context["root_user_request_id"] = policy_bundle.request_lineage.root_user_request_id

        sink_bundle = self.evaluate_sink(runtime_context, policy_bundle, add_trace=add_trace)
        execution_bundle = self.execute_mock_runtime(runtime_context, policy_bundle, sink_bundle, add_trace=add_trace)
        final_bundle = self.finalize_outcome(runtime_context, policy_bundle, sink_bundle, execution_bundle, add_trace=add_trace)

        self.registry.register_tool(runtime_context.selected_tool, request_lineage=policy_bundle.request_lineage)
        add_trace("audit", "tool_snapshot_registered", tool_name=runtime_context.selected_tool.name)

        return AgentExecutionResult(
            user_query=runtime_context.user_query,
            selected_tool=SelectedToolInfo(
                tool_id=runtime_context.selected_tool.tool_id,
                name=runtime_context.selected_tool.name,
                version=runtime_context.selected_tool.version,
                source_uri=runtime_context.selected_tool.source_uri,
            ),
            source_trust_label=policy_bundle.source_trust_label,
            capability_result=policy_bundle.capability_result,
            metadata_validation_result=policy_bundle.metadata_validation_result,
            decision_result=policy_bundle.decision_result,
            sink_result=sink_bundle.sink_result,
            invocation_plan=execution_bundle.invocation_plan,
            simulated_tool_output=final_bundle.simulated_tool_output,
            final_execution_outcome=final_bundle.final_execution_outcome,
            execution_started=final_bundle.execution_started,
            execution_completed=final_bundle.execution_completed,
            entered_execution_stage=final_bundle.entered_execution_stage,
            completed_execution=final_bundle.completed_execution,
            execution_degraded=final_bundle.execution_degraded,
            output_restricted=final_bundle.output_restricted,
            output_degraded=final_bundle.output_degraded,
            output_replaced=final_bundle.output_replaced,
            final_status=final_bundle.final_status,
            execution_trace_record=trace_records,
            execution_trace_records=trace_records,
            trace_records=trace_records,
            logs=logs,
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
        """Compatibility entrypoint: translate legacy query args into MCP envelope."""
        envelope = McpRequestEnvelope(
            request_id=f"req-{uuid4().hex}",
            session_id=f"sess-{uuid4().hex}",
            feature="tools",
            source_role="client",
            payload={
                "user_query": user_query,
                "preferred_tool_name": preferred_tool_name,
                "source_type": source_type,
                "source_content": source_content,
                "source_metadata": dict(source_metadata or {}),
                "sink_payload": sink_payload,
                "sink_metadata": dict(sink_metadata or {}),
                "user_authorized": user_authorized,
            },
        )
        return self.handle_mcp_request(envelope)
