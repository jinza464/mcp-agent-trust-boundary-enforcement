"""Lightweight request lineage and provenance graph for MCP runtime analysis."""

from __future__ import annotations

from collections import deque
from datetime import UTC, datetime
from typing import Literal, TypeAlias
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.models import TrustLabel
from app.mcp.protocol_models import McpFeatureScope, McpSourceRole, RequestLineage

LineageEventType: TypeAlias = Literal[
    "mcp_request",
    "tool_invocation",
    "sampling_request",
    "roots_exposure",
    "elicitation_request",
    "sink_output",
    "runtime_decision",
]
ProvenanceRelation: TypeAlias = Literal[
    "derived_from",
    "parent_of",
    "invokes",
    "samples_from",
    "exposes_roots",
    "elicits",
    "produces_sink_payload",
]
TrustTransfer: TypeAlias = Literal["preserve", "downgrade", "upgrade", "unknown"]

VALID_LINEAGE_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "mcp_request",
        "tool_invocation",
        "sampling_request",
        "roots_exposure",
        "elicitation_request",
        "sink_output",
        "runtime_decision",
    }
)


def _coerce_event_type(value: object) -> LineageEventType:
    text = str(value)
    if text not in VALID_LINEAGE_EVENT_TYPES:
        raise ValueError(f"unsupported lineage event_type: {text}")
    return text  # type: ignore[return-value]


class LineageEvent(BaseModel):
    """One observed protocol/runtime event in a lineage graph."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(default_factory=lambda: f"lineage-event-{uuid4().hex}")
    request_id: str
    parent_request_id: str | None = None
    root_user_request_id: str
    event_type: LineageEventType
    feature: McpFeatureScope | None = None
    source_role: McpSourceRole | None = None
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator("event_id", "request_id", "root_user_request_id")
    @classmethod
    def _non_empty_ids(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("lineage event identifiers must be non-empty.")
        return normalized

    @field_validator("parent_request_id")
    @classmethod
    def _normalize_optional_parent(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @classmethod
    def from_request_lineage(
        cls,
        lineage: RequestLineage,
        *,
        event_type: LineageEventType = "mcp_request",
        metadata: dict[str, object] | None = None,
    ) -> "LineageEvent":
        return cls(
            request_id=lineage.request_id,
            parent_request_id=lineage.parent_request_id,
            root_user_request_id=lineage.root_user_request_id,
            event_type=event_type,
            feature=lineage.feature,
            source_role=lineage.source_role,
            trust_label=lineage.trust_label,
            timestamp=lineage.created_at,
            metadata=metadata or {},
        )


class ProvenanceEdge(BaseModel):
    """Directed provenance relation between two lineage events."""

    model_config = ConfigDict(extra="forbid")

    from_event_id: str
    to_event_id: str
    relation: ProvenanceRelation
    reason: str | None = None
    trust_transfer: TrustTransfer = "unknown"

    @field_validator("from_event_id", "to_event_id")
    @classmethod
    def _non_empty_edge_ids(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("provenance edge ids must be non-empty.")
        return normalized

    @field_validator("reason")
    @classmethod
    def _normalize_reason(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class RequestLineageGraph(BaseModel):
    """In-memory graph for explaining MCP request and payload provenance."""

    model_config = ConfigDict(extra="forbid")

    root_user_request_id: str
    events: dict[str, LineageEvent] = Field(default_factory=dict)
    edges: list[ProvenanceEdge] = Field(default_factory=list)

    @field_validator("root_user_request_id")
    @classmethod
    def _non_empty_root(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("root_user_request_id must be non-empty.")
        return normalized

    def add_event(self, event: LineageEvent | RequestLineage, **overrides: object) -> LineageEvent:
        if isinstance(event, RequestLineage):
            metadata = overrides.pop("metadata", None)
            if metadata is not None and not isinstance(metadata, dict):
                raise TypeError("metadata override must be a dict when provided.")
            lineage_event = LineageEvent.from_request_lineage(
                event,
                event_type=_coerce_event_type(overrides.pop("event_type", "mcp_request")),
                metadata=metadata,
            )
            if overrides:
                lineage_event = lineage_event.model_copy(update=overrides)
        else:
            lineage_event = event.model_copy(update=overrides) if overrides else event
        if lineage_event.root_user_request_id != self.root_user_request_id:
            raise ValueError("event root_user_request_id does not match graph root.")
        self.events[lineage_event.event_id] = lineage_event
        return lineage_event

    def add_edge(
        self,
        edge: ProvenanceEdge | None = None,
        *,
        from_event_id: str | None = None,
        to_event_id: str | None = None,
        relation: ProvenanceRelation | None = None,
        reason: str | None = None,
        trust_transfer: TrustTransfer = "unknown",
    ) -> ProvenanceEdge:
        resolved = edge or ProvenanceEdge(
            from_event_id=from_event_id or "",
            to_event_id=to_event_id or "",
            relation=relation or "derived_from",
            reason=reason,
            trust_transfer=trust_transfer,
        )
        if resolved.from_event_id not in self.events:
            raise ValueError(f"unknown from_event_id: {resolved.from_event_id}")
        if resolved.to_event_id not in self.events:
            raise ValueError(f"unknown to_event_id: {resolved.to_event_id}")
        self.edges.append(resolved)
        return resolved

    def find_ancestors(self, event_id: str) -> list[LineageEvent]:
        if event_id not in self.events:
            return []
        incoming: dict[str, list[str]] = {}
        for edge in self.edges:
            incoming.setdefault(edge.to_event_id, []).append(edge.from_event_id)
        visited: set[str] = set()
        ancestors: list[LineageEvent] = []
        queue: deque[str] = deque(incoming.get(event_id, []))
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            event = self.events.get(current)
            if event is None:
                continue
            ancestors.append(event)
            queue.extend(incoming.get(current, []))
        return ancestors

    def has_untrusted_ancestor(self, event_id: str) -> bool:
        return any(event.trust_label == TrustLabel.UNTRUSTED for event in self.find_ancestors(event_id))

    def sink_payload_from_untrusted_source(self, event_id: str) -> bool:
        event = self.events.get(event_id)
        if event is None:
            return False
        if event.event_type != "sink_output":
            return False
        if event.trust_label == TrustLabel.UNTRUSTED:
            return True
        if bool(event.metadata.get("derived_from_untrusted_source")):
            return True
        return self.has_untrusted_ancestor(event_id)

    def sampling_traces_to_root(self, event_id: str) -> bool:
        event = self.events.get(event_id)
        if event is None or event.event_type != "sampling_request":
            return False
        if event.request_id == self.root_user_request_id:
            return True
        if event.parent_request_id == self.root_user_request_id:
            return True
        return any(ancestor.request_id == self.root_user_request_id for ancestor in self.find_ancestors(event_id))

    def summarize(self) -> dict[str, object]:
        event_type_counts: dict[str, int] = {}
        untrusted_event_ids: list[str] = []
        sink_outputs_from_untrusted: list[str] = []
        sampling_without_root_trace: list[str] = []
        for event in self.events.values():
            event_type_counts[event.event_type] = event_type_counts.get(event.event_type, 0) + 1
            if event.trust_label == TrustLabel.UNTRUSTED:
                untrusted_event_ids.append(event.event_id)
            if self.sink_payload_from_untrusted_source(event.event_id):
                sink_outputs_from_untrusted.append(event.event_id)
            if event.event_type == "sampling_request" and not self.sampling_traces_to_root(event.event_id):
                sampling_without_root_trace.append(event.event_id)
        return {
            "root_user_request_id": self.root_user_request_id,
            "event_count": len(self.events),
            "edge_count": len(self.edges),
            "event_type_counts": event_type_counts,
            "untrusted_event_ids": untrusted_event_ids,
            "sink_outputs_from_untrusted": sink_outputs_from_untrusted,
            "sampling_without_root_trace": sampling_without_root_trace,
            "events": [event.model_dump(mode="json") for event in self.events.values()],
            "edges": [edge.model_dump(mode="json") for edge in self.edges],
        }
