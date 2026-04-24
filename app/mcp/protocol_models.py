"""Protocol-level MCP request objects for lineage-aware client runtime."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.core.models import TrustLabel

McpFeatureScope: TypeAlias = Literal["tools", "resources", "prompts", "sampling", "roots", "elicitation"]
McpSourceRole: TypeAlias = Literal["host", "client", "server"]
McpResponseStatus: TypeAlias = Literal["ok", "error", "cancelled", "partial"]


class ProtocolProvenanceHop(BaseModel):
    """One boundary-crossing hop in an MCP request or payload provenance chain."""

    model_config = ConfigDict(extra="forbid")

    hop_id: str
    source_role: McpSourceRole
    feature: McpFeatureScope | None = None
    request_id: str | None = None
    parent_request_id: str | None = None
    server_origin: str | None = None
    trust_label: TrustLabel = TrustLabel.UNKNOWN
    source_type: str | None = None
    derived_from_untrusted_content: bool = False
    prompt_injection_signal: bool = False
    evidence: dict[str, object] = Field(
        default_factory=dict,
        description="Open evidence boundary for provenance hints observed at this hop.",
    )

    @field_validator("hop_id")
    @classmethod
    def _non_empty_hop_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("hop_id must be non-empty.")
        return normalized

    @field_validator("request_id", "parent_request_id", "server_origin", "source_type")
    @classmethod
    def _normalize_optional_hop_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class RequestProvenance(BaseModel):
    """Compact provenance summary for lineage-aware trust-boundary enforcement."""

    model_config = ConfigDict(extra="forbid")

    provenance_chain: list[ProtocolProvenanceHop] = Field(default_factory=list)
    derived_from_untrusted_content: bool = False
    prompt_injection_propagated: bool = False
    delegated_invocation: bool = False
    authorized_delegation: bool = False
    sink_payload_derived_from_untrusted_source: bool = False
    notes: list[str] = Field(default_factory=list)


class McpRequestEnvelope(BaseModel):
    """Protocol envelope for one MCP-aware runtime request."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    session_id: str
    parent_request_id: str | None = None
    feature: McpFeatureScope
    source_role: McpSourceRole
    server_origin: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    payload: dict[str, object] = Field(
        default_factory=dict,
        description="Protocol payload boundary. Intentionally wide to preserve MCP feature-specific payloads.",
    )

    @field_validator("request_id", "session_id")
    @classmethod
    def _non_empty_required_ids(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("request_id/session_id must be non-empty.")
        return normalized

    @field_validator("parent_request_id", "server_origin")
    @classmethod
    def _normalize_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class McpResponseError(BaseModel):
    """Structured protocol error payload for MCP response envelopes."""

    model_config = ConfigDict(extra="forbid")

    code: str
    message: str
    details: dict[str, object] = Field(default_factory=dict)

    @field_validator("code", "message")
    @classmethod
    def _non_empty_error_fields(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("response error code/message must be non-empty.")
        return normalized


class McpResponseEnvelope(BaseModel):
    """Protocol envelope for MCP-aware runtime responses."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    session_id: str
    parent_request_id: str | None = None
    feature: McpFeatureScope
    source_role: McpSourceRole
    server_origin: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ok: bool = True
    status: McpResponseStatus = "ok"
    payload: dict[str, object] = Field(
        default_factory=dict,
        description="Protocol response payload boundary. Feature-specific response bodies remain intentionally flexible.",
    )
    error: McpResponseError | None = None
    provenance: RequestProvenance | None = None

    @field_validator("request_id", "session_id")
    @classmethod
    def _non_empty_response_ids(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("response request_id/session_id must be non-empty.")
        return normalized

    @field_validator("parent_request_id", "server_origin")
    @classmethod
    def _normalize_optional_response_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None

    @model_validator(mode="after")
    def _align_ok_and_status(self) -> "McpResponseEnvelope":
        if self.status == "error" and self.ok:
            self.ok = False
        if self.error is not None and self.ok:
            self.ok = False
            self.status = "error"
        if self.status == "ok" and not self.ok and self.error is None:
            self.status = "error"
        return self


class RequestLineage(BaseModel):
    """Lineage metadata used for trust-boundary attribution and registry audit."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    parent_request_id: str | None = None
    root_user_request_id: str
    source_role: McpSourceRole
    feature: McpFeatureScope
    trust_label: TrustLabel
    session_id: str | None = None
    server_origin: str | None = None
    lineage_depth: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    provenance: RequestProvenance | None = None
    provenance_chain: list[ProtocolProvenanceHop] = Field(default_factory=list)
    derived_from_untrusted_content: bool = False
    prompt_injection_propagated: bool = False
    delegated_invocation: bool = False
    authorized_delegation: bool = False
    sink_payload_derived_from_untrusted_source: bool = False

    @field_validator("request_id", "root_user_request_id")
    @classmethod
    def _non_empty_required_fields(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("lineage fields must be non-empty.")
        return normalized

    @field_validator("parent_request_id", "session_id", "server_origin")
    @classmethod
    def _normalize_optional_parent_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class SamplingRequestContext(BaseModel):
    """Minimal context for checking whether MCP sampling is tied to legitimate user intent."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    parent_request_id: str | None = None
    root_user_request_id: str
    model_hint: str | None = None
    prompt_source_trust: TrustLabel = TrustLabel.UNKNOWN
    allowed_tools: list[str] = Field(default_factory=list)
    user_approved: bool = False
    server_origin: str | None = None
    request_lineage: RequestLineage | None = None
    sampling_request_id: str | None = None
    linked_user_request_id: str | None = None
    prompt: str | None = None
    system_prompt: str | None = None
    user_intent_confirmed: bool = False
    derived_from_untrusted_content: bool = False
    prompt_injection_signal: bool = False
    metadata: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _populate_from_lineage(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        lineage = data.get("request_lineage")
        if isinstance(lineage, RequestLineage):
            data.setdefault("request_id", lineage.request_id)
            data.setdefault("parent_request_id", lineage.parent_request_id)
            data.setdefault("root_user_request_id", lineage.root_user_request_id)
            data.setdefault("server_origin", lineage.server_origin)
        elif isinstance(lineage, dict):
            data.setdefault("request_id", lineage.get("request_id"))
            data.setdefault("parent_request_id", lineage.get("parent_request_id"))
            data.setdefault("root_user_request_id", lineage.get("root_user_request_id"))
            data.setdefault("server_origin", lineage.get("server_origin"))
        if data.get("sampling_request_id") is None and data.get("request_id") is not None:
            data["sampling_request_id"] = data["request_id"]
        return data

    @field_validator("request_id", "root_user_request_id", "sampling_request_id")
    @classmethod
    def _non_empty_sampling_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("sampling request identifiers must be non-empty.")
        return normalized

    @field_validator("parent_request_id", "model_hint", "server_origin", "linked_user_request_id", "prompt", "system_prompt")
    @classmethod
    def _normalize_optional_sampling_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class RootsExposureContext(BaseModel):
    """Minimal context for reasoning about roots exposure across trust boundaries."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    root_user_request_id: str
    exposed_roots: list[str] = Field(default_factory=list)
    exposure_reason: str | None = None
    user_approved: bool = False
    server_origin: str | None = None
    request_lineage: RequestLineage | None = None
    initiated_by_server: bool = False
    requires_user_confirmation: bool = True
    upstream_trust_label: TrustLabel = TrustLabel.UNKNOWN
    derived_from_untrusted_content: bool = False
    metadata: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _populate_from_lineage(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        lineage = data.get("request_lineage")
        if isinstance(lineage, RequestLineage):
            data.setdefault("request_id", lineage.request_id)
            data.setdefault("root_user_request_id", lineage.root_user_request_id)
            data.setdefault("server_origin", lineage.server_origin)
        elif isinstance(lineage, dict):
            data.setdefault("request_id", lineage.get("request_id"))
            data.setdefault("root_user_request_id", lineage.get("root_user_request_id"))
            data.setdefault("server_origin", lineage.get("server_origin"))
        return data

    @field_validator("request_id", "root_user_request_id")
    @classmethod
    def _non_empty_roots_ids(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("roots exposure identifiers must be non-empty.")
        return normalized

    @field_validator("exposure_reason", "server_origin")
    @classmethod
    def _normalize_optional_roots_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None


class ElicitationContext(BaseModel):
    """Minimal context for user-data elicitation requests and authorization provenance."""

    model_config = ConfigDict(extra="forbid")

    request_id: str
    root_user_request_id: str
    elicitation_prompt: str
    requested_fields: list[str] = Field(default_factory=list)
    user_approved: bool = False
    server_origin: str | None = None
    request_lineage: RequestLineage | None = None
    elicitation_id: str | None = None
    prompt_text: str | None = None
    sensitive_fields: list[str] = Field(default_factory=list)
    purpose: str | None = None
    user_authorized: bool = False
    upstream_trust_label: TrustLabel = TrustLabel.UNKNOWN
    derived_from_untrusted_content: bool = False
    metadata: dict[str, object] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def _populate_compat_fields(cls, data: object) -> object:
        if not isinstance(data, dict):
            return data
        lineage = data.get("request_lineage")
        if isinstance(lineage, RequestLineage):
            data.setdefault("request_id", lineage.request_id)
            data.setdefault("root_user_request_id", lineage.root_user_request_id)
            data.setdefault("server_origin", lineage.server_origin)
        elif isinstance(lineage, dict):
            data.setdefault("request_id", lineage.get("request_id"))
            data.setdefault("root_user_request_id", lineage.get("root_user_request_id"))
            data.setdefault("server_origin", lineage.get("server_origin"))
        if data.get("elicitation_prompt") is None and data.get("prompt_text") is not None:
            data["elicitation_prompt"] = data["prompt_text"]
        if data.get("prompt_text") is None and data.get("elicitation_prompt") is not None:
            data["prompt_text"] = data["elicitation_prompt"]
        if data.get("elicitation_id") is None and data.get("request_id") is not None:
            data["elicitation_id"] = data["request_id"]
        if data.get("user_authorized") is False and data.get("user_approved") is True:
            data["user_authorized"] = True
        return data

    @field_validator("request_id", "root_user_request_id", "elicitation_prompt", "elicitation_id", "prompt_text")
    @classmethod
    def _non_empty_elicitation_fields(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("elicitation context text/id fields must be non-empty.")
        return normalized

    @field_validator("server_origin", "purpose")
    @classmethod
    def _normalize_optional_elicitation_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        return normalized or None
