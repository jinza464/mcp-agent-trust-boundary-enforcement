"""Core domain models for trust-boundary enforcement research and industrial prototyping.

Revision goals for this phase:
- keep wire/runtime compatibility with the current prototype
- tighten type discipline where it does not break the benchmark
- reduce the gap between model-layer abstractions and downstream consumers
- preserve JSON-friendly serialization for audit, testing, and experiment export
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import TypeAlias

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, JsonValue, field_validator, model_validator

JsonObject: TypeAlias = dict[str, JsonValue]

# Fixed-structure-but-flexible JSON documents around tool schema boundaries.
ToolSchemaDocument: TypeAlias = JsonObject
InvocationConstraintDocument: TypeAlias = JsonObject

# Open audit/evidence payload carried across module boundaries.
# These fields intentionally remain extensible for research instrumentation.
RuntimeAuditContext: TypeAlias = JsonObject
ModuleEvidencePayload: TypeAlias = JsonObject
DecisionEvidencePayload: TypeAlias = JsonObject


def _normalize_string_list(value: object, *, field_name: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if not isinstance(value, (list, tuple, set)):
        raise TypeError(f"{field_name} must be a string or an array of strings.")
    normalized: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            normalized.append(text)
    return normalized


def _normalize_json_object(value: object, *, field_name: str) -> JsonObject:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise TypeError(f"{field_name} must be an object.")
    return {str(key): item for key, item in value.items()}


def _normalize_optional_json_object(value: object, *, field_name: str) -> JsonObject | None:
    if value is None:
        return None
    return _normalize_json_object(value, field_name=field_name)


class TrustLabel(str, Enum):
    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    CONDITIONAL = "conditional"


class CapabilityType(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    MCP_INVOKE = "mcp_invoke"
    MODEL_INFER = "model_infer"
    FILE_SYSTEM = "file_system"


class BaseActionCapability(str, Enum):
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    TRANSMIT = "transmit"
    INVOKE = "invoke"


class ResourceScope(str, Enum):
    FILE = "file"
    NETWORK = "network"
    SECRET = "secret"
    CREDENTIAL = "credential"
    CONFIG = "config"
    MODEL = "model"
    STATE = "state"


class InvocationMechanism(str, Enum):
    LOCAL_FUNCTION = "local_function"
    MCP_TOOL = "mcp_tool"
    REMOTE_API = "remote_api"
    SCHEDULED = "scheduled"
    BACKGROUND = "background"


class PolicyCapabilityLabel(str, Enum):
    BENIGN_READ = "benign_read"
    READ_SECRET = "read_secret"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    STATE_CHANGE = "state_change"
    HIDDEN_INVOCATION = "hidden_invocation"
    CREDENTIAL_ACCESS = "credential_access"
    TOOLCHAIN_DELEGATION = "toolchain_delegation"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    REDACT = "redact"
    ESCALATE = "escalate"
    REQUIRE_CONFIRMATION = "require_confirmation"


class RecommendationAction(str, Enum):
    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class IntegrityState(str, Enum):
    UNKNOWN = "unknown"
    VERIFIED = "verified"
    TAMPERED = "tampered"
    MISSING = "missing"


class CapabilityProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    actions: set[BaseActionCapability] = Field(default_factory=set)
    resource_scopes: set[ResourceScope] = Field(default_factory=set)
    invocation_mechanisms: set[InvocationMechanism] = Field(default_factory=set)


class ToolMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tool_id: str = Field(...)
    tool_identity: str | None = Field(default=None)
    name: str = Field(...)
    namespace: str | None = Field(default=None)
    version: str = Field(...)

    provider: str = Field(...)
    provider_identity: str | None = Field(default=None)

    server_id: str | None = Field(default=None)
    server_origin: str | None = Field(default=None)
    source_uri: str | None = Field(default=None, validation_alias=AliasChoices("source_uri", "origin_uri"))

    description: str = Field(...)
    input_schema: ToolSchemaDocument | None = Field(
        default=None,
        description="Tool input schema document exported to JSON outputs and tests.",
    )
    output_schema: ToolSchemaDocument | None = Field(
        default=None,
        description="Tool output schema document exported to JSON outputs and tests.",
    )
    invocation_constraints: InvocationConstraintDocument | None = Field(
        default=None,
        description="Invocation constraints document (rate/scope/context hints).",
    )

    capabilities: set[CapabilityType] = Field(default_factory=set)
    capability_profile: CapabilityProfile | None = Field(default=None)
    policy_capability_labels: set[PolicyCapabilityLabel] = Field(default_factory=set)
    tags: list[str] = Field(default_factory=list)

    @field_validator("tool_id", "name", "version", "provider", "description")
    @classmethod
    def _strip_required_strings(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("required string fields must be non-empty")
        return value

    @field_validator("source_uri", "server_origin", "provider_identity", "tool_identity", "namespace", "server_id")
    @classmethod
    def _strip_optional_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("input_schema", "output_schema", "invocation_constraints", mode="before")
    @classmethod
    def _normalize_schema_documents(cls, value: object, info) -> JsonObject | None:
        return _normalize_optional_json_object(value, field_name=info.field_name)

    @field_validator("tags", mode="before")
    @classmethod
    def _normalize_tags(cls, value: object) -> list[str]:
        normalized = _normalize_string_list(value, field_name="tags")
        seen: set[str] = set()
        deduped: list[str] = []
        for text in normalized:
            if text not in seen:
                seen.add(text)
                deduped.append(text)
        return deduped

    @model_validator(mode="after")
    def _backfill_identity_fields(self) -> ToolMetadata:
        if self.tool_identity is None:
            self.tool_identity = self.tool_id
        if self.provider_identity is None:
            self.provider_identity = self.provider
        if self.server_origin is None:
            self.server_origin = self.source_uri
        if self.source_uri is None:
            self.source_uri = self.server_origin
        if self.namespace is None and self.provider_identity:
            self.namespace = self.provider_identity
        return self


class ToolSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    snapshot_id: str = Field(...)
    tool: ToolMetadata = Field(...)
    captured_at: datetime = Field(...)
    description_hash: str | None = Field(default=None)
    input_schema_hash: str | None = Field(default=None)
    output_schema_hash: str | None = Field(default=None)
    server_origin: str | None = Field(default=None)
    observed_version: str | None = Field(default=None)
    integrity_state: IntegrityState = Field(default=IntegrityState.UNKNOWN)
    trust_label: TrustLabel = Field(default=TrustLabel.UNKNOWN)
    integrity_checksum: str | None = Field(default=None)
    runtime_context: RuntimeAuditContext = Field(
        default_factory=dict,
        description="Open runtime audit context captured alongside snapshot (JSON-serializable).",
    )

    @field_validator("runtime_context", mode="before")
    @classmethod
    def _normalize_runtime_context(cls, value: object) -> JsonObject:
        return _normalize_json_object(value, field_name="runtime_context")

    @model_validator(mode="after")
    def _backfill_explicit_snapshot_fields(self) -> ToolSnapshot:
        if self.server_origin is None:
            raw_origin = self.runtime_context.get("server_origin")
            if isinstance(raw_origin, str) and raw_origin.strip():
                self.server_origin = raw_origin.strip()
            else:
                self.server_origin = self.tool.server_origin or self.tool.source_uri
        if self.observed_version is None:
            self.observed_version = str(self.runtime_context.get("version") or self.tool.version)
        if self.description_hash is None:
            raw = self.runtime_context.get("description_hash")
            self.description_hash = str(raw) if raw is not None else None
        if self.input_schema_hash is None:
            raw = self.runtime_context.get("input_schema_hash") or self.runtime_context.get("schema_hash")
            self.input_schema_hash = str(raw) if raw is not None else None
        if self.output_schema_hash is None:
            raw = self.runtime_context.get("output_schema_hash") or self.runtime_context.get("schema_hash")
            self.output_schema_hash = str(raw) if raw is not None else None
        if self.integrity_state == IntegrityState.UNKNOWN:
            raw_state = self.runtime_context.get("integrity_state")
            if isinstance(raw_state, str):
                try:
                    self.integrity_state = IntegrityState(raw_state)
                except ValueError:
                    self.integrity_state = IntegrityState.UNKNOWN
            elif self.integrity_checksum:
                self.integrity_state = IntegrityState.VERIFIED
        return self


class ModuleAssessmentResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    module_name: str = Field(...)
    recommendation: RecommendationAction = Field(...)
    risk_level: RiskLevel = Field(...)
    reasons: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)
    evidence: ModuleEvidencePayload = Field(
        default_factory=dict,
        description="Open per-module evidence payload for audit/analysis (JSON-serializable).",
    )

    @field_validator("module_name")
    @classmethod
    def _module_name_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("module_name must be non-empty")
        return value

    @field_validator("reasons", "findings", mode="before")
    @classmethod
    def _normalize_reasons_findings(cls, value: object, info) -> list[str]:
        return _normalize_string_list(value, field_name=info.field_name)

    @field_validator("evidence", mode="before")
    @classmethod
    def _normalize_evidence(cls, value: object) -> JsonObject:
        return _normalize_json_object(value, field_name="evidence")


class DecisionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    decision_id: str = Field(...)
    action: DecisionAction = Field(...)
    enforcement_action: DecisionAction | None = Field(default=None)
    module_recommendations: list[ModuleAssessmentResult] = Field(default_factory=list)
    risk_level: RiskLevel = Field(...)
    trust_label: TrustLabel = Field(...)
    reasons: list[str] = Field(default_factory=list, validation_alias=AliasChoices("reasons", "rationale"))
    findings: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    applied_policies: list[str] = Field(default_factory=list)
    required_controls: list[str] = Field(default_factory=list)
    evidence: DecisionEvidencePayload = Field(
        default_factory=dict,
        description="Open merged decision evidence payload for export and reproducibility.",
    )

    @field_validator("reasons", mode="before")
    @classmethod
    def _normalize_reasons(cls, value: object) -> list[str]:
        return _normalize_string_list(value, field_name="reasons")

    @field_validator("findings", "applied_policies", "required_controls", mode="before")
    @classmethod
    def _normalize_string_list_fields(cls, value: object, info) -> list[str]:
        return _normalize_string_list(value, field_name=info.field_name)

    @field_validator("evidence", mode="before")
    @classmethod
    def _normalize_decision_evidence(cls, value: object) -> JsonObject:
        return _normalize_json_object(value, field_name="evidence")

    @model_validator(mode="after")
    def _backfill_enforcement_action(self) -> DecisionResult:
        if self.enforcement_action is None:
            self.enforcement_action = self.action
        return self


class AttackCase(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    case_id: str = Field(...)
    title: str = Field(...)
    description: str = Field(...)
    preconditions: list[str] = Field(default_factory=list)
    attack_steps: list[str] = Field(default_factory=list)
    mapped_capabilities: set[CapabilityType] = Field(default_factory=set)
    normalized_policy_labels: set[PolicyCapabilityLabel] = Field(default_factory=set)
    risk_level: RiskLevel = Field(..., validation_alias=AliasChoices("risk_level", "estimated_risk"))
    expected_impact: str = Field(...)
    mitigations: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
