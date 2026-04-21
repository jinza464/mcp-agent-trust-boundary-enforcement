"""Core domain models for trust-boundary enforcement research and industrial prototyping.

Design goals:
- Keep backward compatibility for current prototype modules.
- Promote previously implicit proxy fields into explicit first-class fields.
- Provide stronger, formalized structures for identity, policy, and decision reasoning.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator, model_validator


class TrustLabel(str, Enum):
    """Trust label assigned to a source/entity under evaluation.

    Compatibility note:
    Existing modules rely on these exact string values; keep stable.
    """

    TRUSTED = "trusted"
    SEMI_TRUSTED = "semi_trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    CONDITIONAL = "conditional"


class CapabilityType(str, Enum):
    """Legacy flat capability taxonomy used by existing prototype modules.

    Compatibility note:
    Retained for current policy/validator/decision code paths.
    Prefer the structured taxonomy (`BaseActionCapability`, `ResourceScope`,
    `InvocationMechanism`, `PolicyCapabilityLabel`) for new development.
    """

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    MCP_INVOKE = "mcp_invoke"
    MODEL_INFER = "model_infer"
    FILE_SYSTEM = "file_system"


class BaseActionCapability(str, Enum):
    """Action-oriented capability primitive (what operation is performed)."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    TRANSMIT = "transmit"
    INVOKE = "invoke"


class ResourceScope(str, Enum):
    """Resource domain targeted by a tool action (what is acted on)."""

    FILE = "file"
    NETWORK = "network"
    SECRET = "secret"
    CREDENTIAL = "credential"
    CONFIG = "config"
    MODEL = "model"
    STATE = "state"


class InvocationMechanism(str, Enum):
    """Invocation mechanism/channel (how action is triggered)."""

    LOCAL_FUNCTION = "local_function"
    MCP_TOOL = "mcp_tool"
    REMOTE_API = "remote_api"
    SCHEDULED = "scheduled"
    BACKGROUND = "background"


class PolicyCapabilityLabel(str, Enum):
    """Normalized policy labels consumed by formal policy/decision layers."""

    BENIGN_READ = "benign_read"
    READ_SECRET = "read_secret"
    FILE_WRITE = "file_write"
    NETWORK_SEND = "network_send"
    STATE_CHANGE = "state_change"
    HIDDEN_INVOCATION = "hidden_invocation"


class RiskLevel(str, Enum):
    """Normalized risk scale for policy and decision outputs."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    """Final enforcement actions available to runtime control plane.

    Compatibility note:
    Existing modules depend on these values.
    """

    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    REDACT = "redact"
    ESCALATE = "escalate"
    REQUIRE_CONFIRMATION = "require_confirmation"


class RecommendationAction(str, Enum):
    """Local module recommendation prior to final enforcement."""

    ALLOW = "allow"
    REVIEW = "review"
    BLOCK = "block"


class IntegrityState(str, Enum):
    """Observed integrity state of metadata/artifact snapshot."""

    UNKNOWN = "unknown"
    VERIFIED = "verified"
    TAMPERED = "tampered"
    MISSING = "missing"


class CapabilityProfile(BaseModel):
    """Structured capability decomposition for formal policy reasoning."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    actions: set[BaseActionCapability] = Field(default_factory=set)
    resource_scopes: set[ResourceScope] = Field(default_factory=set)
    invocation_mechanisms: set[InvocationMechanism] = Field(default_factory=set)


class ToolMetadata(BaseModel):
    """Stable tool identity + schema metadata.

    Prototype compatibility:
    - keeps legacy fields (`provider`, `source_uri`, `capabilities`, `tags`)
    - adds formal identity/schema fields for stricter registry and reasoning.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    # Tool identity
    tool_id: str = Field(..., description="Global unique identifier of the tool.")
    tool_identity: str | None = Field(
        default=None,
        description="Canonical tool identity key for formal registry reasoning.",
    )
    name: str = Field(..., description="Human-readable tool name.")
    namespace: str | None = Field(
        default=None,
        description="Logical namespace to avoid cross-domain name collisions.",
    )

    # Versioning
    version: str = Field(..., description="Tool version string.")

    # Provider identity
    provider: str = Field(..., description="Provider or vendor name (legacy compatibility).")
    provider_identity: str | None = Field(
        default=None,
        description="Canonical provider identity for trust anchoring.",
    )

    # Server identity/origin
    server_id: str | None = Field(
        default=None,
        description="Stable server identity within provider namespace.",
    )
    server_origin: str | None = Field(
        default=None,
        description="Canonical server origin used for trust-boundary decisions.",
    )
    source_uri: str | None = Field(
        default=None,
        validation_alias=AliasChoices("source_uri", "origin_uri"),
        description="Legacy source URI for tool definition retrieval.",
    )

    # Functional description
    description: str = Field(..., description="Short functional description.")

    # Formal schemas (first-class fields)
    input_schema: dict[str, object] | None = Field(
        default=None,
        description="Formal input schema for tool invocation.",
    )
    output_schema: dict[str, object] | None = Field(
        default=None,
        description="Formal output schema for tool response.",
    )
    invocation_constraints: dict[str, object] | None = Field(
        default=None,
        description="Formal invocation constraints (rate/scope/auth/context).",
    )

    # Legacy + structured capability representations
    capabilities: set[CapabilityType] = Field(
        default_factory=set,
        description="Legacy flat capability categories exposed by this tool.",
    )
    capability_profile: CapabilityProfile | None = Field(
        default=None,
        description="Structured capability decomposition for policy/formal reasoning.",
    )
    policy_capability_labels: set[PolicyCapabilityLabel] = Field(
        default_factory=set,
        description="Normalized policy labels usable by validator/decision layers.",
    )

    tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags for retrieval and policy grouping (legacy/auxiliary).",
    )

    @model_validator(mode="after")
    def _backfill_identity_fields(self) -> ToolMetadata:
        """Backfill new identity fields from legacy fields to preserve compatibility."""
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
    """Point-in-time tool state for registry, validation, and policy reasoning.

    Compared with prototype version, key identity/hash fields are explicit first-class
    fields instead of primarily living in runtime_context.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    snapshot_id: str = Field(..., description="Unique snapshot identifier.")
    tool: ToolMetadata = Field(..., description="Embedded stable tool metadata.")
    captured_at: datetime = Field(..., description="Snapshot capture timestamp.")

    # Explicit identity/hash/state fields
    description_hash: str | None = Field(default=None, description="Hash of tool description content.")
    input_schema_hash: str | None = Field(default=None, description="Hash of normalized input schema.")
    output_schema_hash: str | None = Field(default=None, description="Hash of normalized output schema.")
    server_origin: str | None = Field(default=None, description="Observed server origin at capture time.")
    observed_version: str | None = Field(default=None, description="Observed version at capture time.")
    integrity_state: IntegrityState = Field(
        default=IntegrityState.UNKNOWN,
        description="Integrity status at capture time.",
    )

    # Existing fields (compatibility)
    trust_label: TrustLabel = Field(
        default=TrustLabel.UNKNOWN,
        description="Current trust label at snapshot time.",
    )
    integrity_checksum: str | None = Field(
        default=None,
        description="Optional checksum over relevant tool artifacts.",
    )
    runtime_context: dict[str, Any] = Field(
        default_factory=dict,
        description="Extended runtime attributes (auxiliary, non-canonical).",
    )

    @model_validator(mode="after")
    def _backfill_explicit_snapshot_fields(self) -> ToolSnapshot:
        """Backfill first-class snapshot fields from legacy context when needed."""
        if self.server_origin is None:
            self.server_origin = (
                self.runtime_context.get("server_origin")
                or self.tool.server_origin
                or self.tool.source_uri
            )
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
    """Common structured output contract for local security modules.

    Intended for metadata validator, sink guard, capability policy, and future
    formal-policy analyzers to emit consistent recommendation objects.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    module_name: str = Field(..., description="Module identifier emitting this assessment.")
    recommendation: RecommendationAction = Field(..., description="Local recommendation from this module.")
    risk_level: RiskLevel = Field(..., description="Module-local estimated risk.")
    reasons: list[str] = Field(default_factory=list, description="Concise human-readable reasons.")
    findings: list[str] = Field(default_factory=list, description="Detailed supporting findings.")
    evidence: dict[str, Any] = Field(default_factory=dict, description="Structured evidence payload.")


class DecisionResult(BaseModel):
    """Decision engine output for a given request/tool/execution context.

    Separation of concerns:
    - `module_recommendations`: local module outputs before final merge.
    - `action`: final enforcement action used by runtime.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    decision_id: str = Field(..., description="Unique identifier for this decision record.")

    # Final enforcement action (runtime authoritative)
    action: DecisionAction = Field(..., description="Final enforcement action.")
    enforcement_action: DecisionAction | None = Field(
        default=None,
        description="Explicit final enforcement action mirror for formal clarity.",
    )

    # Local recommendations
    module_recommendations: list[ModuleAssessmentResult] = Field(
        default_factory=list,
        description="Module-level recommendations prior to final action merge.",
    )

    risk_level: RiskLevel = Field(..., description="Estimated aggregate risk level.")
    trust_label: TrustLabel = Field(..., description="Trust label at decision time.")

    reasons: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("reasons", "rationale"),
        description="Human-readable reasons for the final decision action.",
    )
    findings: list[str] = Field(
        default_factory=list,
        description="Atomic findings supporting reasons and final action.",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score in [0.0, 1.0].",
    )
    applied_policies: list[str] = Field(
        default_factory=list,
        description="Policy identifiers applied during evaluation.",
    )
    required_controls: list[str] = Field(
        default_factory=list,
        description="Controls required before or during execution.",
    )
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured evidence supporting the final action.",
    )

    @field_validator("reasons", mode="before")
    @classmethod
    def _normalize_reasons(cls, value: Any) -> list[str]:
        """Normalize legacy single-string rationale into list-based reasons."""
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        return value

    @model_validator(mode="after")
    def _backfill_enforcement_action(self) -> DecisionResult:
        """Keep explicit enforcement field aligned with legacy `action` field."""
        if self.enforcement_action is None:
            self.enforcement_action = self.action
        return self


class AttackCase(BaseModel):
    """Structured attack case for adversarial evaluation and benchmarking."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    case_id: str = Field(..., description="Unique attack case identifier.")
    title: str = Field(..., description="Short attack case title.")
    description: str = Field(..., description="Attack case narrative description.")
    preconditions: list[str] = Field(
        default_factory=list,
        description="Preconditions required before the attack can succeed.",
    )
    attack_steps: list[str] = Field(
        default_factory=list,
        description="Ordered attacker action steps.",
    )
    mapped_capabilities: set[CapabilityType] = Field(
        default_factory=set,
        description="Capabilities exercised by this attack path.",
    )
    normalized_policy_labels: set[PolicyCapabilityLabel] = Field(
        default_factory=set,
        description="Normalized policy labels exercised by this attack path.",
    )
    risk_level: RiskLevel = Field(
        ...,
        validation_alias=AliasChoices("risk_level", "estimated_risk"),
        description="Estimated risk severity.",
    )
    expected_impact: str = Field(..., description="Expected impact if attack succeeds.")
    mitigations: list[str] = Field(
        default_factory=list,
        description="Candidate mitigations for this attack case.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="References such as papers, reports, or issue links.",
    )
