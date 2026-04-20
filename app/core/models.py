"""Core data models for client-side trust boundary enforcement research prototype."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_validator


class TrustLabel(str, Enum):
    """Trust label assigned to an entity under evaluation."""

    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"
    CONDITIONAL = "conditional"


class CapabilityType(str, Enum):
    """Abstract capability categories used for trust and policy evaluation."""

    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    NETWORK = "network"
    MCP_INVOKE = "mcp_invoke"
    MODEL_INFER = "model_infer"
    FILE_SYSTEM = "file_system"


class RiskLevel(str, Enum):
    """Normalized risk scale for policy and decision outputs."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DecisionAction(str, Enum):
    """Enforcement actions available to the decision engine."""

    ALLOW = "allow"
    DENY = "deny"
    SANDBOX = "sandbox"
    REDACT = "redact"
    ESCALATE = "escalate"
    REQUIRE_CONFIRMATION = "require_confirmation"


class ToolMetadata(BaseModel):
    """Stable descriptive metadata for a tool registered in the system."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    tool_id: str = Field(..., description="Global unique identifier of the tool.")
    name: str = Field(..., description="Human-readable tool name.")
    version: str = Field(..., description="Tool version string.")
    provider: str = Field(..., description="Provider or vendor name.")
    description: str = Field(..., description="Short functional description.")
    capabilities: set[CapabilityType] = Field(
        default_factory=set,
        description="Declared capability categories exposed by this tool.",
    )
    source_uri: str | None = Field(
        default=None,
        description="Optional source URI for the tool definition.",
    )
    tags: list[str] = Field(
        default_factory=list,
        description="Free-form tags for retrieval and policy grouping.",
    )


class ToolSnapshot(BaseModel):
    """Point-in-time tool state captured for validation and decision making."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    snapshot_id: str = Field(..., description="Unique snapshot identifier.")
    tool: ToolMetadata = Field(..., description="Embedded stable tool metadata.")
    captured_at: datetime = Field(..., description="Snapshot capture timestamp.")
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
        description="Runtime attributes relevant to policy evaluation.",
    )


class DecisionResult(BaseModel):
    """Decision engine output for a given request, tool, or execution context.

    Notes:
        - `reasons` stores concise human-readable explanations.
        - `findings` stores structured/atomic findings used to justify actions.
    """

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    decision_id: str = Field(..., description="Unique identifier for this decision record.")
    action: DecisionAction = Field(..., description="Selected enforcement action.")
    risk_level: RiskLevel = Field(..., description="Estimated risk level.")
    trust_label: TrustLabel = Field(..., description="Trust label at decision time.")
    reasons: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices("reasons", "rationale"),
        description="Human-readable reasons for the decision action.",
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
