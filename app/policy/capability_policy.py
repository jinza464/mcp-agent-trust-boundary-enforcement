"""Capability inference + policy normalization for MCP tool metadata.

This module upgrades simple keyword tagging into a structured inference layer:
- infer normalized policy capabilities from multi-source signals
- preserve explainability with structured findings
- aggregate risk with explicit exfiltration/orchestration semantics
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import CapabilityType, RiskLevel, ToolMetadata


class PolicyCapability(str, Enum):
    """Policy-layer normalized capabilities.

    Member names follow formal-policy terminology.
    Values keep backward-compatible legacy labels used by existing modules.
    """

    BENIGN_READ = "benign_read"
    SENSITIVE_READ = "read_secret"
    FILE_WRITE = "file_write"
    NETWORK_EGRESS = "network_send"
    STATE_MUTATION = "state_change"
    HIDDEN_INVOCATION = "hidden_invocation"
    CREDENTIAL_ACCESS = "credential_access"
    TOOLCHAIN_DELEGATION = "toolchain_delegation"


class CapabilitySignalFinding(BaseModel):
    """Structured explainability finding for one inference signal."""

    model_config = ConfigDict(extra="forbid")

    signal_source: str = Field(..., description="Source of signal: text/schema/constraints/context/declaration.")
    matched_feature: str = Field(..., description="Matched feature token/pattern/attribute.")
    inferred_capability: PolicyCapability = Field(..., description="Inferred policy capability.")
    confidence_hint: str = Field(default="medium", description="Qualitative confidence hint.")


class CapabilityClassificationResult(BaseModel):
    """Structured output for capability inference and policy normalization."""

    model_config = ConfigDict(extra="forbid")

    detected_capabilities: list[PolicyCapability] = Field(
        default_factory=list,
        description="Backward-compatible detected policy capabilities (typed).",
    )
    risk_level: RiskLevel = Field(..., description="Aggregated risk level.")
    findings: list[str] = Field(
        default_factory=list,
        description="Human-readable findings for compatibility with existing modules.",
    )
    structured_findings: list[CapabilitySignalFinding] = Field(
        default_factory=list,
        description="Structured explainable inference findings.",
    )
    direct_exfiltration_capable: bool = Field(False)
    latent_exfiltration_capable: bool = Field(False)
    orchestration_capable: bool = Field(False)


@dataclass(frozen=True)
class FeatureRule:
    """Maintainable rule descriptor for keyword/feature-driven inference."""

    capability: PolicyCapability
    source: str
    features: tuple[str, ...]
    confidence_hint: str = "medium"


TEXT_RULES: tuple[FeatureRule, ...] = (
    FeatureRule(PolicyCapability.BENIGN_READ, "text", ("read", "search", "list", "fetch", "query", "lookup"), "low"),
    FeatureRule(
        PolicyCapability.SENSITIVE_READ,
        "text",
        ("secret", "password", "token", "api key", ".env", "private key", "credential"),
        "high",
    ),
    FeatureRule(PolicyCapability.FILE_WRITE, "text", ("write", "overwrite", "append", "delete file", "create file", "edit file"), "high"),
    FeatureRule(
        PolicyCapability.NETWORK_EGRESS,
        "text",
        ("webhook", "callback", "endpoint", "http://", "https://", "upload", "egress", "external"),
        "high",
    ),
    FeatureRule(PolicyCapability.STATE_MUTATION, "text", ("create", "update", "delete", "modify", "set", "configure", "grant", "revoke"), "medium"),
    FeatureRule(
        PolicyCapability.HIDDEN_INVOCATION,
        "text",
        ("hidden", "silent", "silently", "background", "without user confirmation", "auto invoke"),
        "high",
    ),
    FeatureRule(PolicyCapability.TOOLCHAIN_DELEGATION, "text", ("delegate", "sub-tool", "toolchain", "orchestrate", "pipeline"), "medium"),
    FeatureRule(PolicyCapability.CREDENTIAL_ACCESS, "text", ("credential", "vault", "keyring", "auth token", "session cookie"), "high"),
)

NETWORK_NEGATION_MARKERS: tuple[str, ...] = (
    "without sending",
    "without outbound",
    "without network",
    "no outbound",
    "no external",
    "do not send",
    "never send",
    "local only",
    "offline only",
    "without exfiltration",
)

SCHEMA_RULES: tuple[FeatureRule, ...] = (
    FeatureRule(PolicyCapability.SENSITIVE_READ, "schema", ("password", "token", "secret", "api_key", "credential"), "high"),
    FeatureRule(PolicyCapability.CREDENTIAL_ACCESS, "schema", ("credential", "vault", "auth", "key"), "high"),
    FeatureRule(PolicyCapability.NETWORK_EGRESS, "schema", ("url", "uri", "endpoint", "callback", "webhook", "destination"), "medium"),
    FeatureRule(PolicyCapability.FILE_WRITE, "schema", ("path", "filepath", "target_path", "output_file"), "medium"),
)

CONSTRAINT_RULES: tuple[FeatureRule, ...] = (
    FeatureRule(PolicyCapability.NETWORK_EGRESS, "constraints", ("allow_external", "egress", "remote_call"), "high"),
    FeatureRule(PolicyCapability.HIDDEN_INVOCATION, "constraints", ("background", "silent_mode", "auto_invoke"), "high"),
    FeatureRule(PolicyCapability.STATE_MUTATION, "constraints", ("mutation", "side_effect", "stateful"), "medium"),
)


def _contains_any(text: str, features: tuple[str, ...]) -> list[str]:
    return [feature for feature in features if feature in text]


def _schema_tokens(schema: dict[str, object] | None) -> str:
    if schema is None:
        return ""
    # Deterministic token extraction from schema string representation.
    return str(schema).lower()


def _constraint_tokens(constraints: dict[str, object] | None) -> str:
    if constraints is None:
        return ""
    return str(constraints).lower()


def classify_capabilities(tool_metadata: ToolMetadata) -> CapabilityClassificationResult:
    """Infer policy capabilities from declarations, schema, constraints, and context."""
    text = " ".join(
        [
            tool_metadata.name.lower(),
            tool_metadata.description.lower(),
            " ".join(tool_metadata.tags).lower(),
        ]
    )
    schema_text = " ".join([_schema_tokens(tool_metadata.input_schema), _schema_tokens(tool_metadata.output_schema)])
    constraint_text = _constraint_tokens(tool_metadata.invocation_constraints)
    context_text = " ".join(
        [
            (tool_metadata.provider_identity or tool_metadata.provider).lower(),
            (tool_metadata.server_origin or tool_metadata.source_uri or "").lower(),
            (tool_metadata.namespace or "").lower(),
        ]
    )

    inferred: set[PolicyCapability] = set()
    structured_findings: list[CapabilitySignalFinding] = []
    has_network_negation = any(marker in text for marker in NETWORK_NEGATION_MARKERS)

    def add_capability(capability: PolicyCapability, source: str, feature: str, confidence_hint: str = "medium") -> None:
        inferred.add(capability)
        structured_findings.append(
            CapabilitySignalFinding(
                signal_source=source,
                matched_feature=feature,
                inferred_capability=capability,
                confidence_hint=confidence_hint,
            )
        )

    # 1) Explicit declarations from legacy capability set.
    if CapabilityType.READ in tool_metadata.capabilities:
        add_capability(PolicyCapability.BENIGN_READ, "declaration", "CapabilityType.READ", "high")
    if CapabilityType.WRITE in tool_metadata.capabilities:
        add_capability(PolicyCapability.FILE_WRITE, "declaration", "CapabilityType.WRITE", "high")
        add_capability(PolicyCapability.STATE_MUTATION, "declaration", "CapabilityType.WRITE", "high")
    if CapabilityType.EXECUTE in tool_metadata.capabilities:
        add_capability(PolicyCapability.STATE_MUTATION, "declaration", "CapabilityType.EXECUTE", "high")
    if CapabilityType.NETWORK in tool_metadata.capabilities:
        add_capability(PolicyCapability.NETWORK_EGRESS, "declaration", "CapabilityType.NETWORK", "high")
    if CapabilityType.MCP_INVOKE in tool_metadata.capabilities:
        add_capability(PolicyCapability.TOOLCHAIN_DELEGATION, "declaration", "CapabilityType.MCP_INVOKE", "high")

    # 2) Text rules.
    for rule in TEXT_RULES:
        if rule.capability == PolicyCapability.NETWORK_EGRESS and has_network_negation:
            continue
        for feature in _contains_any(text, rule.features):
            add_capability(rule.capability, rule.source, feature, rule.confidence_hint)

    # 3) Schema-driven rules.
    for rule in SCHEMA_RULES:
        for feature in _contains_any(schema_text, rule.features):
            add_capability(rule.capability, rule.source, feature, rule.confidence_hint)

    # 4) Invocation-constraint rules.
    for rule in CONSTRAINT_RULES:
        for feature in _contains_any(constraint_text, rule.features):
            add_capability(rule.capability, rule.source, feature, rule.confidence_hint)

    # 5) Context-driven hints (provider/server/channel).
    if any(token in context_text for token in ["webhook", "callback", "external"]):
        add_capability(PolicyCapability.NETWORK_EGRESS, "context", "provider/server indicates external callback", "medium")

    # Latent orchestration hint: delegation + explicit transparent wording => not hidden.
    transparent_markers = {"visible", "transparent", "with user confirmation", "audited"}
    has_transparent_marker = any(marker in text for marker in transparent_markers)
    if PolicyCapability.TOOLCHAIN_DELEGATION in inferred and not has_transparent_marker:
        add_capability(PolicyCapability.HIDDEN_INVOCATION, "derived", "delegation without transparency marker", "medium")

    direct_exfiltration_capable = (
        PolicyCapability.NETWORK_EGRESS in inferred
        and (
            PolicyCapability.SENSITIVE_READ in inferred
            or PolicyCapability.CREDENTIAL_ACCESS in inferred
        )
    )
    latent_exfiltration_capable = (
        PolicyCapability.NETWORK_EGRESS in inferred
        and (
            PolicyCapability.FILE_WRITE in inferred
            or PolicyCapability.STATE_MUTATION in inferred
            or PolicyCapability.TOOLCHAIN_DELEGATION in inferred
        )
    )
    orchestration_capable = (
        PolicyCapability.TOOLCHAIN_DELEGATION in inferred
        or PolicyCapability.HIDDEN_INVOCATION in inferred
    )

    if PolicyCapability.HIDDEN_INVOCATION in inferred or direct_exfiltration_capable:
        risk_level = RiskLevel.CRITICAL
    elif (
        PolicyCapability.CREDENTIAL_ACCESS in inferred
        or PolicyCapability.SENSITIVE_READ in inferred
        or PolicyCapability.SENSITIVE_READ in inferred and PolicyCapability.FILE_WRITE in inferred
        or latent_exfiltration_capable
    ):
        risk_level = RiskLevel.HIGH
    elif (
        PolicyCapability.NETWORK_EGRESS in inferred
        or PolicyCapability.STATE_MUTATION in inferred
        or PolicyCapability.FILE_WRITE in inferred
        or orchestration_capable
    ):
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    findings = [
        f"[{item.signal_source}] '{item.matched_feature}' -> {item.inferred_capability.value}"
        for item in structured_findings
    ]
    if not findings:
        findings = ["No capability signal inferred from current metadata inputs."]

    return CapabilityClassificationResult(
        detected_capabilities=sorted(inferred, key=lambda x: x.value),
        risk_level=risk_level,
        findings=findings,
        structured_findings=structured_findings,
        direct_exfiltration_capable=direct_exfiltration_capable,
        latent_exfiltration_capable=latent_exfiltration_capable,
        orchestration_capable=orchestration_capable,
    )
