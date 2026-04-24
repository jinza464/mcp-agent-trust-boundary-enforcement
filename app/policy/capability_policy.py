"""Capability inference + policy normalization for MCP tool metadata.

Stage-3 refinement goals:
- keep classify_capabilities behavior stable for benchmark compatibility
- express rules as structured tables with stable rule ids
- make rule->match->finding->capability flow easier to test and extend
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import (
    BaseActionCapability,
    CapabilityType,
    PolicyCapabilityLabel,
    ResourceScope,
    RiskLevel,
    ToolMetadata,
)


class PolicyCapability(str, Enum):
    BENIGN_READ = "benign_read"
    SENSITIVE_READ = "read_secret"
    FILE_WRITE = "file_write"
    NETWORK_EGRESS = "network_send"
    STATE_MUTATION = "state_change"
    HIDDEN_INVOCATION = "hidden_invocation"
    CREDENTIAL_ACCESS = "credential_access"
    TOOLCHAIN_DELEGATION = "toolchain_delegation"


class RuleSource(str, Enum):
    TEXT = "text"
    SCHEMA = "schema"
    CONSTRAINTS = "constraints"
    CONTEXT = "context"
    DECLARATION = "declaration"
    POLICY_LABEL = "policy_label"
    CAPABILITY_PROFILE = "capability_profile"
    DERIVED = "derived"


@dataclass(frozen=True)
class RuleMatcherConfig:
    source: RuleSource
    confidence_hint: str = "medium"
    skip_when_network_negated: bool = False


@dataclass(frozen=True)
class CapabilityRule:
    rule_id: str
    capability: PolicyCapability
    matcher: RuleMatcherConfig
    features: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    capability: PolicyCapability
    signal_source: RuleSource
    matched_feature: str
    confidence_hint: str


class CapabilitySignalFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signal_source: str = Field(...)
    matched_feature: str = Field(...)
    inferred_capability: PolicyCapability = Field(...)
    confidence_hint: str = Field(default="medium")
    rule_id: str | None = Field(default=None)


class CapabilityClassificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected_capabilities: list[PolicyCapability] = Field(default_factory=list)
    risk_level: RiskLevel = Field(...)
    findings: list[str] = Field(default_factory=list)
    structured_findings: list[CapabilitySignalFinding] = Field(default_factory=list)
    direct_exfiltration_capable: bool = Field(False)
    latent_exfiltration_capable: bool = Field(False)
    orchestration_capable: bool = Field(False)


def _rule(
    *,
    rule_id: str,
    capability: PolicyCapability,
    source: RuleSource,
    features: tuple[str, ...] = (),
    confidence_hint: str = "medium",
    skip_when_network_negated: bool = False,
) -> CapabilityRule:
    return CapabilityRule(
        rule_id=rule_id,
        capability=capability,
        matcher=RuleMatcherConfig(
            source=source,
            confidence_hint=confidence_hint,
            skip_when_network_negated=skip_when_network_negated,
        ),
        features=features,
    )


TOKEN_RULE_TABLE: tuple[CapabilityRule, ...] = (
    _rule(
        rule_id="text:benign_read_keywords",
        capability=PolicyCapability.BENIGN_READ,
        source=RuleSource.TEXT,
        features=("read", "search", "list", "fetch", "query", "lookup"),
        confidence_hint="low",
    ),
    _rule(
        rule_id="text:sensitive_read_keywords",
        capability=PolicyCapability.SENSITIVE_READ,
        source=RuleSource.TEXT,
        features=("secret", "password", "token", "api key", ".env", "private key", "credential"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="text:file_write_keywords",
        capability=PolicyCapability.FILE_WRITE,
        source=RuleSource.TEXT,
        features=("write", "overwrite", "append", "delete file", "create file", "edit file"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="text:network_egress_keywords",
        capability=PolicyCapability.NETWORK_EGRESS,
        source=RuleSource.TEXT,
        features=("webhook", "callback", "endpoint", "http://", "https://", "upload", "egress", "external"),
        confidence_hint="high",
        skip_when_network_negated=True,
    ),
    _rule(
        rule_id="text:state_mutation_keywords",
        capability=PolicyCapability.STATE_MUTATION,
        source=RuleSource.TEXT,
        features=("create", "update", "delete", "modify", "set", "configure", "grant", "revoke"),
        confidence_hint="medium",
    ),
    _rule(
        rule_id="text:hidden_invocation_keywords",
        capability=PolicyCapability.HIDDEN_INVOCATION,
        source=RuleSource.TEXT,
        features=("hidden", "silent", "silently", "background", "without user confirmation", "auto invoke"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="text:toolchain_delegation_keywords",
        capability=PolicyCapability.TOOLCHAIN_DELEGATION,
        source=RuleSource.TEXT,
        features=("delegate", "sub-tool", "toolchain", "orchestrate", "pipeline"),
        confidence_hint="medium",
    ),
    _rule(
        rule_id="text:credential_access_keywords",
        capability=PolicyCapability.CREDENTIAL_ACCESS,
        source=RuleSource.TEXT,
        features=("credential", "vault", "keyring", "auth token", "session cookie"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="schema:sensitive_read_tokens",
        capability=PolicyCapability.SENSITIVE_READ,
        source=RuleSource.SCHEMA,
        features=("password", "token", "secret", "api_key", "credential"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="schema:credential_access_tokens",
        capability=PolicyCapability.CREDENTIAL_ACCESS,
        source=RuleSource.SCHEMA,
        features=("credential", "vault", "auth", "key"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="schema:network_egress_tokens",
        capability=PolicyCapability.NETWORK_EGRESS,
        source=RuleSource.SCHEMA,
        features=("url", "uri", "endpoint", "callback", "webhook", "destination"),
        confidence_hint="medium",
    ),
    _rule(
        rule_id="schema:file_write_tokens",
        capability=PolicyCapability.FILE_WRITE,
        source=RuleSource.SCHEMA,
        features=("path", "filepath", "target_path", "output_file"),
        confidence_hint="medium",
    ),
    _rule(
        rule_id="constraints:network_egress_flags",
        capability=PolicyCapability.NETWORK_EGRESS,
        source=RuleSource.CONSTRAINTS,
        features=("allow_external", "egress", "remote_call"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="constraints:hidden_invocation_flags",
        capability=PolicyCapability.HIDDEN_INVOCATION,
        source=RuleSource.CONSTRAINTS,
        features=("background", "silent_mode", "auto_invoke"),
        confidence_hint="high",
    ),
    _rule(
        rule_id="constraints:state_mutation_flags",
        capability=PolicyCapability.STATE_MUTATION,
        source=RuleSource.CONSTRAINTS,
        features=("mutation", "side_effect", "stateful"),
        confidence_hint="medium",
    ),
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


POLICY_LABEL_RULES: dict[PolicyCapabilityLabel, CapabilityRule] = {
    PolicyCapabilityLabel.BENIGN_READ: _rule(
        rule_id="policy_label:benign_read",
        capability=PolicyCapability.BENIGN_READ,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.READ_SECRET: _rule(
        rule_id="policy_label:read_secret",
        capability=PolicyCapability.SENSITIVE_READ,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.FILE_WRITE: _rule(
        rule_id="policy_label:file_write",
        capability=PolicyCapability.FILE_WRITE,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.NETWORK_SEND: _rule(
        rule_id="policy_label:network_send",
        capability=PolicyCapability.NETWORK_EGRESS,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.STATE_CHANGE: _rule(
        rule_id="policy_label:state_change",
        capability=PolicyCapability.STATE_MUTATION,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.HIDDEN_INVOCATION: _rule(
        rule_id="policy_label:hidden_invocation",
        capability=PolicyCapability.HIDDEN_INVOCATION,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.CREDENTIAL_ACCESS: _rule(
        rule_id="policy_label:credential_access",
        capability=PolicyCapability.CREDENTIAL_ACCESS,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
    PolicyCapabilityLabel.TOOLCHAIN_DELEGATION: _rule(
        rule_id="policy_label:toolchain_delegation",
        capability=PolicyCapability.TOOLCHAIN_DELEGATION,
        source=RuleSource.POLICY_LABEL,
        confidence_hint="high",
    ),
}


DECLARATION_RULE_TABLE: dict[CapabilityType, tuple[CapabilityRule, ...]] = {
    CapabilityType.READ: (
        _rule(
            rule_id="declaration:read_to_benign_read",
            capability=PolicyCapability.BENIGN_READ,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.READ",),
            confidence_hint="high",
        ),
    ),
    CapabilityType.WRITE: (
        _rule(
            rule_id="declaration:write_to_file_write",
            capability=PolicyCapability.FILE_WRITE,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.WRITE",),
            confidence_hint="high",
        ),
        _rule(
            rule_id="declaration:write_to_state_change",
            capability=PolicyCapability.STATE_MUTATION,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.WRITE",),
            confidence_hint="high",
        ),
    ),
    CapabilityType.EXECUTE: (
        _rule(
            rule_id="declaration:execute_to_state_change",
            capability=PolicyCapability.STATE_MUTATION,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.EXECUTE",),
            confidence_hint="high",
        ),
    ),
    CapabilityType.NETWORK: (
        _rule(
            rule_id="declaration:network_to_egress",
            capability=PolicyCapability.NETWORK_EGRESS,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.NETWORK",),
            confidence_hint="high",
        ),
    ),
    CapabilityType.MCP_INVOKE: (
        _rule(
            rule_id="declaration:mcp_invoke_to_toolchain_delegation",
            capability=PolicyCapability.TOOLCHAIN_DELEGATION,
            source=RuleSource.DECLARATION,
            features=("CapabilityType.MCP_INVOKE",),
            confidence_hint="high",
        ),
    ),
}


CONTEXT_RULE = _rule(
    rule_id="context:external_callback_origin",
    capability=PolicyCapability.NETWORK_EGRESS,
    source=RuleSource.CONTEXT,
    features=("webhook", "callback", "external"),
    confidence_hint="medium",
)


DERIVED_HIDDEN_INVOCATION_RULE = _rule(
    rule_id="derived:delegation_without_transparency",
    capability=PolicyCapability.HIDDEN_INVOCATION,
    source=RuleSource.DERIVED,
    features=("delegation without transparency marker",),
    confidence_hint="medium",
)


TRANSPARENCY_MARKERS: tuple[str, ...] = (
    "visible",
    "transparent",
    "with user confirmation",
    "audited",
)


def _contains_any(text: str, features: tuple[str, ...]) -> list[str]:
    return [feature for feature in features if feature in text]


def _schema_tokens(schema: dict[str, object] | None) -> str:
    if schema is None:
        return ""
    return str(schema).lower()


def _constraint_tokens(constraints: dict[str, object] | None) -> str:
    if constraints is None:
        return ""
    return str(constraints).lower()


def _token_rule_matches(
    *,
    source: RuleSource,
    target_text: str,
    has_network_negation: bool,
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in TOKEN_RULE_TABLE:
        if rule.matcher.source != source:
            continue
        if rule.matcher.skip_when_network_negated and has_network_negation:
            continue
        for feature in _contains_any(target_text, rule.features):
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    capability=rule.capability,
                    signal_source=rule.matcher.source,
                    matched_feature=feature,
                    confidence_hint=rule.matcher.confidence_hint,
                )
            )
    return matches


def _policy_label_rule_matches(labels: set[PolicyCapabilityLabel]) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for label in sorted(labels, key=lambda item: item.value):
        rule = POLICY_LABEL_RULES.get(label)
        if rule is None:
            continue
        matches.append(
            RuleMatch(
                rule_id=rule.rule_id,
                capability=rule.capability,
                signal_source=rule.matcher.source,
                matched_feature=rule.capability.value,
                confidence_hint=rule.matcher.confidence_hint,
            )
        )
    return matches


def _profile_rule_matches(tool_metadata: ToolMetadata) -> list[RuleMatch]:
    profile = tool_metadata.capability_profile
    if profile is None:
        return []

    matches: list[RuleMatch] = []
    if BaseActionCapability.READ in profile.actions and ResourceScope.SECRET in profile.resource_scopes:
        matches.append(
            RuleMatch(
                rule_id="capability_profile:read_secret",
                capability=PolicyCapability.SENSITIVE_READ,
                signal_source=RuleSource.CAPABILITY_PROFILE,
                matched_feature=PolicyCapability.SENSITIVE_READ.value,
                confidence_hint="high",
            )
        )
    elif BaseActionCapability.READ in profile.actions:
        matches.append(
            RuleMatch(
                rule_id="capability_profile:read_benign",
                capability=PolicyCapability.BENIGN_READ,
                signal_source=RuleSource.CAPABILITY_PROFILE,
                matched_feature=PolicyCapability.BENIGN_READ.value,
                confidence_hint="high",
            )
        )

    if BaseActionCapability.WRITE in profile.actions and ResourceScope.FILE in profile.resource_scopes:
        matches.append(
            RuleMatch(
                rule_id="capability_profile:file_write",
                capability=PolicyCapability.FILE_WRITE,
                signal_source=RuleSource.CAPABILITY_PROFILE,
                matched_feature=PolicyCapability.FILE_WRITE.value,
                confidence_hint="high",
            )
        )

    if BaseActionCapability.TRANSMIT in profile.actions and ResourceScope.NETWORK in profile.resource_scopes:
        matches.append(
            RuleMatch(
                rule_id="capability_profile:network_send",
                capability=PolicyCapability.NETWORK_EGRESS,
                signal_source=RuleSource.CAPABILITY_PROFILE,
                matched_feature=PolicyCapability.NETWORK_EGRESS.value,
                confidence_hint="high",
            )
        )

    if BaseActionCapability.WRITE in profile.actions and ResourceScope.STATE in profile.resource_scopes:
        matches.append(
            RuleMatch(
                rule_id="capability_profile:state_change",
                capability=PolicyCapability.STATE_MUTATION,
                signal_source=RuleSource.CAPABILITY_PROFILE,
                matched_feature=PolicyCapability.STATE_MUTATION.value,
                confidence_hint="high",
            )
        )
    return matches


def _declaration_rule_matches(declared: set[CapabilityType]) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for capability_type in (
        CapabilityType.READ,
        CapabilityType.WRITE,
        CapabilityType.EXECUTE,
        CapabilityType.NETWORK,
        CapabilityType.MCP_INVOKE,
    ):
        if capability_type not in declared:
            continue
        for rule in DECLARATION_RULE_TABLE.get(capability_type, ()):
            matches.append(
                RuleMatch(
                    rule_id=rule.rule_id,
                    capability=rule.capability,
                    signal_source=rule.matcher.source,
                    matched_feature=rule.features[0] if rule.features else capability_type.value,
                    confidence_hint=rule.matcher.confidence_hint,
                )
            )
    return matches


def classify_capabilities(tool_metadata: ToolMetadata) -> CapabilityClassificationResult:
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

    def add_match(match: RuleMatch) -> None:
        inferred.add(match.capability)
        structured_findings.append(
            CapabilitySignalFinding(
                signal_source=match.signal_source.value,
                matched_feature=match.matched_feature,
                inferred_capability=match.capability,
                confidence_hint=match.confidence_hint,
                rule_id=match.rule_id,
            )
        )

    for match in _policy_label_rule_matches(tool_metadata.policy_capability_labels):
        add_match(match)

    for match in _profile_rule_matches(tool_metadata):
        add_match(match)

    for match in _declaration_rule_matches(tool_metadata.capabilities):
        add_match(match)

    for match in _token_rule_matches(source=RuleSource.TEXT, target_text=text, has_network_negation=has_network_negation):
        add_match(match)

    for match in _token_rule_matches(source=RuleSource.SCHEMA, target_text=schema_text, has_network_negation=False):
        add_match(match)

    for match in _token_rule_matches(source=RuleSource.CONSTRAINTS, target_text=constraint_text, has_network_negation=False):
        add_match(match)

    if any(token in context_text for token in CONTEXT_RULE.features):
        add_match(
            RuleMatch(
                rule_id=CONTEXT_RULE.rule_id,
                capability=CONTEXT_RULE.capability,
                signal_source=CONTEXT_RULE.matcher.source,
                matched_feature="provider/server indicates external callback",
                confidence_hint=CONTEXT_RULE.matcher.confidence_hint,
            )
        )

    has_transparent_marker = any(marker in text for marker in TRANSPARENCY_MARKERS)
    if PolicyCapability.TOOLCHAIN_DELEGATION in inferred and not has_transparent_marker:
        add_match(
            RuleMatch(
                rule_id=DERIVED_HIDDEN_INVOCATION_RULE.rule_id,
                capability=DERIVED_HIDDEN_INVOCATION_RULE.capability,
                signal_source=DERIVED_HIDDEN_INVOCATION_RULE.matcher.source,
                matched_feature=DERIVED_HIDDEN_INVOCATION_RULE.features[0],
                confidence_hint=DERIVED_HIDDEN_INVOCATION_RULE.matcher.confidence_hint,
            )
        )

    direct_exfiltration_capable = PolicyCapability.NETWORK_EGRESS in inferred and (
        PolicyCapability.SENSITIVE_READ in inferred or PolicyCapability.CREDENTIAL_ACCESS in inferred
    )
    latent_exfiltration_capable = PolicyCapability.NETWORK_EGRESS in inferred and (
        PolicyCapability.FILE_WRITE in inferred
        or PolicyCapability.STATE_MUTATION in inferred
        or PolicyCapability.TOOLCHAIN_DELEGATION in inferred
    )
    orchestration_capable = (
        PolicyCapability.TOOLCHAIN_DELEGATION in inferred or PolicyCapability.HIDDEN_INVOCATION in inferred
    )

    if PolicyCapability.HIDDEN_INVOCATION in inferred or direct_exfiltration_capable:
        risk_level = RiskLevel.CRITICAL
    elif (
        PolicyCapability.CREDENTIAL_ACCESS in inferred
        or PolicyCapability.SENSITIVE_READ in inferred
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
        detected_capabilities=sorted(inferred, key=lambda item: item.value),
        risk_level=risk_level,
        findings=findings,
        structured_findings=structured_findings,
        direct_exfiltration_capable=direct_exfiltration_capable,
        latent_exfiltration_capable=latent_exfiltration_capable,
        orchestration_capable=orchestration_capable,
    )
