"""Metadata-first validation for MCP tool evolution risk detection."""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, ToolMetadata, ToolSnapshot
from app.mcp.protocol_models import RequestLineage
from app.registry.tool_registry import ChangeCategory, ToolRegistry


class DriftDomain(str, Enum):
    DESCRIPTIVE = "descriptive_drift"
    INTERFACE = "interface_drift"
    ORIGIN = "origin_drift"
    BEHAVIORAL = "behavioral_drift"


class MetadataValidationFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    drift_domain: DriftDomain = Field(...)
    finding_type: str = Field(...)
    severity: RiskLevel = Field(...)
    message: str = Field(...)
    evidence: dict[str, Any] = Field(default_factory=dict)


class MetadataValidationResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    passed: bool = Field(...)
    findings: list[str] = Field(default_factory=list)
    risk_level: RiskLevel = Field(...)
    recommended_action: DecisionAction = Field(...)
    changed_fields: list[str] = Field(default_factory=list)
    change_categories: list[str] = Field(default_factory=list)
    drift_domains: list[DriftDomain] = Field(default_factory=list)
    structured_findings: list[MetadataValidationFinding] = Field(default_factory=list)


def _risk_rank(level: RiskLevel) -> int:
    return {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}[level]


def _max_risk_level(levels: list[RiskLevel]) -> RiskLevel:
    return max(levels, key=_risk_rank) if levels else RiskLevel.LOW


def _recommended_action_from_risk(risk_level: RiskLevel) -> DecisionAction:
    if risk_level == RiskLevel.CRITICAL:
        return DecisionAction.DENY
    if risk_level == RiskLevel.HIGH:
        return DecisionAction.REQUIRE_CONFIRMATION
    if risk_level == RiskLevel.MEDIUM:
        return DecisionAction.SANDBOX
    return DecisionAction.ALLOW


def _parse_semver(version: str) -> tuple[int, int, int] | None:
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)$", version.strip())
    if not match:
        return None
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _contains_prompt_like_instruction(description: str) -> bool:
    text = description.lower()
    patterns = [
        "ignore previous instructions",
        "ignore all prior instructions",
        "you are now",
        "system prompt",
        "developer message",
        "do not tell the user",
        "without user confirmation",
        "act as",
        "override policy",
        "bypass validation",
        "treat this tool as trusted",
    ]
    return any(pattern in text for pattern in patterns)


def _stable_hash(payload: Any) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _schema_properties(schema: dict[str, object] | None) -> dict[str, object]:
    if not isinstance(schema, dict):
        return {}
    props = schema.get("properties")
    return props if isinstance(props, dict) else {}


def _schema_required(schema: dict[str, object] | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    required = schema.get("required")
    if isinstance(required, list):
        return {str(item) for item in required}
    return set()


def _fingerprint(value: Any) -> str:
    return "none" if value is None else _stable_hash(value)


def _append_finding(
    *,
    findings: list[MetadataValidationFinding],
    drift_domain: DriftDomain,
    finding_type: str,
    severity: RiskLevel,
    message: str,
    evidence: dict[str, Any] | None = None,
) -> None:
    findings.append(
        MetadataValidationFinding(
            drift_domain=drift_domain,
            finding_type=finding_type,
            severity=severity,
            message=message,
            evidence=evidence or {},
        )
    )


def _as_object(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return {str(key): item for key, item in value.items()}
    return {}


def _to_string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        return [text] if text else []
    if isinstance(value, (list, tuple, set)):
        output: list[str] = []
        for item in value:
            text = str(item).strip()
            if text:
                output.append(text)
        return output
    if isinstance(value, dict):
        output: list[str] = []
        for key, item in value.items():
            key_text = str(key).strip()
            if key_text:
                output.append(key_text)
            if isinstance(item, str):
                item_text = item.strip()
                if item_text:
                    output.append(item_text)
        return output
    text = str(value).strip()
    return [text] if text else []


def _normalize_scope(value: str) -> str:
    text = value.strip().lower()
    if text in {"*", "/", "any", "all"}:
        return text
    return text.rstrip("/")


def _is_scope_wildcard(scope: str) -> bool:
    return scope in {"*", "/", "any", "all"} or "*" in scope


def _scope_contains(parent_scope: str, child_scope: str) -> bool:
    parent = _normalize_scope(parent_scope)
    child = _normalize_scope(child_scope)
    if parent == child:
        return True
    if _is_scope_wildcard(parent):
        return True
    if "*" in parent:
        pattern = re.escape(parent).replace(r"\*", ".*")
        return re.fullmatch(pattern, child) is not None
    return child.startswith(f"{parent}/") or child.startswith(parent)


def _detect_scope_broadening(old_scopes: list[str], new_scopes: list[str]) -> tuple[bool, list[str], bool]:
    old_normalized = sorted({_normalize_scope(item) for item in old_scopes if item.strip()})
    new_normalized = sorted({_normalize_scope(item) for item in new_scopes if item.strip()})
    if not old_normalized or not new_normalized:
        return False, [], False
    newly_exposed = [scope for scope in new_normalized if not any(_scope_contains(old_scope, scope) for old_scope in old_normalized)]
    wildcard_expansion = any(_is_scope_wildcard(scope) for scope in newly_exposed)
    return bool(newly_exposed), newly_exposed, wildcard_expansion


def _extract_sampling_controls(metadata: ToolMetadata) -> dict[str, Any]:
    constraints = _as_object(metadata.invocation_constraints)
    controls: dict[str, Any] = {}
    for key in (
        "sampling",
        "sampling_policy",
        "sampling_mode",
        "sampling_prompt_policy",
        "prompt_template",
        "system_prompt",
        "temperature",
        "top_p",
        "max_tokens",
        "stop",
    ):
        if key in constraints:
            controls[key] = constraints[key]
    sampling_tags = sorted(tag for tag in metadata.tags if ("sampling" in tag.lower() or "prompt" in tag.lower()))
    if sampling_tags:
        controls["sampling_tags"] = sampling_tags
    return controls


def _extract_root_scopes(metadata: ToolMetadata) -> list[str]:
    constraints = _as_object(metadata.invocation_constraints)
    scopes: list[str] = []
    for key in ("roots", "allowed_roots", "root_paths", "root_scope", "root_scopes"):
        scopes.extend(_to_string_list(constraints.get(key)))
    for tag in metadata.tags:
        lower = tag.lower()
        if lower.startswith("root:") or lower.startswith("roots:"):
            scopes.append(tag.split(":", 1)[1])
    return sorted({_normalize_scope(item) for item in scopes if item.strip()})


def _extract_resource_uri_scopes(metadata: ToolMetadata) -> list[str]:
    constraints = _as_object(metadata.invocation_constraints)
    scopes: list[str] = []
    for key in (
        "resource_uri",
        "resource_uris",
        "resource_uri_scope",
        "resource_uri_prefix",
        "resource_uri_prefixes",
        "allowed_resource_uris",
        "resource_scope",
        "resource_scopes",
    ):
        scopes.extend(_to_string_list(constraints.get(key)))
    for tag in metadata.tags:
        lower = tag.lower()
        if lower.startswith("resource:") or lower.startswith("resource_uri:") or lower.startswith("uri:"):
            scopes.append(tag.split(":", 1)[1])
    return sorted({_normalize_scope(item) for item in scopes if item.strip()})


def _extract_capability_advertisement(metadata: ToolMetadata) -> list[str]:
    constraints = _as_object(metadata.invocation_constraints)
    advertised: list[str] = []
    for key in (
        "server_capabilities",
        "advertised_capabilities",
        "supported_features",
        "mcp_features",
        "feature_scope",
        "feature_scopes",
    ):
        advertised.extend(_to_string_list(constraints.get(key)))
    for tag in metadata.tags:
        lower = tag.lower()
        if lower.startswith("feature:") or lower.startswith("mcp_feature:") or lower.startswith("capability_adv:"):
            advertised.append(tag.split(":", 1)[1])
    return sorted({_normalize_scope(item) for item in advertised if item.strip()})


def _resolve_feature_scope(
    *,
    old_snapshot: ToolSnapshot,
    request_lineage: RequestLineage | None,
    feature_scope: str | None,
) -> str | None:
    if isinstance(feature_scope, str) and feature_scope.strip():
        return feature_scope.strip().lower()
    if request_lineage is not None:
        raw = request_lineage.feature
        text = str(raw).strip().lower()
        if text:
            return text
    runtime_context = old_snapshot.runtime_context if isinstance(old_snapshot.runtime_context, dict) else {}
    raw = runtime_context.get("feature_scope")
    if isinstance(raw, str):
        text = raw.strip().lower()
        if text:
            return text
    return None


def _domain_from_change_categories(categories: list[str]) -> DriftDomain:
    category_set = set(categories)
    if {ChangeCategory.SERVER_RELOCATION.value, ChangeCategory.NAMESPACE_CONFLICT.value}.intersection(category_set):
        return DriftDomain.ORIGIN
    if ChangeCategory.SCHEMA_CHANGE.value in category_set:
        return DriftDomain.INTERFACE
    if ChangeCategory.DESCRIPTIVE_CHANGE.value in category_set:
        return DriftDomain.DESCRIPTIVE
    return DriftDomain.BEHAVIORAL


def validate_metadata(
    old_snapshot: ToolSnapshot | None,
    new_metadata: ToolMetadata,
    *,
    request_lineage: RequestLineage | None = None,
    feature_scope: str | None = None,
) -> MetadataValidationResult:
    if old_snapshot is None:
        return MetadataValidationResult(
            passed=True,
            findings=[],
            risk_level=RiskLevel.LOW,
            recommended_action=DecisionAction.ALLOW,
            changed_fields=[],
            change_categories=[],
            drift_domains=[],
            structured_findings=[],
        )

    structured_findings: list[MetadataValidationFinding] = []
    risk_levels: list[RiskLevel] = []
    consumed_change_categories: set[str] = set()

    registry = ToolRegistry()
    diff = registry.detect_changes(old_snapshot, new_metadata)

    old_origin = old_snapshot.server_origin or old_snapshot.tool.server_origin or old_snapshot.tool.source_uri or "unknown"
    new_origin = new_metadata.server_origin or new_metadata.source_uri or "unknown"
    old_namespace = old_snapshot.tool.namespace or old_snapshot.tool.provider_identity or old_snapshot.tool.provider
    new_namespace = new_metadata.namespace or new_metadata.provider_identity or new_metadata.provider
    old_provider = old_snapshot.tool.provider_identity or old_snapshot.tool.provider
    new_provider = new_metadata.provider_identity or new_metadata.provider

    if "description_hash" in diff.changed_fields:
        consumed_change_categories.add(ChangeCategory.DESCRIPTIVE_CHANGE.value)
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.DESCRIPTIVE,
            finding_type="description_drift",
            severity=RiskLevel.MEDIUM,
            message="Description changed from previous snapshot.",
            evidence={
                "old_description_hash": old_snapshot.description_hash or _fingerprint(old_snapshot.tool.description),
                "new_description_hash": _fingerprint(new_metadata.description),
            },
        )
        risk_levels.append(RiskLevel.MEDIUM)

    old_input_hash = old_snapshot.input_schema_hash or _fingerprint(old_snapshot.tool.input_schema)
    new_input_hash = _fingerprint(new_metadata.input_schema)
    old_output_hash = old_snapshot.output_schema_hash or _fingerprint(old_snapshot.tool.output_schema)
    new_output_hash = _fingerprint(new_metadata.output_schema)
    if old_input_hash != new_input_hash or old_output_hash != new_output_hash or "schema_hash" in diff.changed_fields:
        consumed_change_categories.add(ChangeCategory.SCHEMA_CHANGE.value)
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.INTERFACE,
            finding_type="formal_schema_drift",
            severity=RiskLevel.HIGH,
            message="Formal tool schema drift detected.",
            evidence={
                "old_input_schema_hash": old_input_hash,
                "new_input_schema_hash": new_input_hash,
                "old_output_schema_hash": old_output_hash,
                "new_output_schema_hash": new_output_hash,
            },
        )
        risk_levels.append(RiskLevel.HIGH)

    old_props = _schema_properties(old_snapshot.tool.input_schema)
    new_props = _schema_properties(new_metadata.input_schema)
    added_params = sorted(set(new_props) - set(old_props))
    removed_params = sorted(set(old_props) - set(new_props))
    common_params = set(old_props).intersection(new_props)
    changed_params = sorted(key for key in common_params if _fingerprint(old_props.get(key)) != _fingerprint(new_props.get(key)))
    old_required = _schema_required(old_snapshot.tool.input_schema)
    new_required = _schema_required(new_metadata.input_schema)
    newly_required = sorted(new_required - old_required)
    if added_params or removed_params or changed_params or newly_required:
        severity = RiskLevel.HIGH if newly_required or removed_params else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.INTERFACE,
            finding_type="parameter_level_drift",
            severity=severity,
            message="Input parameter contract drift detected.",
            evidence={
                "added_params": added_params,
                "removed_params": removed_params,
                "changed_params": changed_params,
                "newly_required_params": newly_required,
            },
        )
        risk_levels.append(severity)

    old_out_required = _schema_required(old_snapshot.tool.output_schema)
    new_out_required = _schema_required(new_metadata.output_schema)
    out_props_old = _schema_properties(old_snapshot.tool.output_schema)
    out_props_new = _schema_properties(new_metadata.output_schema)
    if old_out_required != new_out_required or set(out_props_old.keys()) != set(out_props_new.keys()):
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.INTERFACE,
            finding_type="output_contract_drift",
            severity=RiskLevel.HIGH,
            message="Output contract drift detected.",
            evidence={
                "old_required": sorted(old_out_required),
                "new_required": sorted(new_out_required),
                "old_output_fields": sorted(out_props_old.keys()),
                "new_output_fields": sorted(out_props_new.keys()),
            },
        )
        risk_levels.append(RiskLevel.HIGH)

    if _fingerprint(old_snapshot.tool.invocation_constraints) != _fingerprint(new_metadata.invocation_constraints):
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.BEHAVIORAL,
            finding_type="invocation_constraint_drift",
            severity=RiskLevel.HIGH,
            message="Invocation constraints changed from previous snapshot.",
            evidence={
                "old_invocation_constraints_hash": _fingerprint(old_snapshot.tool.invocation_constraints),
                "new_invocation_constraints_hash": _fingerprint(new_metadata.invocation_constraints),
            },
        )
        risk_levels.append(RiskLevel.HIGH)

    if old_origin != new_origin:
        consumed_change_categories.add(ChangeCategory.SERVER_RELOCATION.value)
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.ORIGIN,
            finding_type="provider_server_relocation",
            severity=RiskLevel.HIGH,
            message="Server origin relocation detected for same tool identity.",
            evidence={"old_server_origin": old_origin, "new_server_origin": new_origin},
        )
        risk_levels.append(RiskLevel.HIGH)

    if old_namespace != new_namespace or old_provider != new_provider:
        consumed_change_categories.add(ChangeCategory.NAMESPACE_CONFLICT.value)
        strong_identity_confusion = (
            old_origin != new_origin
            and old_namespace != new_namespace
            and old_provider != new_provider
            and (old_snapshot.tool.tool_identity or old_snapshot.tool.tool_id) == (new_metadata.tool_identity or new_metadata.tool_id)
        )
        severity = RiskLevel.CRITICAL if strong_identity_confusion else RiskLevel.HIGH
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.ORIGIN,
            finding_type="namespace_confusion",
            severity=severity,
            message="Namespace/provider identity changed and may indicate confusion risk.",
            evidence={
                "old_namespace": old_namespace,
                "new_namespace": new_namespace,
                "old_provider_identity": old_provider,
                "new_provider_identity": new_provider,
                "strong_identity_confusion": strong_identity_confusion,
            },
        )
        risk_levels.append(severity)

    old_version = old_snapshot.tool.version
    new_version = new_metadata.version
    old_semver = _parse_semver(old_version)
    new_semver = _parse_semver(new_version)
    capability_changed = set(old_snapshot.tool.capabilities) != set(new_metadata.capabilities)
    if old_semver and new_semver:
        if new_semver < old_semver:
            consumed_change_categories.add(ChangeCategory.ROLLBACK.value)
            severity = RiskLevel.CRITICAL if not capability_changed else RiskLevel.HIGH
            _append_finding(
                findings=structured_findings,
                drift_domain=DriftDomain.BEHAVIORAL,
                finding_type="rollback_without_explicit_capability_change" if not capability_changed else "version_rollback",
                severity=severity,
                message=(
                    f"Version rollback detected without explicit capability change: {old_version} -> {new_version}."
                    if not capability_changed else f"Version rollback detected: {old_version} -> {new_version}."
                ),
                evidence={
                    "old_version": old_version,
                    "new_version": new_version,
                    "capability_changed": capability_changed,
                },
            )
            risk_levels.append(severity)
        elif new_semver[0] - old_semver[0] > 1:
            _append_finding(
                findings=structured_findings,
                drift_domain=DriftDomain.BEHAVIORAL,
                finding_type="version_anomaly_major_jump",
                severity=RiskLevel.MEDIUM,
                message=f"Version anomaly detected: major jump {old_version} -> {new_version}.",
                evidence={"old_version": old_version, "new_version": new_version},
            )
            risk_levels.append(RiskLevel.MEDIUM)
    elif old_version != new_version:
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.BEHAVIORAL,
            finding_type="version_format_anomaly",
            severity=RiskLevel.MEDIUM,
            message=f"Version format anomaly detected: {old_version} -> {new_version}.",
            evidence={"old_version": old_version, "new_version": new_version},
        )
        risk_levels.append(RiskLevel.MEDIUM)

    if _contains_prompt_like_instruction(new_metadata.description):
        strong_compromise_context = (
            old_origin != new_origin
            or old_namespace != new_namespace
            or old_provider != new_provider
            or (ChangeCategory.ROLLBACK.value in diff.change_categories and not capability_changed)
            or (ChangeCategory.SCHEMA_CHANGE.value in diff.change_categories and ChangeCategory.SERVER_RELOCATION.value in diff.change_categories)
        )
        severity = RiskLevel.CRITICAL if strong_compromise_context else RiskLevel.HIGH
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.DESCRIPTIVE,
            finding_type="metadata_only_prompt_injection",
            severity=severity,
            message="Prompt-like control instruction detected in tool metadata description.",
            evidence={
                "description_excerpt": new_metadata.description[:200],
                "strong_compromise_context": strong_compromise_context,
            },
        )
        risk_levels.append(severity)

    resolved_feature_scope = _resolve_feature_scope(
        old_snapshot=old_snapshot,
        request_lineage=request_lineage,
        feature_scope=feature_scope,
    )

    # Protocol-level drift checks are additive and intentionally conservative:
    # only trigger when both old/new protocol semantics are present.
    old_sampling_controls = _extract_sampling_controls(old_snapshot.tool)
    new_sampling_controls = _extract_sampling_controls(new_metadata)
    if old_sampling_controls and new_sampling_controls and _fingerprint(old_sampling_controls) != _fingerprint(new_sampling_controls):
        prompt_like_sampling = _contains_prompt_like_instruction(
            f"{new_sampling_controls.get('prompt_template', '')} {new_sampling_controls.get('system_prompt', '')}"
        )
        severity = RiskLevel.HIGH if (resolved_feature_scope == "sampling" or prompt_like_sampling) else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.BEHAVIORAL,
            finding_type="sampling_control_drift",
            severity=severity,
            message="Sampling-related control metadata drift detected.",
            evidence={
                "feature_scope": resolved_feature_scope,
                "old_sampling_controls_hash": _fingerprint(old_sampling_controls),
                "new_sampling_controls_hash": _fingerprint(new_sampling_controls),
                "prompt_like_sampling_signal": prompt_like_sampling,
            },
        )
        risk_levels.append(severity)

    old_root_scopes = _extract_root_scopes(old_snapshot.tool)
    new_root_scopes = _extract_root_scopes(new_metadata)
    roots_broadening, newly_exposed_roots, roots_wildcard = _detect_scope_broadening(old_root_scopes, new_root_scopes)
    if roots_broadening:
        severity = RiskLevel.HIGH if (resolved_feature_scope == "roots" or roots_wildcard) else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.BEHAVIORAL,
            finding_type="roots_scope_broadening",
            severity=severity,
            message="Roots scope broadening detected in protocol metadata.",
            evidence={
                "feature_scope": resolved_feature_scope,
                "old_root_scopes": old_root_scopes,
                "new_root_scopes": new_root_scopes,
                "newly_exposed_roots": newly_exposed_roots,
                "wildcard_expansion": roots_wildcard,
            },
        )
        risk_levels.append(severity)

    old_resource_scopes = _extract_resource_uri_scopes(old_snapshot.tool)
    new_resource_scopes = _extract_resource_uri_scopes(new_metadata)
    if old_resource_scopes and new_resource_scopes and _fingerprint(old_resource_scopes) != _fingerprint(new_resource_scopes):
        uri_broadening, newly_exposed_uris, uri_wildcard = _detect_scope_broadening(old_resource_scopes, new_resource_scopes)
        severity = RiskLevel.HIGH if (resolved_feature_scope == "resources" and (uri_broadening or uri_wildcard)) else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.ORIGIN,
            finding_type="resource_uri_scope_drift",
            severity=severity,
            message="Resource URI scope drift detected in protocol metadata.",
            evidence={
                "feature_scope": resolved_feature_scope,
                "old_resource_scopes": old_resource_scopes,
                "new_resource_scopes": new_resource_scopes,
                "scope_broadening": uri_broadening,
                "newly_exposed_resource_scopes": newly_exposed_uris,
                "wildcard_expansion": uri_wildcard,
            },
        )
        risk_levels.append(severity)

    old_advertised_capabilities = _extract_capability_advertisement(old_snapshot.tool)
    new_advertised_capabilities = _extract_capability_advertisement(new_metadata)
    if old_advertised_capabilities and new_advertised_capabilities and set(old_advertised_capabilities) != set(new_advertised_capabilities):
        added_advertised = sorted(set(new_advertised_capabilities) - set(old_advertised_capabilities))
        removed_advertised = sorted(set(old_advertised_capabilities) - set(new_advertised_capabilities))
        high_impact_protocol_caps = {"sampling", "roots", "resources", "elicitation"}
        high_impact_expansion = bool(high_impact_protocol_caps.intersection(set(added_advertised)))
        severity = RiskLevel.HIGH if high_impact_expansion else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.BEHAVIORAL,
            finding_type="capability_advertisement_drift",
            severity=severity,
            message="Server capability advertisement drift detected in protocol metadata.",
            evidence={
                "feature_scope": resolved_feature_scope,
                "old_advertised_capabilities": old_advertised_capabilities,
                "new_advertised_capabilities": new_advertised_capabilities,
                "added_advertised_capabilities": added_advertised,
                "removed_advertised_capabilities": removed_advertised,
                "high_impact_expansion": high_impact_expansion,
            },
        )
        risk_levels.append(severity)

    unconsumed_categories = [item.value if hasattr(item, 'value') else str(item) for item in diff.change_categories if (item.value if hasattr(item,'value') else str(item)) not in consumed_change_categories]
    if unconsumed_categories:
        severity = diff.severity if diff.severity in {RiskLevel.HIGH, RiskLevel.CRITICAL} else RiskLevel.MEDIUM
        _append_finding(
            findings=structured_findings,
            drift_domain=_domain_from_change_categories(unconsumed_categories),
            finding_type="registry_detected_drift",
            severity=severity,
            message="Registry reported additional drift categories not covered by direct metadata checks.",
            evidence={
                "change_categories": unconsumed_categories,
                "old_values": diff.old_values,
                "new_values": diff.new_values,
            },
        )
        risk_levels.append(severity)

    risk_level = _max_risk_level(risk_levels)
    recommended_action = _recommended_action_from_risk(risk_level)
    findings = [item.message for item in structured_findings]
    drift_domains = sorted({item.drift_domain for item in structured_findings}, key=lambda item: item.value)
    return MetadataValidationResult(
        passed=recommended_action == DecisionAction.ALLOW,
        findings=findings,
        risk_level=risk_level,
        recommended_action=recommended_action,
        changed_fields=diff.changed_fields,
        change_categories=[item.value if hasattr(item, 'value') else str(item) for item in diff.change_categories],
        drift_domains=drift_domains,
        structured_findings=structured_findings,
    )
