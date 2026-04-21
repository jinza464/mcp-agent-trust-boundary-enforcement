"""Metadata-first validation for MCP tool evolution risk detection.

This module is intentionally metadata-centric:
- It evaluates identity/interface/origin/behavioral drift directly from metadata.
- It avoids coupling to capability policy as a primary signal.
"""

from __future__ import annotations

import json
import re
from enum import Enum
import hashlib
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, ToolMetadata, ToolSnapshot
from app.registry.tool_registry import ToolRegistry


class DriftDomain(str, Enum):
    """High-level metadata drift domains used for explainable classification."""

    DESCRIPTIVE = "descriptive_drift"
    INTERFACE = "interface_drift"
    ORIGIN = "origin_drift"
    BEHAVIORAL = "behavioral_drift"


class MetadataValidationFinding(BaseModel):
    """Structured metadata validation finding."""

    model_config = ConfigDict(extra="forbid")

    drift_domain: DriftDomain = Field(..., description="Top-level drift domain.")
    finding_type: str = Field(..., description="Concrete finding type.")
    severity: RiskLevel = Field(..., description="Finding-local severity.")
    message: str = Field(..., description="Human-readable explainable finding.")
    evidence: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured supporting evidence for this finding.",
    )


class MetadataValidationResult(BaseModel):
    """Structured result for metadata validation."""

    model_config = ConfigDict(extra="forbid")

    passed: bool = Field(..., description="Whether validation passed without risky findings.")
    findings: list[str] = Field(default_factory=list, description="Human-readable findings.")
    risk_level: RiskLevel = Field(..., description="Aggregated validation risk level.")
    recommended_action: DecisionAction = Field(..., description="Suggested policy action.")
    changed_fields: list[str] = Field(
        default_factory=list,
        description="Changed identity fields detected by the registry comparator.",
    )
    change_categories: list[str] = Field(
        default_factory=list,
        description="Typed change categories propagated from ToolRegistry.",
    )
    drift_domains: list[DriftDomain] = Field(
        default_factory=list,
        description="Observed top-level drift domains.",
    )
    structured_findings: list[MetadataValidationFinding] = Field(
        default_factory=list,
        description="Structured metadata-sensitive findings.",
    )


def _risk_rank(level: RiskLevel) -> int:
    return {
        RiskLevel.LOW: 1,
        RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3,
        RiskLevel.CRITICAL: 4,
    }[level]


def _max_risk_level(levels: list[RiskLevel]) -> RiskLevel:
    if not levels:
        return RiskLevel.LOW
    return max(levels, key=_risk_rank)


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
    if value is None:
        return "none"
    return _stable_hash(value)


def _parse_semver_any(version: str) -> tuple[int, int, int] | None:
    return _parse_semver(version)


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


def _domain_from_change_categories(categories: list[str]) -> DriftDomain:
    category_set = set(categories)
    if {"server_relocation", "namespace_conflict"}.intersection(category_set):
        return DriftDomain.ORIGIN
    if {"schema_change"}.intersection(category_set):
        return DriftDomain.INTERFACE
    if {"descriptive_change"}.intersection(category_set):
        return DriftDomain.DESCRIPTIVE
    return DriftDomain.BEHAVIORAL


def validate_metadata(old_snapshot: ToolSnapshot, new_metadata: ToolMetadata) -> MetadataValidationResult:
    """Validate metadata evolution with metadata-only and explainable risk rules."""
    structured_findings: list[MetadataValidationFinding] = []
    risk_levels: list[RiskLevel] = []

    registry = ToolRegistry()
    diff = registry.detect_changes(old_snapshot, new_metadata)

    old_origin = old_snapshot.server_origin or old_snapshot.tool.server_origin or old_snapshot.tool.source_uri or "unknown"
    new_origin = new_metadata.server_origin or new_metadata.source_uri or "unknown"

    old_namespace = old_snapshot.tool.namespace or old_snapshot.tool.provider_identity or old_snapshot.tool.provider
    new_namespace = new_metadata.namespace or new_metadata.provider_identity or new_metadata.provider

    old_provider = old_snapshot.tool.provider_identity or old_snapshot.tool.provider
    new_provider = new_metadata.provider_identity or new_metadata.provider

    if "description_hash" in diff.changed_fields:
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

    # Formal schema drift and contract-level drift.
    old_input_hash = old_snapshot.input_schema_hash or _fingerprint(old_snapshot.tool.input_schema)
    new_input_hash = _fingerprint(new_metadata.input_schema)
    old_output_hash = old_snapshot.output_schema_hash or _fingerprint(old_snapshot.tool.output_schema)
    new_output_hash = _fingerprint(new_metadata.output_schema)
    if old_input_hash != new_input_hash or old_output_hash != new_output_hash or "schema_hash" in diff.changed_fields:
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
    changed_params = sorted(
        key for key in common_params if _fingerprint(old_props.get(key)) != _fingerprint(new_props.get(key))
    )
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
    if (
        old_out_required != new_out_required
        or set(out_props_old.keys()) != set(out_props_new.keys())
    ):
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
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.ORIGIN,
            finding_type="namespace_confusion",
            severity=RiskLevel.CRITICAL,
            message="Namespace/provider identity changed and may indicate confusion risk.",
            evidence={
                "old_namespace": old_namespace,
                "new_namespace": new_namespace,
                "old_provider_identity": old_provider,
                "new_provider_identity": new_provider,
            },
        )
        risk_levels.append(RiskLevel.CRITICAL)

    old_version = old_snapshot.tool.version
    new_version = new_metadata.version
    old_semver = _parse_semver_any(old_version)
    new_semver = _parse_semver_any(new_version)
    capability_changed = set(old_snapshot.tool.capabilities) != set(new_metadata.capabilities)
    if old_semver and new_semver:
        if new_semver < old_semver:
            severity = RiskLevel.CRITICAL if not capability_changed else RiskLevel.HIGH
            message = (
                f"Version rollback detected without explicit capability change: {old_version} -> {new_version}."
                if not capability_changed
                else f"Version rollback detected: {old_version} -> {new_version}."
            )
            _append_finding(
                findings=structured_findings,
                drift_domain=DriftDomain.BEHAVIORAL,
                finding_type="rollback_without_explicit_capability_change"
                if not capability_changed
                else "version_rollback",
                severity=severity,
                message=message,
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
    elif old_version != new_version and (old_semver is None or new_semver is None):
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
        _append_finding(
            findings=structured_findings,
            drift_domain=DriftDomain.DESCRIPTIVE,
            finding_type="metadata_only_prompt_injection",
            severity=RiskLevel.CRITICAL,
            message="Prompt-like control instruction detected in tool metadata description.",
            evidence={"description_excerpt": new_metadata.description[:200]},
        )
        risk_levels.append(RiskLevel.CRITICAL)

    if diff.change_categories:
        severity = diff.severity
        _append_finding(
            findings=structured_findings,
            drift_domain=_domain_from_change_categories(diff.change_categories),
            finding_type="registry_detected_drift",
            severity=severity,
            message=diff.drift_summary,
            evidence={
                "change_categories": diff.change_categories,
                "old_values": diff.old_values,
                "new_values": diff.new_values,
            },
        )
        risk_levels.append(severity)

    risk_level = _max_risk_level(risk_levels)
    recommended_action = _recommended_action_from_risk(risk_level)
    findings = [finding.message for finding in structured_findings]
    drift_domains = sorted({finding.drift_domain for finding in structured_findings}, key=lambda item: item.value)

    return MetadataValidationResult(
        passed=recommended_action == DecisionAction.ALLOW,
        findings=findings,
        risk_level=risk_level,
        recommended_action=recommended_action,
        changed_fields=diff.changed_fields,
        change_categories=diff.change_categories,
        drift_domains=drift_domains,
        structured_findings=structured_findings,
    )
