"""Rule-based metadata validation for MCP tool evolution risk detection."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, ToolMetadata, ToolSnapshot
from app.policy.capability_policy import classify_capabilities
from app.registry.tool_registry import ToolRegistry


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
    ]
    return any(pattern in text for pattern in patterns)


def _origin_of_snapshot(snapshot: ToolSnapshot) -> str:
    return str(snapshot.runtime_context.get("server_origin", snapshot.tool.source_uri or "unknown"))


def _risk_capabilities(capability_labels: list[str]) -> set[str]:
    return {label for label in capability_labels if label in {"read_secret", "file_write", "network_send", "hidden_invocation"}}


def validate_metadata(old_snapshot: ToolSnapshot, new_metadata: ToolMetadata) -> MetadataValidationResult:
    """Validate metadata changes using explicit, explainable rules."""
    findings: list[str] = []
    risk_levels: list[RiskLevel] = []

    registry = ToolRegistry()
    diff = registry.detect_changes(old_snapshot, new_metadata)

    old_origin = _origin_of_snapshot(old_snapshot)
    new_origin = new_metadata.source_uri or "unknown"
    if old_snapshot.tool.name == new_metadata.name and old_origin != new_origin:
        findings.append("Shadowing risk: same tool name appears from a different server origin.")
        risk_levels.append(RiskLevel.HIGH)

    if "description_hash" in diff.changed_fields:
        findings.append("Description hash changed from previous snapshot.")
        risk_levels.append(RiskLevel.MEDIUM)

    if "schema_hash" in diff.changed_fields:
        findings.append("Schema hash changed from previous snapshot.")
        risk_levels.append(RiskLevel.HIGH)

    if _contains_prompt_like_instruction(new_metadata.description):
        findings.append("Prompt-like instruction detected in tool description.")
        risk_levels.append(RiskLevel.HIGH)

    old_capabilities = classify_capabilities(old_snapshot.tool).detected_capabilities
    new_capabilities = classify_capabilities(new_metadata).detected_capabilities
    newly_added_high_risk = _risk_capabilities(new_capabilities) - _risk_capabilities(old_capabilities)
    if newly_added_high_risk:
        findings.append(
            f"New high-risk capabilities introduced: {', '.join(sorted(newly_added_high_risk))}."
        )
        if "hidden_invocation" in newly_added_high_risk:
            risk_levels.append(RiskLevel.CRITICAL)
        else:
            risk_levels.append(RiskLevel.HIGH)

    old_version = old_snapshot.tool.version
    new_version = new_metadata.version
    old_semver = _parse_semver(old_version)
    new_semver = _parse_semver(new_version)
    if old_semver and new_semver:
        if new_semver < old_semver:
            findings.append(f"Version rollback detected: {old_version} -> {new_version}.")
            risk_levels.append(RiskLevel.HIGH)
        elif new_semver[0] - old_semver[0] > 1:
            findings.append(f"Version anomaly detected: major jump {old_version} -> {new_version}.")
            risk_levels.append(RiskLevel.MEDIUM)
    elif old_version != new_version and (old_semver is None or new_semver is None):
        findings.append(f"Version format anomaly detected: {old_version} -> {new_version}.")
        risk_levels.append(RiskLevel.MEDIUM)

    risk_level = _max_risk_level(risk_levels)
    recommended_action = _recommended_action_from_risk(risk_level)

    return MetadataValidationResult(
        passed=recommended_action == DecisionAction.ALLOW,
        findings=findings,
        risk_level=risk_level,
        recommended_action=recommended_action,
        changed_fields=diff.changed_fields,
    )
