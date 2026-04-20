"""Rule-based capability classification for MCP tool metadata."""

from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import CapabilityType, RiskLevel, ToolMetadata


class CapabilityClassificationResult(BaseModel):
    """Structured output for capability classification."""

    model_config = ConfigDict(extra="forbid")

    detected_capabilities: list[str] = Field(
        default_factory=list,
        description="Detected policy capability classes.",
    )
    risk_level: RiskLevel = Field(..., description="Aggregated risk level.")
    findings: list[str] = Field(
        default_factory=list,
        description="Human-readable rule findings supporting the result.",
    )


def _contains_any(text: str, keywords: set[str]) -> bool:
    """Return True when any keyword is found in normalized text."""
    return any(keyword in text for keyword in keywords)


def classify_capabilities(tool_metadata: ToolMetadata) -> CapabilityClassificationResult:
    """Classify tool capabilities into policy classes using deterministic rules."""
    name = tool_metadata.name.lower()
    description = tool_metadata.description.lower()
    tags_text = " ".join(tool_metadata.tags).lower()
    combined_text = f"{name} {description} {tags_text}"

    schema_like_text = " ".join(
        tag for tag in tool_metadata.tags if tag.lower().startswith(("schema:", "input:", "output:", "param:"))
    ).lower()
    # Also extract quoted field names from schema-like tags for simple structural hints.
    schema_fields = set(re.findall(r'"([a-zA-Z0-9_]+)"', schema_like_text))

    detected: set[str] = set()
    findings: list[str] = []

    read_keywords = {"read", "search", "list", "fetch", "query", "retrieve", "lookup"}
    secret_keywords = {
        "secret",
        "password",
        "token",
        "credential",
        "api key",
        "private key",
        ".env",
        "session cookie",
    }
    write_keywords = {"write", "save", "append", "overwrite", "delete file", "create file", "edit file"}
    network_keywords = {"send", "post", "webhook", "callback", "http request", "upload", "exfiltrate"}
    state_change_keywords = {"create", "update", "delete", "modify", "set", "configure", "revoke", "grant"}
    hidden_keywords = {"hidden", "silent", "silently", "background", "without user confirmation", "auto invoke"}

    if CapabilityType.READ in tool_metadata.capabilities or _contains_any(combined_text, read_keywords):
        detected.add("benign_read")
        findings.append("Detected read/list/query behavior from capability or text patterns.")

    if (
        _contains_any(combined_text, secret_keywords)
        or {"password", "token", "secret", "credential"} & schema_fields
    ):
        detected.add("read_secret")
        findings.append("Detected secret-sensitive access keywords in description/schema hints.")

    if CapabilityType.WRITE in tool_metadata.capabilities or _contains_any(combined_text, write_keywords):
        detected.add("file_write")
        findings.append("Detected file write/modify semantics from capability or text patterns.")

    if CapabilityType.NETWORK in tool_metadata.capabilities or _contains_any(combined_text, network_keywords):
        detected.add("network_send")
        findings.append("Detected outbound network transmission patterns.")

    if (
        CapabilityType.EXECUTE in tool_metadata.capabilities
        or CapabilityType.WRITE in tool_metadata.capabilities
        or _contains_any(combined_text, state_change_keywords)
    ):
        detected.add("state_change")
        findings.append("Detected state-changing behavior (create/update/delete/execute).")

    if (
        CapabilityType.MCP_INVOKE in tool_metadata.capabilities
        or _contains_any(combined_text, hidden_keywords)
    ) and (_contains_any(combined_text, hidden_keywords) or CapabilityType.EXECUTE in tool_metadata.capabilities):
        detected.add("hidden_invocation")
        findings.append("Detected hidden/background invocation risk patterns.")

    # Benign read should not be the only label when stronger read-secret signals exist.
    if "read_secret" in detected and "benign_read" in detected:
        findings.append("Read capability includes secret-oriented signals; treat as sensitive read path.")

    if "hidden_invocation" in detected:
        risk_level = RiskLevel.CRITICAL
    elif "read_secret" in detected and "network_send" in detected:
        risk_level = RiskLevel.CRITICAL
    elif {"read_secret", "file_write", "network_send"} & detected:
        risk_level = RiskLevel.HIGH
    elif "state_change" in detected:
        risk_level = RiskLevel.MEDIUM
    else:
        risk_level = RiskLevel.LOW

    return CapabilityClassificationResult(
        detected_capabilities=sorted(detected),
        risk_level=risk_level,
        findings=findings or ["No high-risk capability signal detected by current rules."],
    )
