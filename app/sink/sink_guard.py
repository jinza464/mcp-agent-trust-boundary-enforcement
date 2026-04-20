"""Rule-based sink guard for last-mile execution control."""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel


class SinkInspectionResult(BaseModel):
    """Structured sink inspection output for enforcement."""

    model_config = ConfigDict(extra="forbid")

    action: DecisionAction = Field(..., description="Final sink control action.")
    risk_level: RiskLevel = Field(..., description="Sink risk level.")
    findings: list[str] = Field(default_factory=list, description="Human-readable sink findings.")
    blocked_reasons: list[str] = Field(
        default_factory=list,
        description="Reasons that block direct execution without guard intervention.",
    )
    requires_user_confirmation: bool = Field(
        default=False,
        description="Whether explicit user confirmation is required.",
    )


def _normalize_planned_action(planned_action: DecisionAction | str) -> str:
    if isinstance(planned_action, DecisionAction):
        return planned_action.value.lower()
    return str(planned_action).strip().lower()


def _flatten_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.lower()
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()
    except (TypeError, ValueError):
        return str(payload).lower()


def _contains_sensitive_content(text: str) -> bool:
    keyword_hits = [
        "token",
        "password",
        "api key",
        "apikey",
        "secret",
        "credential",
        "private_key",
        "bearer ",
    ]
    if any(token in text for token in keyword_hits):
        return True

    regexes = [
        r"api[_-]?key\s*[:=]\s*[^\s,;]+",
        r"password\s*[:=]\s*[^\s,;]+",
        r"token\s*[:=]\s*[^\s,;]+",
        r"bearer\s+[a-z0-9\-\._~\+\/]+=*",
    ]
    return any(re.search(pattern, text) for pattern in regexes)


def _extract_endpoint(metadata: dict[str, Any], payload_text: str) -> str | None:
    endpoint = metadata.get("endpoint") or metadata.get("url") or metadata.get("destination")
    if isinstance(endpoint, str) and endpoint.strip():
        return endpoint.strip().lower()
    match = re.search(r"https?://[^\s\"'>]+", payload_text)
    return match.group(0).lower() if match else None


def _is_external_endpoint(endpoint: str | None) -> bool:
    if not endpoint:
        return False
    high_risk_markers = ["webhook", "callback", "external", "http://", "https://"]
    return any(marker in endpoint for marker in high_risk_markers)


def _is_sensitive_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.lower()
    markers = ["credential", "config", "system", ".env", "token", "secret", "passwd"]
    return any(marker in normalized for marker in markers)


def inspect_sink(
    planned_action: DecisionAction | str,
    payload: Any,
    metadata: dict[str, Any] | None = None,
) -> SinkInspectionResult:
    """Inspect sink execution and return a structured enforcement decision."""
    meta = metadata or {}
    action_name = _normalize_planned_action(planned_action)
    payload_text = _flatten_payload(payload)
    sink_type = str(meta.get("sink_type", action_name)).lower()

    findings: list[str] = []
    blocked_reasons: list[str] = []
    action = DecisionAction.ALLOW
    risk_level = RiskLevel.LOW

    is_network_sink = sink_type in {"network_send", "network", "send", "post"}
    is_file_write_sink = sink_type in {"file_write", "write_file", "write"}
    is_secret_read_sink = sink_type in {"secret_read", "read_secret"}
    is_credential_sink = sink_type in {"credential_access", "credential_read"}
    is_state_change_sink = sink_type in {"state_change", "modify_state", "state_changing_action"}

    has_sensitive_content = _contains_sensitive_content(payload_text)
    endpoint = _extract_endpoint(meta, payload_text)
    external_endpoint = _is_external_endpoint(endpoint)

    if is_network_sink:
        findings.append("Detected network send sink.")
        if has_sensitive_content:
            action = DecisionAction.DENY
            risk_level = RiskLevel.CRITICAL
            blocked_reasons.append("Sensitive secret/token/password content detected in outbound payload.")
        elif external_endpoint:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH
            blocked_reasons.append("Outbound traffic to webhook/external endpoint requires confirmation.")

    if is_file_write_sink:
        findings.append("Detected file write sink.")
        target_path = str(meta.get("path") or meta.get("file_path") or meta.get("target_path") or "")
        if _is_sensitive_path(target_path):
            if action != DecisionAction.DENY:
                action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level
            blocked_reasons.append("Write target is a sensitive path (credential/config/system/.env/token).")

    if is_secret_read_sink:
        findings.append("Detected secret read sink.")
        if action == DecisionAction.ALLOW:
            risk_level = RiskLevel.LOW

    if is_credential_sink:
        findings.append("Detected credential access sink.")
        if action != DecisionAction.DENY:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level
            blocked_reasons.append("Credential access requires explicit user confirmation.")

    if is_state_change_sink:
        findings.append("Detected state-changing sink.")
        if action == DecisionAction.ALLOW:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.MEDIUM
            blocked_reasons.append("State-changing operation requires explicit user confirmation.")

    requires_user_confirmation = action == DecisionAction.REQUIRE_CONFIRMATION
    if not findings:
        findings.append("No high-risk sink signal detected.")

    return SinkInspectionResult(
        action=action,
        risk_level=risk_level,
        findings=findings,
        blocked_reasons=blocked_reasons,
        requires_user_confirmation=requires_user_confirmation,
    )
