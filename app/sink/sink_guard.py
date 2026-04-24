"""Rule-based sink guard for last-mile execution control."""

from __future__ import annotations

import json
import re
from urllib.parse import urlparse
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction, RiskLevel, TrustLabel


class SinkInspectionResult(BaseModel):
    """Structured sink inspection output for enforcement."""

    model_config = ConfigDict(extra="forbid")

    action: DecisionAction = Field(..., description="Final sink control action.")
    risk_level: RiskLevel = Field(..., description="Sink risk level.")
    findings: list[str] = Field(default_factory=list, description="Human-readable sink findings.")
    blocked_reasons: list[str] = Field(default_factory=list, description="Reasons that block direct execution.")
    requires_user_confirmation: bool = Field(default=False)
    endpoint_class: str = Field(default="unknown", description="internal / allowlisted / external / unknown.")
    sensitive_payload_signals: list[str] = Field(default_factory=list)
    sink_risk_factors: list[str] = Field(default_factory=list)
    fragment_suspicion: bool = Field(default=False)
    staged_exfil_signals: list[str] = Field(default_factory=list)
    payload_sensitivity_class: str = Field(default="low", description="low / suspicious / sensitive.")


class SinkDecisionContext(BaseModel):
    """Lineage-aware sink decision context used by inspect_sink_with_context()."""

    model_config = ConfigDict(extra="forbid")

    request_lineage: dict[str, Any] | BaseModel | None = Field(default=None)
    upstream_trust_label: TrustLabel | str | None = Field(default=None)
    decision_action: DecisionAction | str = Field(...)
    capability_result: Any | None = Field(default=None)
    payload: Any = Field(default=None)
    sink_metadata: dict[str, Any] = Field(default_factory=dict)


def _normalize_planned_action(planned_action: DecisionAction | str) -> str:
    if isinstance(planned_action, DecisionAction):
        return planned_action.value.lower()
    return str(planned_action).strip().lower()


def _risk_rank(level: RiskLevel) -> int:
    return {RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}[level]


def _escalate_to_confirmation(action: DecisionAction, risk_level: RiskLevel, minimum_risk: RiskLevel) -> tuple[DecisionAction, RiskLevel]:
    if action == DecisionAction.DENY:
        return action, risk_level
    next_action = DecisionAction.REQUIRE_CONFIRMATION
    next_risk = minimum_risk if _risk_rank(risk_level) < _risk_rank(minimum_risk) else risk_level
    return next_action, next_risk


def _normalize_trust_label(value: TrustLabel | str | None) -> TrustLabel | None:
    if isinstance(value, TrustLabel):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        for item in TrustLabel:
            if normalized == item.value:
                return item
    return None


def _context_field(obj: dict[str, Any] | BaseModel | None, key: str) -> Any:
    if obj is None:
        return None
    if isinstance(obj, dict):
        return obj.get(key)
    return getattr(obj, key, None)


def _lineage_trust_label(request_lineage: dict[str, Any] | BaseModel | None) -> TrustLabel | None:
    return _normalize_trust_label(_context_field(request_lineage, "trust_label"))


def _lineage_feature_scope(request_lineage: dict[str, Any] | BaseModel | None) -> str | None:
    value = _context_field(request_lineage, "feature")
    if isinstance(value, str):
        normalized = value.strip().lower()
        return normalized or None
    return None


def _capability_tokens(capability_result: Any) -> set[str]:
    if capability_result is None:
        return set()

    detected = None
    if isinstance(capability_result, dict):
        detected = capability_result.get("detected_capabilities")
    else:
        detected = getattr(capability_result, "detected_capabilities", None)

    tokens: set[str] = set()
    if isinstance(detected, (list, tuple, set)):
        for item in detected:
            if isinstance(item, str):
                tokens.add(item.strip().lower())
            else:
                value = getattr(item, "value", None)
                if isinstance(value, str):
                    tokens.add(value.strip().lower())
                else:
                    tokens.add(str(item).strip().lower())
    return tokens


def _flatten_payload(payload: Any) -> str:
    if isinstance(payload, str):
        return payload.lower()
    try:
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).lower()
    except (TypeError, ValueError):
        return str(payload).lower()


def _contains_sensitive_content(text: str) -> bool:
    normalized = text
    for marker in (
        "no secrets",
        "no secret",
        "without secrets",
        "without secret",
        "no token",
        "without token",
        "no password",
        "without password",
    ):
        normalized = normalized.replace(marker, "")

    keyword_hits = ["token", "password", "api key", "apikey", "secret", "credential", "private_key", "bearer "]
    if any(token in normalized for token in keyword_hits):
        return True

    regexes = [
        r"api[_-]?key\s*[:=]\s*[^\s,;]+",
        r"password\s*[:=]\s*[^\s,;]+",
        r"token\s*[:=]\s*[^\s,;]+",
        r"bearer\s+[a-z0-9\-\._~\+\/]+=*",
    ]
    return any(re.search(pattern, normalized) for pattern in regexes)


def _extract_endpoint(metadata: dict[str, Any], payload_text: str) -> str | None:
    endpoint = metadata.get("endpoint") or metadata.get("url") or metadata.get("destination")
    if isinstance(endpoint, str) and endpoint.strip():
        return endpoint.strip().lower()
    match = re.search(r"https?://[^\s\"'>]+", payload_text)
    return match.group(0).lower() if match else None


def _extract_domain(endpoint: str) -> str:
    normalized = endpoint if "://" in endpoint else f"https://{endpoint}"
    parsed = urlparse(normalized)
    host = parsed.netloc or parsed.path
    if "/" in host:
        host = host.split("/", 1)[0]
    if ":" in host:
        host = host.split(":", 1)[0]
    return host.lower()


def _is_private_ipv4(host: str) -> bool:
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        return False
    octets = [int(item) for item in host.split(".")]
    if any(item > 255 for item in octets):
        return False
    return (
        octets[0] == 10
        or (octets[0] == 172 and 16 <= octets[1] <= 31)
        or (octets[0] == 192 and octets[1] == 168)
        or host.startswith("127.")
    )


def _classify_endpoint(endpoint: str | None, metadata: dict[str, Any]) -> str:
    if not endpoint:
        return "unknown"
    host = _extract_domain(endpoint)
    if not host:
        return "unknown"

    parsed = urlparse(endpoint if "://" in endpoint else f"https://{endpoint}")
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return "unknown"

    allowlisted = {_extract_domain(str(item).lower()) for item in metadata.get("allowlisted_domains", []) if isinstance(item, str)}
    allowlisted_endpoints = {str(item).lower() for item in metadata.get("allowlisted_endpoints", []) if isinstance(item, str)}
    internal_domains = {_extract_domain(str(item).lower()) for item in metadata.get("internal_domains", []) if isinstance(item, str)}
    internal_markers = [".internal", ".intra", ".corp", ".local", "localhost"]

    if endpoint.lower() in allowlisted_endpoints or host in allowlisted or any(host.endswith(f".{d}") for d in allowlisted if d):
        return "allowlisted"
    if host in internal_domains or any(host.endswith(f".{d}") for d in internal_domains if d) or _is_private_ipv4(host) or any(marker in host for marker in internal_markers):
        return "internal"
    return "external"


def _is_sensitive_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.lower()
    return any(marker in normalized for marker in ["credential", "config", "system", ".env", "token", "secret", "passwd"])


def _find_base64_like_tokens(text: str) -> list[str]:
    pattern = r"\b[A-Za-z0-9+/=_-]{24,}\b"
    tokens: list[str] = []
    for token in re.findall(pattern, text):
        if len(set(token)) < 6:
            continue
        if re.fullmatch(r"[0-9a-f-]{24,}", token):
            continue
        if not (re.search(r"[A-Za-z]", token) and re.search(r"\d", token)):
            continue
        tokens.append(token)
    return tokens


def _sensitivity_signals(payload: Any, payload_text: str) -> list[str]:
    signals: list[str] = []
    if _contains_sensitive_content(payload_text):
        signals.append("explicit_secret_marker")

    lower = payload_text.lower()
    if any(key in lower for key in ["session", "cookie", "auth", "bearer", "credential"]):
        signals.append("auth_material_marker")
    if any(key in lower for key in ["ssn", "bank", "private", "personal_data", "pii"]):
        signals.append("pii_marker")

    if _find_base64_like_tokens(payload_text):
        signals.append("obfuscated_payload_pattern")

    if isinstance(payload, dict):
        keys = {str(k).lower() for k in payload.keys()}
        if {"chunk", "part", "fragment", "segment"}.intersection(keys):
            signals.append("fragmented_payload_marker")
        if {"chunks", "parts", "fragments", "segments"}.intersection(keys):
            for list_key in ("chunks", "parts", "fragments", "segments"):
                value = payload.get(list_key)
                if isinstance(value, list) and len(value) >= 2:
                    signals.append("fragmented_payload_marker")
                    break
        if {"chunk_index", "total_chunks", "transfer_id", "batch_id"}.intersection(keys):
            signals.append("staged_transfer_marker")
        if any(re.match(r"^(stage|step|part|chunk|segment)[_\-]?\d+$", key) for key in keys):
            signals.append("staged_transfer_marker")
        if {"callback_id", "sequence_id", "retry_id", "handoff_id", "cursor", "next_cursor"}.intersection(keys):
            signals.append("staged_transfer_marker")
        if {"current_stage", "next_stage", "stage_total", "stage_index"}.intersection(keys):
            signals.append("staged_transfer_marker")
        chunk_value = payload.get("chunk") or payload.get("part") or payload.get("fragment")
        if isinstance(chunk_value, str) and len(chunk_value) >= 16 and re.match(r"^[A-Za-z0-9+/=_-]+$", chunk_value):
            signals.append("fragment_chunk_high_entropy")

    return sorted(set(signals))


def _payload_sensitivity_class(signals: list[str]) -> str:
    signal_set = set(signals)
    if {"explicit_secret_marker", "auth_material_marker", "pii_marker"}.intersection(signal_set):
        return "sensitive"
    if {"fragmented_payload_marker", "fragment_chunk_high_entropy", "staged_transfer_marker", "obfuscated_payload_pattern"}.intersection(signal_set):
        return "suspicious"
    return "low"


def _staged_exfil_signals(*, endpoint_class: str, endpoint: str | None, signals: list[str]) -> list[str]:
    output: list[str] = []
    for marker in ("fragmented_payload_marker", "fragment_chunk_high_entropy", "staged_transfer_marker", "obfuscated_payload_pattern"):
        if marker in signals:
            output.append(marker)
    if "staged_transfer_marker" in signals and "explicit_secret_marker" not in signals:
        output.append("low_obviousness_payload")
    if endpoint_class == "external":
        output.append("external_endpoint")
        if endpoint and ("callback" in endpoint or "webhook" in endpoint):
            output.append("external_callback_channel")
    elif endpoint_class == "allowlisted":
        output.append("allowlisted_endpoint")
    elif endpoint_class == "internal":
        output.append("internal_endpoint")
    else:
        output.append("unknown_endpoint")
    return list(dict.fromkeys(output))


def _is_trusted_internal_sync(
    *,
    endpoint_class: str,
    metadata: dict[str, Any],
    payload_text: str,
    payload_sensitivity_class: str,
    staged_marker: bool,
    fragment_suspicion: bool,
    obfuscated_marker: bool,
) -> bool:
    if endpoint_class != "internal":
        return False
    if payload_sensitivity_class == "sensitive":
        return False
    if obfuscated_marker:
        return False
    trust_hints = bool(metadata.get("integrity_verified")) or bool(metadata.get("signature_valid")) or bool(metadata.get("is_local")) or bool(metadata.get("trusted_internal"))
    telemetry_like = any(marker in payload_text for marker in ["sync", "heartbeat", "metrics", "uptime", "status", "health"])
    if staged_marker or fragment_suspicion:
        return trust_hints and telemetry_like
    return trust_hints or telemetry_like


def _is_benign_report_path(path: str) -> bool:
    normalized = path.lower()
    return any(marker in normalized for marker in ["report", "summary", "output", "results", "logs"]) and not _is_sensitive_path(path)


def inspect_sink(
    planned_action: DecisionAction | str,
    payload: Any,
    metadata: dict[str, Any] | None = None,
) -> SinkInspectionResult:
    """Backward-compatible sink inspection entrypoint."""
    return inspect_sink_with_context(
        SinkDecisionContext(
            decision_action=planned_action,
            payload=payload,
            sink_metadata=metadata or {},
        )
    )


def inspect_sink_with_context(context: SinkDecisionContext | dict[str, Any]) -> SinkInspectionResult:
    """Inspect sink execution with optional lineage-aware runtime context."""
    ctx = context if isinstance(context, SinkDecisionContext) else SinkDecisionContext.model_validate(context)
    meta = ctx.sink_metadata or {}
    payload = ctx.payload
    action_name = _normalize_planned_action(ctx.decision_action)
    payload_text = _flatten_payload(payload)
    sink_type = str(meta.get("sink_type", action_name)).lower()

    findings: list[str] = []
    blocked_reasons: list[str] = []
    sink_risk_factors: list[str] = []

    action = DecisionAction.ALLOW
    risk_level = RiskLevel.LOW

    is_network_sink = sink_type in {"network_send", "network", "send", "post"}
    is_file_write_sink = sink_type in {"file_write", "write_file", "write"}
    is_secret_read_sink = sink_type in {"secret_read", "read_secret"}
    is_credential_sink = sink_type in {"credential_access", "credential_read"}
    is_state_change_sink = sink_type in {"state_change", "modify_state", "state_changing_action"}

    endpoint = _extract_endpoint(meta, payload_text)
    endpoint_class = _classify_endpoint(endpoint, meta)
    sensitive_signals = _sensitivity_signals(payload, payload_text)
    has_any_sensitivity_signal = bool(sensitive_signals)
    staged_marker = "staged_transfer_marker" in sensitive_signals
    fragmented_marker = any(item in sensitive_signals for item in {"fragmented_payload_marker", "fragment_chunk_high_entropy"})
    obfuscated_marker = "obfuscated_payload_pattern" in sensitive_signals
    fragment_suspicion = fragmented_marker or (obfuscated_marker and staged_marker)
    payload_sensitivity_class = _payload_sensitivity_class(sensitive_signals)
    staged_signals = _staged_exfil_signals(endpoint_class=endpoint_class, endpoint=endpoint, signals=sensitive_signals)
    trusted_internal_sync = _is_trusted_internal_sync(
        endpoint_class=endpoint_class,
        metadata=meta,
        payload_text=payload_text,
        payload_sensitivity_class=payload_sensitivity_class,
        staged_marker=staged_marker,
        fragment_suspicion=fragment_suspicion,
        obfuscated_marker=obfuscated_marker,
    )

    lineage_trust_label = _lineage_trust_label(ctx.request_lineage)
    upstream_trust_label = _normalize_trust_label(ctx.upstream_trust_label)
    lineage_feature = _lineage_feature_scope(ctx.request_lineage)
    capability_tokens = _capability_tokens(ctx.capability_result)
    payload_dict = payload if isinstance(payload, dict) else {}
    explicit_untrusted_derivation = (
        bool(meta.get("derived_from_untrusted_content"))
        or bool(payload_dict.get("derived_from_untrusted_content"))
    )
    derived_from_untrusted_upstream = (
        explicit_untrusted_derivation
        or upstream_trust_label == TrustLabel.UNTRUSTED
        or lineage_trust_label == TrustLabel.UNTRUSTED
    )

    delegated_or_hidden_context = bool(
        {"toolchain_delegation", "hidden_invocation", "mcp_invoke", "delegate", "orchestration"}.intersection(capability_tokens)
        or bool(meta.get("delegated_invocation"))
        or bool(meta.get("hidden_invocation"))
    )
    external_resource_context = bool(
        {"network_send", "network_egress"}.intersection(capability_tokens)
        or bool(meta.get("external_resource"))
        or endpoint_class == "external"
    )

    if is_network_sink:
        findings.append("Detected network send sink.")
        findings.append(f"Endpoint classified as {endpoint_class}.")
        if "explicit_secret_marker" in sensitive_signals:
            action = DecisionAction.DENY
            risk_level = RiskLevel.CRITICAL
            blocked_reasons.append("Sensitive secret/token/password content detected in outbound payload.")
            sink_risk_factors.append("hard_deny_explicit_secret_egress")
        elif endpoint_class == "external" and (fragment_suspicion or obfuscated_marker or staged_marker):
            action = DecisionAction.DENY
            risk_level = RiskLevel.CRITICAL
            blocked_reasons.append("Potential fragmented/obfuscated/staged exfiltration to external endpoint.")
            sink_risk_factors.append("external_advanced_exfil_pattern")
        elif endpoint_class == "external" and has_any_sensitivity_signal:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH
            blocked_reasons.append("Sensitive telemetry/content headed to external endpoint.")
            sink_risk_factors.append("external_sensitive_telemetry")
        elif endpoint_class == "external":
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH
            blocked_reasons.append("Outbound traffic to external endpoint requires confirmation.")
            sink_risk_factors.append("external_callback_telemetry")
        elif endpoint_class == "unknown":
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH if payload_sensitivity_class in {"suspicious", "sensitive"} else RiskLevel.MEDIUM
            blocked_reasons.append("Outbound traffic with unknown endpoint requires explicit confirmation.")
            sink_risk_factors.append("unknown_endpoint_egress")
        elif endpoint_class in {"internal", "allowlisted"}:
            if payload_sensitivity_class == "sensitive":
                action = DecisionAction.REQUIRE_CONFIRMATION
                risk_level = RiskLevel.HIGH
                blocked_reasons.append("Sensitive payload to non-external endpoint requires confirmation.")
                sink_risk_factors.append("non_external_sensitive_payload")
            elif endpoint_class == "allowlisted" and (fragment_suspicion or staged_marker or obfuscated_marker):
                action = DecisionAction.REQUIRE_CONFIRMATION
                risk_level = RiskLevel.MEDIUM
                blocked_reasons.append("Staged/fragmented callback pattern on allowlisted endpoint requires confirmation.")
                sink_risk_factors.append("allowlisted_staged_outbound_signal")
            elif endpoint_class == "internal" and (fragment_suspicion or staged_marker or obfuscated_marker) and not trusted_internal_sync:
                action = DecisionAction.REQUIRE_CONFIRMATION
                risk_level = RiskLevel.MEDIUM
                blocked_reasons.append("Suspicious staged/fragmented outbound pattern on internal endpoint.")
                sink_risk_factors.append("internal_staged_outbound_signal")
            elif endpoint_class == "internal" and trusted_internal_sync:
                findings.append("Trusted internal sync context detected.")

    if is_file_write_sink:
        findings.append("Detected file write sink.")
        target_path = str(meta.get("path") or meta.get("file_path") or meta.get("target_path") or "")
        if _is_sensitive_path(target_path):
            action = DecisionAction.REQUIRE_CONFIRMATION if action != DecisionAction.DENY else action
            risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level
            blocked_reasons.append("Write target is a sensitive path (credential/config/system/.env/token).")
            sink_risk_factors.append("sensitive_config_path_write")
        elif target_path and _is_benign_report_path(target_path):
            findings.append("Write target looks like benign report/output path.")
        elif target_path and any(seg in target_path.lower() for seg in {"tmp", "temp", "cache"}):
            findings.append("Write target is temporary/local workspace path.")

    if is_secret_read_sink:
        findings.append("Detected secret read sink.")
        if action == DecisionAction.ALLOW:
            risk_level = RiskLevel.LOW

    if is_credential_sink:
        findings.append("Detected credential access sink.")
        operation = str(meta.get("operation", "")).lower()
        if operation in {"list_aliases", "health_check", "status"} and action == DecisionAction.ALLOW:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.MEDIUM
            blocked_reasons.append("Credential system metadata access requires confirmation.")
            sink_risk_factors.append("credential_metadata_access")
        elif action != DecisionAction.DENY:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level
            blocked_reasons.append("Credential access requires explicit user confirmation.")
            sink_risk_factors.append("credential_access_sensitive")

    if is_state_change_sink:
        findings.append("Detected state-changing sink.")
        operation = str(meta.get("operation") or payload_text).lower()
        user_authorized = bool(meta.get("user_authorized", False))
        destructive = any(item in operation for item in {"delete", "revoke", "disable", "drop"})
        if destructive and not user_authorized and action != DecisionAction.DENY:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.HIGH if risk_level != RiskLevel.CRITICAL else risk_level
            blocked_reasons.append("Destructive state-changing operation requires explicit user confirmation.")
            sink_risk_factors.append("destructive_state_change")
        elif action == DecisionAction.ALLOW and not user_authorized:
            action = DecisionAction.REQUIRE_CONFIRMATION
            risk_level = RiskLevel.MEDIUM
            blocked_reasons.append("State-changing operation requires explicit user confirmation.")
            sink_risk_factors.append("state_change_requires_confirmation")

    # Lineage-aware additive controls (do not replace existing sink heuristics).
    if derived_from_untrusted_upstream:
        findings.append("Lineage context indicates payload derived from untrusted upstream content.")
        sink_risk_factors.append("lineage_untrusted_upstream_payload")
        if is_network_sink and action != DecisionAction.DENY:
            target_risk = RiskLevel.HIGH if endpoint_class in {"external", "unknown"} else RiskLevel.MEDIUM
            action, risk_level = _escalate_to_confirmation(action, risk_level, target_risk)
            blocked_reasons.append("Outbound sink payload derived from untrusted upstream content requires confirmation.")
        elif is_state_change_sink and action != DecisionAction.DENY:
            action, risk_level = _escalate_to_confirmation(action, risk_level, RiskLevel.HIGH)
            blocked_reasons.append("State-changing sink derived from untrusted upstream content requires confirmation.")
            sink_risk_factors.append("state_change_untrusted_upstream")

    if is_network_sink and delegated_or_hidden_context and external_resource_context and action != DecisionAction.DENY:
        findings.append("Delegated/hidden invocation context combined with external sink signal.")
        sink_risk_factors.append("lineage_delegated_external_sink")
        target_risk = RiskLevel.HIGH if endpoint_class in {"external", "unknown"} else RiskLevel.MEDIUM
        action, risk_level = _escalate_to_confirmation(action, risk_level, target_risk)
        blocked_reasons.append("Delegated/hidden invocation context raises sink confirmation requirement.")

    if is_state_change_sink:
        user_authorized = bool(meta.get("user_authorized", False))
        explicit_auth_chain = meta.get("authorization_chain_trusted")
        trusted_authorization_chain = (
            (explicit_auth_chain is True)
            or (
                user_authorized
                and (upstream_trust_label in {TrustLabel.TRUSTED, TrustLabel.SEMI_TRUSTED})
                and (lineage_trust_label in {TrustLabel.TRUSTED, TrustLabel.SEMI_TRUSTED, None})
            )
        )
        if user_authorized and not trusted_authorization_chain and action != DecisionAction.DENY:
            findings.append("State-change authorization lacks trusted lineage chain.")
            sink_risk_factors.append("state_change_untrusted_authorization_chain")
            action, risk_level = _escalate_to_confirmation(action, risk_level, RiskLevel.MEDIUM)
            blocked_reasons.append("State-changing operation requires trusted authorization lineage or explicit reconfirmation.")

    if lineage_feature and lineage_feature != "tools":
        findings.append(f"Lineage feature scope={lineage_feature} provided for sink inspection context.")

    if not findings:
        findings.append("No high-risk sink signal detected.")

    return SinkInspectionResult(
        action=action,
        risk_level=risk_level,
        findings=findings,
        blocked_reasons=blocked_reasons,
        requires_user_confirmation=action == DecisionAction.REQUIRE_CONFIRMATION,
        endpoint_class=endpoint_class,
        sensitive_payload_signals=sensitive_signals,
        sink_risk_factors=sorted(set(sink_risk_factors)),
        fragment_suspicion=fragment_suspicion,
        staged_exfil_signals=staged_signals,
        payload_sensitivity_class=payload_sensitivity_class,
    )
