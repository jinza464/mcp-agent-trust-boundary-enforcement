"""Tests for sink guard rules."""

from __future__ import annotations

from app.core.models import DecisionAction, RiskLevel, TrustLabel
from app.mcp.protocol_models import RequestLineage
from app.policy.capability_policy import CapabilityClassificationResult, PolicyCapability
from app.sink.sink_guard import SinkDecisionContext, inspect_sink, inspect_sink_with_context


def test_normal_low_risk_local_output_allow() -> None:
    result = inspect_sink(
        planned_action="local_output",
        payload={"message": "render report summary"},
        metadata={"sink_type": "local_output"},
    )
    assert result.action == DecisionAction.ALLOW
    assert result.risk_level == RiskLevel.LOW


def test_network_send_token_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"token": "abc123"},
        metadata={"endpoint": "https://api.external.example/upload", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert "hard_deny_explicit_secret_egress" in result.sink_risk_factors


def test_network_send_password_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload="password=my-secret-password",
        metadata={"url": "https://example.org/callback", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL


def test_external_callback_telemetry_requires_confirmation() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"event": "build_completed", "client_id": "abc-123"},
        metadata={"endpoint": "https://hooks.example.com/webhook/notify", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.requires_user_confirmation is True
    assert result.endpoint_class == "external"
    assert result.payload_sensitivity_class == "low"
    assert result.fragment_suspicion is False
    assert "external_endpoint" in result.staged_exfil_signals
    assert "external_callback_channel" in result.staged_exfil_signals


def test_trusted_internal_sync_allowed() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"event": "sync_complete", "records": 12},
        metadata={
            "endpoint": "https://sync.internal.corp/v1/push",
            "sink_type": "network_send",
            "integrity_verified": True,
            "signature_valid": True,
        },
    )
    assert result.action == DecisionAction.ALLOW
    assert result.endpoint_class == "internal"
    assert result.payload_sensitivity_class == "low"
    assert result.fragment_suspicion is False
    assert "internal_endpoint" in result.staged_exfil_signals


def test_fragmented_leakage_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={
            "chunk": "QWxhZGRpbjpPcGVuU2VzYW1lQ2h1bmsx",
            "chunk_index": 1,
            "total_chunks": 3,
            "transfer_id": "exf-001",
        },
        metadata={"endpoint": "https://attacker.example/callback", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert "fragmented_payload_marker" in result.sensitive_payload_signals or "staged_transfer_marker" in result.sensitive_payload_signals
    assert result.fragment_suspicion is True
    assert result.payload_sensitivity_class == "suspicious"
    assert "external_endpoint" in result.staged_exfil_signals
    assert "external_callback_channel" in result.staged_exfil_signals


def test_staged_exfiltration_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"stage_1": "diag-a", "stage_2": "diag-b", "sequence_id": "seq-77"},
        metadata={"endpoint": "https://collector.example.com/callback", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert "staged_transfer_marker" in result.sensitive_payload_signals
    assert "external_callback_channel" in result.staged_exfil_signals
    assert "low_obviousness_payload" in result.staged_exfil_signals
    assert result.payload_sensitivity_class == "suspicious"


def test_obfuscated_exfiltration_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={
            "blob": "ZXlKaGJHY2lPaUpJVXpJMU5pSjkuZXlKemRXSWlPaUpwYzNNaUxDSnBZWFFpT2pFMk56ZzVNVGt3T1RFaWZRLg==",
        },
        metadata={"endpoint": "https://unknown.example/upload", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert "obfuscated_payload_pattern" in result.sensitive_payload_signals
    assert result.payload_sensitivity_class == "suspicious"


def test_allowlisted_callback_telemetry_allowed() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"event": "job_done", "summary": "no secrets"},
        metadata={
            "endpoint": "https://hooks.partner.example/callback",
            "sink_type": "network_send",
            "allowlisted_domains": ["hooks.partner.example"],
        },
    )
    assert result.action == DecisionAction.ALLOW
    assert result.endpoint_class == "allowlisted"
    assert result.payload_sensitivity_class == "low"
    assert "allowlisted_endpoint" in result.staged_exfil_signals


def test_sensitive_config_write_requires_confirmation() -> None:
    result = inspect_sink(
        planned_action="file_write",
        payload="API_KEY=abcd",
        metadata={"path": "/workspace/.env", "sink_type": "file_write"},
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.risk_level == RiskLevel.HIGH


def test_write_report_file_allow() -> None:
    result = inspect_sink(
        planned_action="file_write",
        payload="Quarterly report body",
        metadata={"path": "/workspace/reports/q1_report.md", "sink_type": "file_write"},
    )
    assert result.action == DecisionAction.ALLOW
    assert result.risk_level == RiskLevel.LOW
    assert result.payload_sensitivity_class == "low"
    assert result.fragment_suspicion is False


def test_credential_access_requires_confirmation() -> None:
    result = inspect_sink(
        planned_action="credential_access",
        payload="read credentials for deployment",
        metadata={"sink_type": "credential_access"},
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.risk_level == RiskLevel.HIGH


def test_state_changing_action_requires_confirmation() -> None:
    result = inspect_sink(
        planned_action="state_change",
        payload={"operation": "update_policy"},
        metadata={"sink_type": "state_change"},
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.risk_level == RiskLevel.MEDIUM


def test_lineage_untrusted_upstream_external_network_context_is_reflected() -> None:
    request_lineage = RequestLineage(
        request_id="r-1",
        parent_request_id=None,
        root_user_request_id="root-r-1",
        source_role="client",
        feature="tools",
        trust_label=TrustLabel.UNTRUSTED,
    )
    result = inspect_sink_with_context(
        SinkDecisionContext(
            decision_action="network_send",
            request_lineage=request_lineage,
            upstream_trust_label=TrustLabel.UNTRUSTED,
            payload={"event": "build_done"},
            sink_metadata={"sink_type": "network_send", "endpoint": "https://external.example/upload"},
        )
    )
    assert result.action in {DecisionAction.REQUIRE_CONFIRMATION, DecisionAction.DENY}
    assert any("untrusted upstream" in item.lower() for item in [*result.findings, *result.blocked_reasons]) or (
        "lineage_untrusted_upstream_payload" in result.sink_risk_factors
    )


def test_lineage_delegated_external_context_increases_sink_attention() -> None:
    request_lineage = RequestLineage(
        request_id="r-2",
        parent_request_id=None,
        root_user_request_id="root-r-2",
        source_role="client",
        feature="tools",
        trust_label=TrustLabel.SEMI_TRUSTED,
    )
    capability_result = CapabilityClassificationResult(
        detected_capabilities=[PolicyCapability.TOOLCHAIN_DELEGATION, PolicyCapability.NETWORK_EGRESS],
        risk_level=RiskLevel.HIGH,
        findings=[],
        structured_findings=[],
    )
    result = inspect_sink_with_context(
        SinkDecisionContext(
            decision_action="network_send",
            request_lineage=request_lineage,
            upstream_trust_label=TrustLabel.SEMI_TRUSTED,
            capability_result=capability_result,
            payload={"event": "status"},
            sink_metadata={"sink_type": "network_send", "endpoint": "https://hooks.example.com/callback"},
        )
    )
    assert result.action in {DecisionAction.REQUIRE_CONFIRMATION, DecisionAction.DENY}
    assert "lineage_delegated_external_sink" in result.sink_risk_factors or any(
        "delegated" in item.lower() or "hidden invocation" in item.lower()
        for item in [*result.findings, *result.blocked_reasons]
    )


def test_state_change_user_authorized_but_untrusted_lineage_not_fully_relaxed() -> None:
    request_lineage = RequestLineage(
        request_id="r-3",
        parent_request_id=None,
        root_user_request_id="root-r-3",
        source_role="client",
        feature="tools",
        trust_label=TrustLabel.UNTRUSTED,
    )
    result = inspect_sink_with_context(
        SinkDecisionContext(
            decision_action="state_change",
            request_lineage=request_lineage,
            upstream_trust_label=TrustLabel.UNTRUSTED,
            payload={"operation": "update_policy"},
            sink_metadata={"sink_type": "state_change", "user_authorized": True},
        )
    )
    assert result.action != DecisionAction.ALLOW
    assert result.action in {DecisionAction.REQUIRE_CONFIRMATION, DecisionAction.DENY}
    assert any("authorization lineage" in item.lower() or "untrusted upstream" in item.lower() for item in [*result.findings, *result.blocked_reasons]) or (
        "state_change_untrusted_authorization_chain" in result.sink_risk_factors
        or "state_change_untrusted_upstream" in result.sink_risk_factors
    )


def test_inspect_sink_legacy_entrypoint_still_works_after_context_upgrade() -> None:
    legacy = inspect_sink(
        planned_action="network_send",
        payload={"event": "build_completed"},
        metadata={"sink_type": "network_send", "endpoint": "https://hooks.example.com/callback"},
    )
    assert legacy.action == DecisionAction.REQUIRE_CONFIRMATION
    assert legacy.endpoint_class == "external"
