"""Tests for sink guard rules."""

from __future__ import annotations

from app.core.models import DecisionAction, RiskLevel
from app.sink.sink_guard import inspect_sink


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
    assert result.payload_sensitivity_class == "low_sensitivity"


def test_trusted_internal_sync_allowed() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"event": "sync_complete", "records": 12},
        metadata={"endpoint": "https://sync.internal.corp/v1/push", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.ALLOW
    assert result.endpoint_class == "internal"
    assert result.payload_sensitivity_class == "low_sensitivity"


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


def test_staged_exfiltration_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={
            "stage_1": "diag-a",
            "stage_2": "diag-b",
            "sequence_id": "seq-77",
        },
        metadata={"endpoint": "https://collector.example.com/callback", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL
    assert "staged_transfer_marker" in result.sensitive_payload_signals
    assert "external_callback_channel" in result.staged_exfil_signals


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
    assert result.payload_sensitivity_class == "low_sensitivity"


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
