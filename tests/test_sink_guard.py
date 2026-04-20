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


def test_network_send_password_denied() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload="password=my-secret-password",
        metadata={"url": "https://example.org/callback", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.DENY
    assert result.risk_level == RiskLevel.CRITICAL


def test_webhook_outbound_requires_confirmation() -> None:
    result = inspect_sink(
        planned_action="network_send",
        payload={"event": "build_completed"},
        metadata={"endpoint": "https://hooks.example.com/webhook/notify", "sink_type": "network_send"},
    )
    assert result.action == DecisionAction.REQUIRE_CONFIRMATION
    assert result.requires_user_confirmation is True


def test_write_env_requires_confirmation() -> None:
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
