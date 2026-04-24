from __future__ import annotations

import json

from app.core.concurrency import CancellationState, RuntimeExecutionGovernance, TimeoutPolicy
from app.core.models import DecisionAction


def test_timeout_policy_defaults_and_custom_values_are_available() -> None:
    default_policy = TimeoutPolicy()
    custom_policy = TimeoutPolicy(total_timeout_ms=20_000, tool_call_timeout_ms=5_000)

    assert default_policy.total_timeout_ms == 30_000
    assert default_policy.tool_call_timeout_ms == 10_000
    assert custom_policy.total_timeout_ms == 20_000
    assert custom_policy.tool_call_timeout_ms == 5_000


def test_cancellation_state_reports_cancelled_status() -> None:
    active = CancellationState()
    cancelled = active.mark_cancelled(reason="user stop", source="user")

    assert active.is_cancelled() is False
    assert cancelled.is_cancelled() is True
    assert cancelled.reason == "user stop"
    assert cancelled.source == "user"
    assert cancelled.cancelled_at is not None


def test_runtime_governance_adds_partial_failure_and_fails_closed() -> None:
    governance = RuntimeExecutionGovernance()

    updated = governance.add_partial_failure(
        stage="sink_check",
        error_type="TimeoutError",
        message="sink check timed out",
        recoverable=False,
        fallback_action=DecisionAction.DENY,
    )

    assert governance.partial_failures == []
    assert len(updated.partial_failures) == 1
    assert updated.should_fail_closed("sink_check") is True
    assert updated.should_fail_closed() is True


def test_runtime_governance_respects_fail_open_setting_for_partial_failures() -> None:
    governance = RuntimeExecutionGovernance(fail_closed=False).add_partial_failure(
        stage="metadata_validation",
        error_type="ValidationTimeout",
        message="metadata validator timed out",
        recoverable=False,
    )

    assert governance.should_fail_closed("metadata_validation") is False


def test_runtime_governance_summary_is_json_serializable() -> None:
    governance = RuntimeExecutionGovernance().add_partial_failure(
        stage="tool_call",
        error_type="ToolError",
        message="tool call failed",
        recoverable=True,
    )

    summary = governance.summary()
    assert summary["partial_failure_count"] == 1
    assert summary["recoverable_failure_count"] == 1
    assert summary["non_recoverable_failure_count"] == 0
    assert summary["fail_closed"] is True
    json.dumps(summary)
