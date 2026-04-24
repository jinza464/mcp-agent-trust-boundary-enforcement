"""Minimal runtime governance semantics for timeout, cancellation, and partial failure."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal, TypeAlias

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.models import DecisionAction

RuntimeStage: TypeAlias = Literal[
    "request_context",
    "trust_tagging",
    "capability_classification",
    "metadata_validation",
    "decision",
    "sink_check",
    "tool_call",
    "finalization",
    "background_task",
]
CancellationSource: TypeAlias = Literal["user", "timeout", "system", "policy", "shutdown", "unknown"]


class TimeoutPolicy(BaseModel):
    """Prototype timeout budget hints for future structured runtime execution."""

    model_config = ConfigDict(extra="forbid")

    total_timeout_ms: int = Field(default=30_000, ge=1)
    tool_call_timeout_ms: int = Field(default=10_000, ge=1)
    sink_check_timeout_ms: int = Field(default=5_000, ge=1)
    metadata_validation_timeout_ms: int = Field(default=5_000, ge=1)

    @field_validator("tool_call_timeout_ms", "sink_check_timeout_ms", "metadata_validation_timeout_ms")
    @classmethod
    def _stage_timeout_within_total(cls, value: int, info) -> int:
        total = info.data.get("total_timeout_ms")
        if isinstance(total, int) and value > total:
            raise ValueError("stage timeout must not exceed total_timeout_ms")
        return value


class CancellationState(BaseModel):
    """Cancellation state captured without requiring async cancellation scopes yet."""

    model_config = ConfigDict(extra="forbid")

    cancelled: bool = False
    reason: str | None = None
    cancelled_at: datetime | None = None
    source: CancellationSource = "unknown"

    def is_cancelled(self) -> bool:
        return self.cancelled

    def mark_cancelled(
        self,
        *,
        reason: str,
        source: CancellationSource = "unknown",
        cancelled_at: datetime | None = None,
    ) -> "CancellationState":
        return self.model_copy(
            update={
                "cancelled": True,
                "reason": reason,
                "cancelled_at": cancelled_at or datetime.now(UTC),
                "source": source,
            }
        )


class PartialFailure(BaseModel):
    """Recoverable or fail-closed stage failure observed during runtime orchestration."""

    model_config = ConfigDict(extra="forbid")

    stage: RuntimeStage | str
    error_type: str
    message: str
    recoverable: bool = False
    fallback_action: DecisionAction | str | None = None

    @field_validator("stage", "error_type", "message")
    @classmethod
    def _non_empty_failure_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("partial failure stage/error_type/message must be non-empty.")
        return normalized


class RuntimeExecutionGovernance(BaseModel):
    """Shared semantic envelope for future timeout/cancellation/partial-failure handling."""

    model_config = ConfigDict(extra="forbid")

    timeout_policy: TimeoutPolicy = Field(default_factory=TimeoutPolicy)
    cancellation_state: CancellationState = Field(default_factory=CancellationState)
    partial_failures: list[PartialFailure] = Field(default_factory=list)
    fail_closed: bool = True

    def is_cancelled(self) -> bool:
        return self.cancellation_state.is_cancelled()

    def add_partial_failure(
        self,
        failure: PartialFailure | None = None,
        *,
        stage: RuntimeStage | str | None = None,
        error_type: str | None = None,
        message: str | None = None,
        recoverable: bool = False,
        fallback_action: DecisionAction | str | None = None,
    ) -> "RuntimeExecutionGovernance":
        resolved = failure or PartialFailure(
            stage=stage or "background_task",
            error_type=error_type or "unknown_error",
            message=message or "Runtime stage reported a partial failure.",
            recoverable=recoverable,
            fallback_action=fallback_action,
        )
        return self.model_copy(update={"partial_failures": [*self.partial_failures, resolved]})

    def should_fail_closed(self, stage: RuntimeStage | str | None = None) -> bool:
        if self.is_cancelled():
            return True
        if not self.fail_closed:
            return False
        if stage is None:
            return any(not failure.recoverable for failure in self.partial_failures)
        return any(failure.stage == stage and not failure.recoverable for failure in self.partial_failures)

    def summary(self) -> dict[str, object]:
        return {
            "timeout_policy": self.timeout_policy.model_dump(mode="json"),
            "cancellation_state": self.cancellation_state.model_dump(mode="json"),
            "partial_failure_count": len(self.partial_failures),
            "recoverable_failure_count": sum(1 for failure in self.partial_failures if failure.recoverable),
            "non_recoverable_failure_count": sum(1 for failure in self.partial_failures if not failure.recoverable),
            "fail_closed": self.fail_closed,
            "should_fail_closed": self.should_fail_closed(),
            "partial_failures": [failure.model_dump(mode="json") for failure in self.partial_failures],
        }
