"""Unified runtime/eval semantics for execution lifecycle and intervention states."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction

RUNTIME_SEMANTICS_VERSION = "v1"
CASE_PACK_VERSION = "v1"
SEAL_TAG = "research-prototype-v1.0"

SEMANTIC_ARTIFACT_FIELDS: tuple[str, ...] = (
    "completed_execution",
    "execution_degraded",
    "intervention_triggered",
    "leak_possible",
)


def artifact_metadata() -> dict[str, str]:
    """Return stable artifact version metadata for eval outputs."""
    return {
        "semantics_version": RUNTIME_SEMANTICS_VERSION,
        "case_pack_version": CASE_PACK_VERSION,
        "seal_tag": SEAL_TAG,
    }


class ExecutionSemantics(BaseModel):
    """Single source of truth for runtime/eval execution semantics."""

    model_config = ConfigDict(extra="forbid")

    decision_action: DecisionAction = Field(...)
    sink_action: DecisionAction | None = Field(default=None)

    executed: bool = Field(default=False)
    completed_execution: bool = Field(default=False)
    execution_degraded: bool = Field(default=False)

    intervention_triggered: bool = Field(default=False)
    hard_blocked: bool = Field(default=False)
    confirmation_required: bool = Field(default=False)
    escalation_triggered: bool = Field(default=False)

    blocked_by_decision: bool = Field(default=False)
    blocked_by_sink: bool = Field(default=False)

    leak_possible: bool = Field(default=False)


@dataclass(frozen=True)
class _ActionSemanticState:
    blocked_by_decision: bool
    blocked_by_sink: bool
    hard_blocked: bool
    confirmation_required: bool
    escalation_triggered: bool
    intervention_triggered: bool
    executed: bool
    completed_execution: bool
    execution_degraded: bool


_INTERVENTION_ACTIONS: frozenset[DecisionAction] = frozenset(
    {
        DecisionAction.DENY,
        DecisionAction.REQUIRE_CONFIRMATION,
        DecisionAction.ESCALATE,
        DecisionAction.SANDBOX,
        DecisionAction.REDACT,
    }
)
_DECISION_BLOCK_ACTIONS: frozenset[DecisionAction] = frozenset(
    {
        DecisionAction.DENY,
        DecisionAction.REQUIRE_CONFIRMATION,
        DecisionAction.ESCALATE,
    }
)
_SINK_BLOCK_ACTIONS: frozenset[DecisionAction] = frozenset(
    {
        DecisionAction.DENY,
        DecisionAction.REQUIRE_CONFIRMATION,
    }
)
_DEGRADE_ACTIONS: frozenset[DecisionAction] = frozenset(
    {
        DecisionAction.SANDBOX,
        DecisionAction.REDACT,
    }
)


def _normalize_action(value: DecisionAction | str | None) -> DecisionAction | None:
    if value is None:
        return None
    if isinstance(value, DecisionAction):
        return value
    normalized = str(value).strip().lower()
    for action in DecisionAction:
        if normalized == action.value:
            return action
    raise ValueError(f"Unsupported action value: {value!r}")


def _artifact_to_mapping(artifact: Mapping[str, Any] | BaseModel) -> Mapping[str, Any]:
    if isinstance(artifact, BaseModel):
        return artifact.model_dump(mode="python")
    return artifact


def _artifact_optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            return True
        if normalized in {"false", "0", "no", "n"}:
            return False
    return None


def _infer_action_semantics(
    decision_action: DecisionAction,
    sink_action: DecisionAction | None,
) -> _ActionSemanticState:
    blocked_by_decision = decision_action in _DECISION_BLOCK_ACTIONS
    blocked_by_sink = sink_action in _SINK_BLOCK_ACTIONS
    hard_blocked = decision_action == DecisionAction.DENY or sink_action == DecisionAction.DENY
    confirmation_required = (
        decision_action == DecisionAction.REQUIRE_CONFIRMATION
        or sink_action == DecisionAction.REQUIRE_CONFIRMATION
    )
    escalation_triggered = (
        decision_action == DecisionAction.ESCALATE or sink_action == DecisionAction.ESCALATE
    )
    intervention_triggered = (
        decision_action in _INTERVENTION_ACTIONS
        or (sink_action is not None and sink_action in _INTERVENTION_ACTIONS)
    )

    inferred_executed = not (blocked_by_decision or blocked_by_sink)
    inferred_completed_execution = inferred_executed
    inferred_execution_degraded = inferred_executed and (
        decision_action in _DEGRADE_ACTIONS
        or (sink_action is not None and sink_action in _DEGRADE_ACTIONS)
    )

    return _ActionSemanticState(
        blocked_by_decision=blocked_by_decision,
        blocked_by_sink=blocked_by_sink,
        hard_blocked=hard_blocked,
        confirmation_required=confirmation_required,
        escalation_triggered=escalation_triggered,
        intervention_triggered=intervention_triggered,
        executed=inferred_executed,
        completed_execution=inferred_completed_execution,
        execution_degraded=inferred_execution_degraded,
    )


def _merge_runtime_truth(
    base_state: _ActionSemanticState,
    *,
    runtime_executed: bool | None,
    runtime_completed_execution: bool | None,
    runtime_execution_degraded: bool | None,
) -> tuple[bool, bool, bool]:
    executed = base_state.executed if runtime_executed is None else bool(runtime_executed)
    completed_execution = (
        base_state.completed_execution
        if runtime_completed_execution is None
        else bool(runtime_completed_execution)
    )
    if runtime_completed_execution is not None and runtime_executed is None and completed_execution:
        executed = True
    execution_degraded = bool(runtime_execution_degraded) if runtime_execution_degraded is not None else base_state.execution_degraded
    return executed, completed_execution, execution_degraded


def _infer_leak_possible(
    decision_action: DecisionAction,
    sink_action: DecisionAction | None,
    *,
    completed_execution: bool,
) -> bool:
    # Conservative boundary: only mark possible leakage when execution completed and
    # both gates are explicit ALLOW; unknown/partial sink semantics default to False.
    if not completed_execution:
        return False
    if decision_action != DecisionAction.ALLOW:
        return False
    if sink_action is None:
        return False
    return sink_action == DecisionAction.ALLOW


def compute_execution_semantics(
    decision_action: DecisionAction | str,
    sink_action: DecisionAction | str | None,
    *,
    runtime_executed: bool | None = None,
    runtime_completed_execution: bool | None = None,
    runtime_execution_degraded: bool | None = None,
) -> ExecutionSemantics:
    """
    Compute normalized execution semantics from action-level gates and optional runtime truth.

    Layer 1: infer semantics from decision/sink actions.
    Layer 2: override execution truth fields with runtime values when available.
    """
    normalized_decision = _normalize_action(decision_action)
    if normalized_decision is None:
        raise ValueError("decision_action must be a valid DecisionAction.")
    normalized_sink = _normalize_action(sink_action)

    action_state = _infer_action_semantics(normalized_decision, normalized_sink)
    executed, completed_execution, execution_degraded = _merge_runtime_truth(
        action_state,
        runtime_executed=runtime_executed,
        runtime_completed_execution=runtime_completed_execution,
        runtime_execution_degraded=runtime_execution_degraded,
    )
    if runtime_execution_degraded is None:
        # Eval compatibility: "incomplete execution + intervention" is degraded even when
        # action type is not sandbox/redact (e.g. confirmation or escalation gates).
        execution_degraded = execution_degraded or (
            (not completed_execution) and action_state.intervention_triggered
        )
    leak_possible = _infer_leak_possible(
        normalized_decision,
        normalized_sink,
        completed_execution=completed_execution,
    )

    return ExecutionSemantics(
        decision_action=normalized_decision,
        sink_action=normalized_sink,
        executed=executed,
        completed_execution=completed_execution,
        execution_degraded=execution_degraded,
        intervention_triggered=action_state.intervention_triggered,
        hard_blocked=action_state.hard_blocked,
        confirmation_required=action_state.confirmation_required,
        escalation_triggered=action_state.escalation_triggered,
        blocked_by_decision=action_state.blocked_by_decision,
        blocked_by_sink=action_state.blocked_by_sink,
        leak_possible=leak_possible,
    )


def validate_execution_artifact_consistency(
    artifact: Mapping[str, Any] | BaseModel,
    *,
    raise_on_warning: bool = False,
) -> list[str]:
    """
    Validate persisted execution semantic fields against the canonical semantic function.

    The validator is intentionally read-only: it reports drift between artifact fields and
    recomputed semantics, but never rewrites historical artifacts.
    """
    item = _artifact_to_mapping(artifact)
    if "decision_action" not in item:
        warnings = ["artifact missing required decision_action for semantic consistency validation"]
        if raise_on_warning:
            raise ValueError("; ".join(warnings))
        return warnings

    try:
        expected = compute_execution_semantics(
            item["decision_action"],
            item.get("sink_action"),
            runtime_executed=_artifact_optional_bool(item.get("runtime_executed")),
            runtime_completed_execution=_artifact_optional_bool(item.get("runtime_completed_execution")),
            runtime_execution_degraded=_artifact_optional_bool(item.get("runtime_execution_degraded")),
        )
    except ValueError as exc:
        warnings = [f"artifact semantic validation failed: {exc}"]
        if raise_on_warning:
            raise ValueError("; ".join(warnings)) from exc
        return warnings

    warnings: list[str] = []
    expected_payload = expected.model_dump(mode="python")
    case_id = str(item.get("case_id") or item.get("id") or "unknown")
    for field in SEMANTIC_ARTIFACT_FIELDS:
        if field not in item or item.get(field) is None:
            continue
        observed = _artifact_optional_bool(item.get(field))
        expected_value = expected_payload[field]
        if observed is None:
            warnings.append(f"{case_id}: {field} is not a boolean-compatible value")
            continue
        if observed != expected_value:
            warnings.append(
                f"{case_id}: {field} mismatch; observed={observed}, expected={expected_value}"
            )

    if raise_on_warning and warnings:
        raise ValueError("; ".join(warnings))
    return warnings
