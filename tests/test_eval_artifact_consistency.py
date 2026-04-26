"""Tests for eval artifact semantic versioning and consistency validation."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.core.models import DecisionAction, RiskLevel
from app.eval.metrics import export_results, summarize_results
from app.eval.runner import EvalCaseResult
from app.eval.runtime_semantics import (
    CASE_PACK_VERSION,
    RUNTIME_SEMANTICS_VERSION,
    SEAL_TAG,
    validate_execution_artifact_consistency,
)


def _result() -> EvalCaseResult:
    return EvalCaseResult(
        case_id="artifact-consistency-case",
        attack_type="benign-safe",
        is_attack=False,
        is_benign=True,
        involves_sink=False,
        detected_risk_level=RiskLevel.LOW,
        decision_action=DecisionAction.ALLOW,
        sink_action=None,
        matched_expectation=True,
        intervention_triggered=False,
        completed_execution=True,
        execution_degraded=False,
        leak_possible=False,
    )


def test_consistent_artifact_passes_consistency_validator() -> None:
    artifact = {
        "case_id": "consistent",
        "decision_action": "allow",
        "sink_action": "allow",
        "completed_execution": True,
        "execution_degraded": False,
        "intervention_triggered": False,
        "leak_possible": True,
    }

    assert validate_execution_artifact_consistency(artifact) == []


def test_conflicting_artifact_is_reported_by_consistency_validator() -> None:
    artifact = {
        "case_id": "conflict",
        "decision_action": "deny",
        "sink_action": None,
        "completed_execution": True,
        "execution_degraded": False,
        "intervention_triggered": False,
        "leak_possible": True,
    }

    warnings = validate_execution_artifact_consistency(artifact)

    assert warnings
    assert any("completed_execution mismatch" in warning for warning in warnings)
    assert any("intervention_triggered mismatch" in warning for warning in warnings)


def test_summary_and_exported_artifacts_include_version_metadata() -> None:
    result = _result()
    summary = summarize_results([result])

    assert summary.semantics_version == RUNTIME_SEMANTICS_VERSION
    assert summary.case_pack_version == CASE_PACK_VERSION
    assert summary.seal_tag == SEAL_TAG
    assert summary.total_cases == 1
    assert summary.match_rate == 1.0
    assert summary.execution_completion_rate == 1.0
    assert summary.intervention_rate == 0.0

    out_dir = Path("data") / "test_outputs" / f"artifact-consistency-{uuid4().hex}"
    try:
        paths = export_results([result], out_dir)
        case_payload = json.loads(paths["cases"].read_text(encoding="utf-8"))
        summary_payload = json.loads(paths["summary"].read_text(encoding="utf-8"))

        assert case_payload[0]["semantics_version"] == RUNTIME_SEMANTICS_VERSION
        assert case_payload[0]["case_pack_version"] == CASE_PACK_VERSION
        assert case_payload[0]["seal_tag"] == SEAL_TAG
        assert summary_payload["semantics_version"] == RUNTIME_SEMANTICS_VERSION
        assert summary_payload["case_pack_version"] == CASE_PACK_VERSION
        assert summary_payload["seal_tag"] == SEAL_TAG
    finally:
        if out_dir.exists():
            for item in out_dir.glob("*"):
                item.unlink()
            out_dir.rmdir()
