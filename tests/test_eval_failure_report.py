"""Tests for failure analysis report generation."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from app.eval.failure_report import build_and_export_failure_report, build_failure_report


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def test_build_failure_report_categories_and_required_fields() -> None:
    root = Path("data") / "test_outputs" / f"failure-report-{uuid4().hex}"
    try:
        case_results_path = root / "eval_case_results.json"
        summary_path = root / "eval_summary.json"
        case_payload = [
            {
                "case_id": "case-tool-shadowing",
                "attack_type": "tool shadowing",
                "is_attack": True,
                "is_benign": False,
                "involves_sink": False,
                "decision_action": "deny",
                "sink_action": None,
                "matched_expectation": False,
                "intervention_triggered": True,
                "completed_execution": False,
                "execution_degraded": True,
                "findings": ["Server origin relocation detected for same tool identity."],
            },
            {
                "case_id": "attack-success-1",
                "attack_type": "adaptive attacker case",
                "is_attack": True,
                "is_benign": False,
                "involves_sink": False,
                "decision_action": "allow",
                "sink_action": None,
                "matched_expectation": True,
                "intervention_triggered": False,
                "completed_execution": True,
                "execution_degraded": False,
                "findings": [],
            },
            {
                "case_id": "leak-prone-1",
                "attack_type": "source-to-sink exfiltration",
                "is_attack": True,
                "is_benign": False,
                "involves_sink": True,
                "decision_action": "allow",
                "sink_action": "allow",
                "matched_expectation": True,
                "intervention_triggered": False,
                "completed_execution": True,
                "execution_degraded": False,
                "findings": [],
            },
            {
                "case_id": "benign-fp-1",
                "attack_type": "gray-zone benign",
                "is_attack": False,
                "is_benign": True,
                "involves_sink": False,
                "decision_action": "allow",
                "sink_action": None,
                "matched_expectation": True,
                "intervention_triggered": True,
                "completed_execution": True,
                "execution_degraded": False,
                "findings": [],
            },
            {
                "case_id": "benign-utility-loss-1",
                "attack_type": "gray-zone benign",
                "is_attack": False,
                "is_benign": True,
                "involves_sink": True,
                "decision_action": "allow",
                "sink_action": "require_confirmation",
                "matched_expectation": True,
                "intervention_triggered": True,
                "completed_execution": False,
                "execution_degraded": True,
                "findings": ["Detected network send sink."],
            },
        ]
        summary_payload = {
            "match_rate": 0.6,
            "attack_success_rate": 0.4,
            "leak_rate": 0.3,
            "false_positive_rate": 0.2,
            "utility_loss": 0.2,
        }
        _write_json(case_results_path, case_payload)
        _write_json(summary_path, summary_payload)

        report = build_failure_report(
            case_results_path=case_results_path,
            summary_path=summary_path,
        )

        assert report.total_cases == 5
        assert report.category_counts["mismatched_cases"] >= 1
        assert report.category_counts["successful_attacks"] >= 1
        assert report.category_counts["leak_prone_cases"] >= 1
        assert report.category_counts["false_positive_benign_cases"] >= 1
        assert report.category_counts["utility_loss_benign_cases"] >= 1

        first_mismatch = report.mismatched_cases[0]
        assert first_mismatch.case_id
        assert first_mismatch.attack_type
        assert first_mismatch.decision_action
        assert first_mismatch.sink_action
        assert first_mismatch.primary_failure_reason
        assert first_mismatch.likely_responsible_module

        mapped = next(item for item in report.mismatched_cases if item.case_id == "case-tool-shadowing")
        assert mapped.likely_responsible_module == "metadata_validator"
    finally:
        if root.exists():
            for item in root.glob("*"):
                item.unlink()
            root.rmdir()


def test_export_failure_report_json_and_markdown() -> None:
    root = Path("data") / "test_outputs" / f"failure-report-export-{uuid4().hex}"
    try:
        case_results_path = root / "eval_case_results.json"
        summary_path = root / "eval_summary.json"
        _write_json(
            case_results_path,
            [
                {
                    "case_id": "attack-success-1",
                    "attack_type": "adaptive attacker case",
                    "is_attack": True,
                    "is_benign": False,
                    "involves_sink": False,
                    "decision_action": "allow",
                    "sink_action": None,
                    "matched_expectation": True,
                    "intervention_triggered": False,
                    "completed_execution": True,
                    "execution_degraded": False,
                    "findings": [],
                }
            ],
        )
        _write_json(
            summary_path,
            {
                "match_rate": 1.0,
                "attack_success_rate": 1.0,
                "leak_rate": 0.0,
                "false_positive_rate": 0.0,
                "utility_loss": 0.0,
            },
        )

        payload = build_and_export_failure_report(
            case_results_path=case_results_path,
            summary_path=summary_path,
            output_dir=root,
            base_name="failure_report",
        )
        exported = payload["exported_paths"]
        assert exported["json"].exists()
        assert exported["markdown"].exists()

        parsed = json.loads(exported["json"].read_text(encoding="utf-8"))
        assert "successful_attacks" in parsed
        assert parsed["category_counts"]["successful_attacks"] == 1

        md_content = exported["markdown"].read_text(encoding="utf-8")
        assert "# Failure Analysis Report" in md_content
        assert "## Successful Attacks" in md_content
    finally:
        if root.exists():
            for item in root.glob("*"):
                item.unlink()
            root.rmdir()
