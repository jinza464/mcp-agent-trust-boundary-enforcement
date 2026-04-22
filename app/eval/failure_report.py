"""Failure analysis report builder for paper-oriented case-level diagnostics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.eval.attack_cases import default_attack_cases


DEFAULT_CASE_RESULTS_PATH = Path("data/eval_outputs/baseline/eval_case_results.json")
DEFAULT_SUMMARY_PATH = Path("data/eval_outputs/baseline/eval_summary.json")


class FailureCaseSummary(BaseModel):
    """Minimal structured failure/trade-off case summary for paper analysis."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    attack_type: str
    decision_action: str
    sink_action: str
    primary_failure_reason: str
    likely_responsible_module: str


class FailureAnalysisReport(BaseModel):
    """Structured failure analysis payload exported to JSON + Markdown."""

    model_config = ConfigDict(extra="forbid")

    total_cases: int
    summary_snapshot: dict[str, object] = Field(default_factory=dict)
    category_counts: dict[str, int] = Field(default_factory=dict)
    mismatched_cases: list[FailureCaseSummary] = Field(default_factory=list)
    successful_attacks: list[FailureCaseSummary] = Field(default_factory=list)
    leak_prone_cases: list[FailureCaseSummary] = Field(default_factory=list)
    false_positive_benign_cases: list[FailureCaseSummary] = Field(default_factory=list)
    utility_loss_benign_cases: list[FailureCaseSummary] = Field(default_factory=list)
    trade_off_cases: list[FailureCaseSummary] = Field(default_factory=list)
    recommended_analysis_cases: list[FailureCaseSummary] = Field(default_factory=list)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_action(value: object) -> str:
    if value is None:
        return "none"
    text = str(value).strip().lower()
    return text or "none"


def _is_intervention(item: dict[str, object]) -> bool:
    explicit = item.get("intervention_triggered")
    if explicit is not None:
        return bool(explicit)
    decision_action = _normalize_action(item.get("decision_action"))
    sink_action = _normalize_action(item.get("sink_action"))
    return decision_action != "allow" or sink_action not in {"none", "allow"}


def _is_completed(item: dict[str, object]) -> bool:
    explicit = item.get("completed_execution")
    if explicit is not None:
        return bool(explicit)
    decision_action = _normalize_action(item.get("decision_action"))
    sink_action = _normalize_action(item.get("sink_action"))
    decision_blocks = decision_action in {"deny", "escalate", "require_confirmation"}
    sink_blocks = sink_action in {"deny", "require_confirmation"}
    return not (decision_blocks or sink_blocks)


def _is_degraded(item: dict[str, object]) -> bool:
    explicit = item.get("execution_degraded")
    if explicit is not None:
        return bool(explicit)
    if not _is_completed(item):
        return True
    decision_action = _normalize_action(item.get("decision_action"))
    return decision_action in {"sandbox", "redact"}


def _build_case_meta_lookup() -> dict[str, dict[str, str]]:
    lookup: dict[str, dict[str, str]] = {}
    for case in default_attack_cases():
        lookup[case.id] = {
            "primary_target_module": case.primary_target_module,
            "expected_failure_mode": case.expected_failure_mode,
        }
    return lookup


def _infer_module(item: dict[str, object], case_meta_lookup: dict[str, dict[str, str]]) -> str:
    case_id = str(item.get("case_id", ""))
    if case_id in case_meta_lookup:
        return case_meta_lookup[case_id]["primary_target_module"]

    findings_text = " ".join(str(x).lower() for x in item.get("findings", []))
    sink_action = _normalize_action(item.get("sink_action"))
    if sink_action != "none" or bool(item.get("involves_sink")):
        return "sink_guard"
    if any(token in findings_text for token in ["schema", "metadata", "rollback", "origin relocation"]):
        return "metadata_validator"
    if "source trust" in findings_text:
        return "trust_tagger"
    if any(token in findings_text for token in ["hidden_invocation", "toolchain_delegation", "capability"]):
        return "capability_policy"
    return "decision_engine"


def _primary_failure_reason(
    *,
    mismatched: bool,
    successful_attack: bool,
    leak_prone: bool,
    false_positive: bool,
    utility_loss: bool,
) -> str:
    if successful_attack and leak_prone:
        return "attack_succeeded_and_sink_path_remained_leak_prone"
    if successful_attack:
        return "attack_succeeded_without_effective_intervention"
    if leak_prone:
        return "sink_path_completed_without_hard_block"
    if false_positive and utility_loss:
        return "benign_case_intervened_and_lost_utility"
    if false_positive:
        return "benign_case_intervened_false_positive"
    if utility_loss:
        return "benign_case_execution_degraded_or_blocked"
    if mismatched:
        return "expected_outcome_mismatch"
    return "analysis_candidate"


def _to_summary(
    item: dict[str, object],
    *,
    primary_failure_reason: str,
    likely_responsible_module: str,
) -> FailureCaseSummary:
    return FailureCaseSummary(
        case_id=str(item.get("case_id", "")),
        attack_type=str(item.get("attack_type", "")),
        decision_action=_normalize_action(item.get("decision_action")),
        sink_action=_normalize_action(item.get("sink_action")),
        primary_failure_reason=primary_failure_reason,
        likely_responsible_module=likely_responsible_module,
    )


def _markdown_table(items: list[FailureCaseSummary]) -> str:
    if not items:
        return "_None_\n"
    lines = [
        "| case_id | attack_type | decision_action | sink_action | primary_failure_reason | likely_responsible_module |",
        "|---|---|---|---|---|---|",
    ]
    for item in items:
        lines.append(
            f"| {item.case_id} | {item.attack_type} | {item.decision_action} | {item.sink_action} | "
            f"{item.primary_failure_reason} | {item.likely_responsible_module} |"
        )
    return "\n".join(lines) + "\n"


def _build_markdown(report: FailureAnalysisReport, case_results_path: Path, summary_path: Path) -> str:
    lines = [
        "# Failure Analysis Report",
        "",
        f"- case_results: `{case_results_path}`",
        f"- summary: `{summary_path}`",
        "",
        "## Category Counts",
        "",
        "| category | count |",
        "|---|---:|",
    ]
    for key in [
        "mismatched_cases",
        "successful_attacks",
        "leak_prone_cases",
        "false_positive_benign_cases",
        "utility_loss_benign_cases",
        "trade_off_cases",
        "recommended_analysis_cases",
    ]:
        lines.append(f"| {key} | {report.category_counts.get(key, 0)} |")

    def add_section(title: str, items: list[FailureCaseSummary]) -> None:
        lines.extend(["", f"## {title}", "", _markdown_table(items)])

    add_section("Mismatched Cases", report.mismatched_cases)
    add_section("Successful Attacks", report.successful_attacks)
    add_section("Leak-prone Cases", report.leak_prone_cases)
    add_section("False Positive Benign Cases", report.false_positive_benign_cases)
    add_section("Utility-loss Benign Cases", report.utility_loss_benign_cases)
    add_section("Trade-off Cases", report.trade_off_cases)
    add_section("Recommended Analysis Cases", report.recommended_analysis_cases)
    return "\n".join(lines) + "\n"


def build_failure_report(
    *,
    case_results_path: str | Path,
    summary_path: str | Path,
) -> FailureAnalysisReport:
    """Build structured failure analysis report from case-level results and summary."""
    case_path = Path(case_results_path)
    sum_path = Path(summary_path)
    case_payload = _load_json(case_path)
    summary_payload = _load_json(sum_path)
    if not isinstance(case_payload, list):
        raise ValueError("eval_case_results.json must be a list.")
    if not isinstance(summary_payload, dict):
        raise ValueError("eval_summary.json must be an object.")

    case_meta_lookup = _build_case_meta_lookup()
    mismatched_cases: list[FailureCaseSummary] = []
    successful_attacks: list[FailureCaseSummary] = []
    leak_prone_cases: list[FailureCaseSummary] = []
    false_positive_benign_cases: list[FailureCaseSummary] = []
    utility_loss_benign_cases: list[FailureCaseSummary] = []
    trade_off_cases: list[FailureCaseSummary] = []

    scored_cases: list[tuple[int, FailureCaseSummary]] = []

    for item in case_payload:
        if not isinstance(item, dict):
            continue

        is_attack = bool(item.get("is_attack", False))
        is_benign = bool(item.get("is_benign", False))
        mismatched = not bool(item.get("matched_expectation", False))
        successful_attack = is_attack and (not _is_intervention(item))
        leak_prone = bool(item.get("involves_sink", False)) and _is_completed(item) and _normalize_action(item.get("sink_action")) != "deny"
        false_positive = is_benign and _is_intervention(item)
        utility_loss = is_benign and ((not _is_completed(item)) or _is_degraded(item))
        trade_off = (is_benign and (false_positive or utility_loss)) or (is_attack and successful_attack)

        likely_module = _infer_module(item, case_meta_lookup)
        reason = _primary_failure_reason(
            mismatched=mismatched,
            successful_attack=successful_attack,
            leak_prone=leak_prone,
            false_positive=false_positive,
            utility_loss=utility_loss,
        )
        summary = _to_summary(
            item,
            primary_failure_reason=reason,
            likely_responsible_module=likely_module,
        )

        if mismatched:
            mismatched_cases.append(summary)
        if successful_attack:
            successful_attacks.append(summary)
        if leak_prone:
            leak_prone_cases.append(summary)
        if false_positive:
            false_positive_benign_cases.append(summary)
        if utility_loss:
            utility_loss_benign_cases.append(summary)
        if trade_off:
            trade_off_cases.append(summary)

        score = (
            (5 if successful_attack else 0)
            + (4 if leak_prone else 0)
            + (3 if false_positive else 0)
            + (3 if utility_loss else 0)
            + (2 if mismatched else 0)
        )
        if score > 0:
            scored_cases.append((score, summary))

    # Deduplicate recommended cases by case_id keeping highest score first.
    scored_cases.sort(key=lambda item: (-item[0], item[1].case_id))
    recommended: list[FailureCaseSummary] = []
    seen: set[str] = set()
    for _, summary in scored_cases:
        if summary.case_id in seen:
            continue
        recommended.append(summary)
        seen.add(summary.case_id)
        if len(recommended) >= 12:
            break

    report = FailureAnalysisReport(
        total_cases=len([item for item in case_payload if isinstance(item, dict)]),
        summary_snapshot={
            "match_rate": summary_payload.get("match_rate"),
            "attack_success_rate": summary_payload.get("attack_success_rate"),
            "leak_rate": summary_payload.get("leak_rate"),
            "false_positive_rate": summary_payload.get("false_positive_rate"),
            "utility_loss": summary_payload.get("utility_loss"),
        },
        category_counts={
            "mismatched_cases": len(mismatched_cases),
            "successful_attacks": len(successful_attacks),
            "leak_prone_cases": len(leak_prone_cases),
            "false_positive_benign_cases": len(false_positive_benign_cases),
            "utility_loss_benign_cases": len(utility_loss_benign_cases),
            "trade_off_cases": len(trade_off_cases),
            "recommended_analysis_cases": len(recommended),
        },
        mismatched_cases=mismatched_cases,
        successful_attacks=successful_attacks,
        leak_prone_cases=leak_prone_cases,
        false_positive_benign_cases=false_positive_benign_cases,
        utility_loss_benign_cases=utility_loss_benign_cases,
        trade_off_cases=trade_off_cases,
        recommended_analysis_cases=recommended,
    )
    return report


def export_failure_report(
    report: FailureAnalysisReport,
    *,
    case_results_path: str | Path,
    summary_path: str | Path,
    output_dir: str | Path,
    base_name: str = "failure_analysis_report",
) -> dict[str, Path]:
    """Export failure report into JSON + Markdown files."""
    case_path = Path(case_results_path)
    sum_path = Path(summary_path)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    json_path = out_dir / f"{base_name}.json"
    md_path = out_dir / f"{base_name}.md"

    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    md_path.write_text(
        _build_markdown(report, case_path, sum_path),
        encoding="utf-8",
    )
    return {"json": json_path, "markdown": md_path}


def build_and_export_failure_report(
    *,
    case_results_path: str | Path = DEFAULT_CASE_RESULTS_PATH,
    summary_path: str | Path = DEFAULT_SUMMARY_PATH,
    output_dir: str | Path | None = None,
    base_name: str = "failure_analysis_report",
) -> dict[str, object]:
    """Build and export failure analysis report for a given evaluation output set."""
    case_path = Path(case_results_path)
    sum_path = Path(summary_path)
    out_dir = Path(output_dir) if output_dir is not None else case_path.parent
    report = build_failure_report(case_results_path=case_path, summary_path=sum_path)
    exported = export_failure_report(
        report,
        case_results_path=case_path,
        summary_path=sum_path,
        output_dir=out_dir,
        base_name=base_name,
    )
    return {"report": report, "exported_paths": exported}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build failure analysis report from eval outputs.")
    parser.add_argument(
        "--case-results",
        default=str(DEFAULT_CASE_RESULTS_PATH),
        help="Path to eval_case_results.json",
    )
    parser.add_argument(
        "--summary",
        default=str(DEFAULT_SUMMARY_PATH),
        help="Path to eval_summary.json",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Output directory. Default: same directory as case-results file.",
    )
    parser.add_argument(
        "--base-name",
        default="failure_analysis_report",
        help="Output file base name.",
    )
    args = parser.parse_args()

    payload = build_and_export_failure_report(
        case_results_path=args.case_results,
        summary_path=args.summary,
        output_dir=args.output_dir,
        base_name=args.base_name,
    )
    print(f"total_cases: {payload['report'].total_cases}")
    print(f"json: {payload['exported_paths']['json']}")
    print(f"markdown: {payload['exported_paths']['markdown']}")


if __name__ == "__main__":
    main()
