"""Failure analysis report builder for paper-oriented case-level diagnostics."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.core.models import DecisionAction
from app.eval.attack_cases import default_attack_cases
from app.eval.pattern_memory import PatternMemory
from app.eval.runtime_semantics import (
    CASE_PACK_VERSION,
    RUNTIME_SEMANTICS_VERSION,
    SEAL_TAG,
    ExecutionSemantics,
    compute_execution_semantics,
    validate_execution_artifact_consistency,
)


DEFAULT_CASE_RESULTS_PATH = Path("data/eval_outputs/baseline/eval_case_results.json")
DEFAULT_SUMMARY_PATH = Path("data/eval_outputs/baseline/eval_summary.json")


class SimilarPatternSummary(BaseModel):
    """Compact similar-pattern hit attached only when optional retrieval is enabled."""

    model_config = ConfigDict(extra="forbid")

    pattern_id: str
    source_case_id: str | None = None
    pattern_type: str
    score: float
    text_excerpt: str


class FailureCaseSummary(BaseModel):
    """Minimal structured failure/trade-off case summary for paper analysis."""

    model_config = ConfigDict(extra="forbid")

    case_id: str
    attack_type: str
    decision_action: str
    sink_action: str
    primary_failure_reason: str
    likely_responsible_module: str
    module_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    secondary_module_candidates: list[str] = Field(default_factory=list)

    # Backward-compatible fields kept for existing report consumers/tests.
    module_attribution_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    secondary_responsible_modules: list[str] = Field(default_factory=list)
    attribution_evidence: list[str] = Field(default_factory=list)
    expected_failure_mode: str = "unknown"
    similar_patterns: list[SimilarPatternSummary] | None = None


class FailureAnalysisReport(BaseModel):
    """Structured failure analysis payload exported to JSON + Markdown."""

    model_config = ConfigDict(extra="forbid")

    semantics_version: str = Field(default=RUNTIME_SEMANTICS_VERSION)
    case_pack_version: str = Field(default=CASE_PACK_VERSION)
    seal_tag: str = Field(default=SEAL_TAG)
    total_cases: int
    summary_snapshot: dict[str, object] = Field(default_factory=dict)
    artifact_consistency_warnings: list[str] = Field(default_factory=list)
    category_counts: dict[str, int] = Field(default_factory=dict)
    mismatched_cases: list[FailureCaseSummary] = Field(default_factory=list)
    successful_attacks: list[FailureCaseSummary] = Field(default_factory=list)
    leak_prone_cases: list[FailureCaseSummary] = Field(default_factory=list)
    false_positive_benign_cases: list[FailureCaseSummary] = Field(default_factory=list)
    utility_loss_benign_cases: list[FailureCaseSummary] = Field(default_factory=list)
    trade_off_cases: list[FailureCaseSummary] = Field(default_factory=list)
    recommended_analysis_cases: list[FailureCaseSummary] = Field(default_factory=list)
    module_responsibility_distribution: dict[str, int] = Field(default_factory=dict)
    module_confidence_by_module: dict[str, float] = Field(default_factory=dict)
    attribution_candidate_count: int = 0
    average_module_attribution_confidence: float = 0.0
    high_confidence_candidate_ratio: float = 0.0
    low_confidence_case_ids: list[str] = Field(default_factory=list)


KNOWN_MODULES: tuple[str, ...] = (
    "trust_tagger",
    "metadata_validator",
    "capability_policy",
    "decision_engine",
    "sink_guard",
)

MODULE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "trust_tagger": (
        "source trust",
        "untrusted",
        "semi-trusted",
        "server_notification",
        "external_document",
        "cached_metadata",
        "integrity_verified",
        "signature",
    ),
    "metadata_validator": (
        "schema",
        "metadata",
        "rollback",
        "origin relocation",
        "version drift",
        "contract drift",
        "description drift",
        "same provider",
    ),
    "capability_policy": (
        "capability",
        "hidden_invocation",
        "toolchain_delegation",
        "mcp_invoke",
        "network",
        "write",
        "execute",
        "permission",
    ),
    "decision_engine": (
        "authorization",
        "policy composition",
        "risk level",
        "decision gate",
        "escalate",
        "require_confirmation",
        "sandbox",
    ),
    "sink_guard": (
        "sink",
        "endpoint",
        "network_send",
        "payload",
        "fragment",
        "staged",
        "exfil",
        "redact",
        "allowlisted",
    ),
}


class ModuleAttribution(BaseModel):
    """Structured module attribution used by failure summaries."""

    model_config = ConfigDict(extra="forbid")

    likely_responsible_module: str
    module_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    secondary_module_candidates: list[str] = Field(default_factory=list)
    attribution_evidence: list[str] = Field(default_factory=list)
    expected_failure_mode: str = "unknown"


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_action(value: object) -> str:
    if value is None:
        return "none"
    text = str(value).strip().lower()
    return text or "none"


def _coerce_optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    return bool(value)


def _normalize_decision_action_for_semantics(value: object) -> DecisionAction:
    if isinstance(value, DecisionAction):
        return value
    normalized = _normalize_action(value)
    for action in DecisionAction:
        if normalized == action.value:
            return action
    return DecisionAction.ALLOW


def _normalize_sink_action_for_semantics(value: object) -> DecisionAction | None:
    if value is None:
        return None
    if isinstance(value, DecisionAction):
        return value
    normalized = _normalize_action(value)
    if normalized == "none":
        return None
    for action in DecisionAction:
        if normalized == action.value:
            return action
    return None


def _item_execution_semantics(item: dict[str, object]) -> ExecutionSemantics:
    semantics = compute_execution_semantics(
        _normalize_decision_action_for_semantics(item.get("decision_action")),
        _normalize_sink_action_for_semantics(item.get("sink_action")),
        runtime_executed=_coerce_optional_bool(item.get("executed")),
        runtime_completed_execution=_coerce_optional_bool(item.get("completed_execution")),
        runtime_execution_degraded=_coerce_optional_bool(item.get("execution_degraded")),
    )
    explicit_intervention = item.get("intervention_triggered")
    if explicit_intervention is not None:
        semantics = semantics.model_copy(update={"intervention_triggered": bool(explicit_intervention)})
    return semantics


def _build_case_meta_lookup() -> dict[str, dict[str, str]]:
    lookup: dict[str, dict[str, str]] = {}
    for case in default_attack_cases():
        lookup[case.id] = {
            "primary_target_module": case.primary_target_module,
            "expected_failure_mode": case.expected_failure_mode,
            "case_family": case.case_family,
        }
    return lookup


def _normalize_module_name(module: object) -> str:
    normalized = str(module or "").strip().lower()
    if normalized in KNOWN_MODULES:
        return normalized
    return "decision_engine"


def _add_score(
    *,
    module_scores: dict[str, float],
    module_evidence: dict[str, list[str]],
    module: str,
    score: float,
    evidence: str,
) -> None:
    normalized_module = _normalize_module_name(module)
    module_scores[normalized_module] += score
    if evidence not in module_evidence[normalized_module]:
        module_evidence[normalized_module].append(evidence)


def _collect_signal_text(item: dict[str, object]) -> str:
    parts: list[str] = []
    for key in ("attack_type", "decision_action", "sink_action", "primary_failure_reason"):
        value = item.get(key)
        if value is not None:
            parts.append(str(value))

    for key in ("findings", "reasons"):
        value = item.get(key)
        if isinstance(value, list):
            parts.extend(str(entry) for entry in value)
    return " ".join(parts).lower()


def _infer_module_attribution(
    item: dict[str, object],
    case_meta_lookup: dict[str, dict[str, str]],
) -> ModuleAttribution:
    module_scores: dict[str, float] = {module: 0.0 for module in KNOWN_MODULES}
    module_evidence: dict[str, list[str]] = {module: [] for module in KNOWN_MODULES}

    case_id = str(item.get("case_id", ""))
    case_meta = case_meta_lookup.get(case_id)
    expected_failure_mode = "unknown"
    meta_module = "decision_engine"
    if case_meta is not None:
        expected_failure_mode = case_meta.get("expected_failure_mode", "unknown")
        meta_module = _normalize_module_name(case_meta.get("primary_target_module"))
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module=meta_module,
            score=3.0,
            evidence=f"case_metadata_target:{meta_module}",
        )
        if expected_failure_mode and expected_failure_mode != "none":
            _add_score(
                module_scores=module_scores,
                module_evidence=module_evidence,
                module=meta_module,
                score=0.4,
                evidence=f"expected_failure_mode:{expected_failure_mode}",
            )

    sink_action = _normalize_action(item.get("sink_action"))
    decision_action = _normalize_action(item.get("decision_action"))
    if bool(item.get("involves_sink")):
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module="sink_guard",
            score=1.4,
            evidence="case_flag:involves_sink",
        )
    if sink_action != "none":
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module="sink_guard",
            score=0.8,
            evidence=f"sink_action:{sink_action}",
        )
    if decision_action in {"escalate", "require_confirmation", "sandbox", "redact"}:
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module="decision_engine",
            score=0.8,
            evidence=f"decision_action:{decision_action}",
        )

    signal_text = _collect_signal_text(item)
    for module, keywords in MODULE_KEYWORDS.items():
        hits = [token for token in keywords if token in signal_text]
        if not hits:
            continue
        capped_hits = hits[:4]
        score = min(2.0, 0.45 * len(hits))
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module=module,
            score=score,
            evidence=f"signals:{', '.join(capped_hits)}",
        )

    scored_modules = sorted(module_scores.items(), key=lambda entry: (-entry[1], entry[0]))
    top_module, top_score = scored_modules[0]
    if top_score <= 0:
        top_module = "decision_engine"
        top_score = 1.0
        _add_score(
            module_scores=module_scores,
            module_evidence=module_evidence,
            module=top_module,
            score=top_score,
            evidence="fallback:no_strong_signal",
        )
        scored_modules = sorted(module_scores.items(), key=lambda entry: (-entry[1], entry[0]))

    second_score = scored_modules[1][1] if len(scored_modules) > 1 else 0.0
    margin_ratio = ((top_score - second_score) / top_score) if top_score > 0 else 0.0
    has_competing_signal = second_score >= 1.2

    base_confidence = 0.35
    if case_meta is not None:
        base_confidence += 0.2 if top_module == meta_module else -0.05
    support_bonus = min(top_score / 5.0, 1.0) * 0.08
    ambiguity_penalty = 0.1 if has_competing_signal else 0.0
    evidence_bonus = min(len(module_evidence.get(top_module, [])), 3) * 0.015
    confidence = round(
        min(0.95, max(0.2, base_confidence + (0.2 * margin_ratio) + support_bonus + evidence_bonus - ambiguity_penalty)),
        3,
    )

    secondary_modules = [
        module
        for module, score in scored_modules[1:]
        if score > 0 and score >= max(1.2, top_score * 0.55)
    ][:2]
    evidence = module_evidence.get(top_module, [])[:3]
    if not evidence:
        evidence = ["fallback:no_direct_evidence"]

    return ModuleAttribution(
        likely_responsible_module=top_module,
        module_confidence=confidence,
        secondary_module_candidates=secondary_modules,
        attribution_evidence=evidence,
        expected_failure_mode=expected_failure_mode,
    )


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
    module_attribution: ModuleAttribution,
) -> FailureCaseSummary:
    return FailureCaseSummary(
        case_id=str(item.get("case_id", "")),
        attack_type=str(item.get("attack_type", "")),
        decision_action=_normalize_action(item.get("decision_action")),
        sink_action=_normalize_action(item.get("sink_action")),
        primary_failure_reason=primary_failure_reason,
        likely_responsible_module=module_attribution.likely_responsible_module,
        module_confidence=module_attribution.module_confidence,
        secondary_module_candidates=module_attribution.secondary_module_candidates,
        module_attribution_confidence=module_attribution.module_confidence,
        secondary_responsible_modules=module_attribution.secondary_module_candidates,
        attribution_evidence=module_attribution.attribution_evidence,
        expected_failure_mode=module_attribution.expected_failure_mode,
    )


def _similar_pattern_query(
    item: dict[str, object],
    summary: FailureCaseSummary,
) -> str:
    parts = [
        summary.attack_type,
        summary.primary_failure_reason,
        summary.likely_responsible_module,
        summary.expected_failure_mode,
    ]
    for key in ("findings", "reasons"):
        value = item.get(key)
        if isinstance(value, list):
            parts.extend(str(entry) for entry in value)
    return " ".join(part for part in parts if part)


def _find_similar_patterns(
    *,
    item: dict[str, object],
    summary: FailureCaseSummary,
    memory: PatternMemory,
    top_k: int,
) -> list[SimilarPatternSummary]:
    query = _similar_pattern_query(item, summary)
    if not query.strip():
        return []
    results = memory.search(query, top_k=top_k)
    return [
        SimilarPatternSummary(
            pattern_id=result.record.pattern_id,
            source_case_id=result.record.source_case_id,
            pattern_type=result.record.pattern_type,
            score=round(result.score, 6),
            text_excerpt=result.record.text[:160],
        )
        for result in results
    ]


def _markdown_table(items: list[FailureCaseSummary]) -> str:
    if not items:
        return "_None_\n"
    lines = [
        "| case_id | attack_type | decision_action | sink_action | primary_failure_reason | likely_responsible_module | attribution_confidence | expected_failure_mode | attribution_evidence |",
        "|---|---|---|---|---|---|---:|---|---|",
    ]
    for item in items:
        evidence = "; ".join(item.attribution_evidence[:2]) if item.attribution_evidence else "none"
        lines.append(
            f"| {item.case_id} | {item.attack_type} | {item.decision_action} | {item.sink_action} | "
            f"{item.primary_failure_reason} | {item.likely_responsible_module} | "
            f"{item.module_attribution_confidence:.3f} | {item.expected_failure_mode} | {evidence} |"
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

    lines.extend(
        [
            "",
            "## Module Attribution Snapshot",
            "",
            f"- attribution_candidate_count: {report.attribution_candidate_count}",
            f"- average_module_attribution_confidence: {report.average_module_attribution_confidence:.3f}",
            f"- high_confidence_candidate_ratio: {report.high_confidence_candidate_ratio:.3f}",
            f"- low_confidence_case_ids: {', '.join(report.low_confidence_case_ids) if report.low_confidence_case_ids else 'none'}",
            "",
            "| module | case_count | avg_confidence |",
            "|---|---:|---:|",
        ]
    )
    for module, count in report.module_responsibility_distribution.items():
        avg_confidence = report.module_confidence_by_module.get(module, 0.0)
        lines.append(f"| {module} | {count} | {avg_confidence:.3f} |")

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
    include_similar_cases: bool = False,
    similar_top_k: int = 3,
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
    artifact_consistency_warnings: list[str] = []

    scored_cases: list[tuple[int, FailureCaseSummary]] = []
    analysis_candidates: dict[str, FailureCaseSummary] = {}
    pattern_memory = PatternMemory.from_attack_cases(default_attack_cases()) if include_similar_cases else None

    for item in case_payload:
        if not isinstance(item, dict):
            continue

        artifact_consistency_warnings.extend(validate_execution_artifact_consistency(item))
        semantics: ExecutionSemantics = _item_execution_semantics(item)
        is_attack = bool(item.get("is_attack", False))
        is_benign = bool(item.get("is_benign", False))
        mismatched = not bool(item.get("matched_expectation", False))
        successful_attack = is_attack and (not semantics.intervention_triggered)
        # Leak semantics use the same unified source as metrics.py.
        leak_prone = bool(item.get("involves_sink", False)) and semantics.leak_possible
        false_positive = is_benign and semantics.intervention_triggered
        utility_loss = is_benign and ((not semantics.completed_execution) or semantics.execution_degraded)
        trade_off = (is_benign and (false_positive or utility_loss)) or (is_attack and successful_attack)

        module_attribution = _infer_module_attribution(item, case_meta_lookup)
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
            module_attribution=module_attribution,
        )
        if pattern_memory is not None:
            summary = summary.model_copy(
                update={
                    "similar_patterns": _find_similar_patterns(
                        item=item,
                        summary=summary,
                        memory=pattern_memory,
                        top_k=similar_top_k,
                    )
                }
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
            current = analysis_candidates.get(summary.case_id)
            if current is None or summary.module_attribution_confidence > current.module_attribution_confidence:
                analysis_candidates[summary.case_id] = summary

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

    candidate_items = list(analysis_candidates.values())
    module_responsibility_distribution: dict[str, int] = {}
    module_confidence_accumulator: dict[str, list[float]] = {}
    low_confidence_case_ids: list[str] = []
    for item in candidate_items:
        module = item.likely_responsible_module
        module_responsibility_distribution[module] = module_responsibility_distribution.get(module, 0) + 1
        module_confidence_accumulator.setdefault(module, []).append(item.module_attribution_confidence)
        if item.module_attribution_confidence < 0.5:
            low_confidence_case_ids.append(item.case_id)

    module_confidence_by_module = {
        module: round(sum(values) / len(values), 3)
        for module, values in sorted(module_confidence_accumulator.items())
    }
    candidate_count = len(candidate_items)
    average_confidence = (
        round(sum(item.module_attribution_confidence for item in candidate_items) / candidate_count, 3)
        if candidate_count > 0
        else 0.0
    )
    high_confidence_candidate_ratio = (
        round(
            len([item for item in candidate_items if item.module_attribution_confidence >= 0.75]) / candidate_count,
            3,
        )
        if candidate_count > 0
        else 0.0
    )

    report = FailureAnalysisReport(
        total_cases=len([item for item in case_payload if isinstance(item, dict)]),
        summary_snapshot={
            "semantics_version": summary_payload.get("semantics_version"),
            "case_pack_version": summary_payload.get("case_pack_version"),
            "seal_tag": summary_payload.get("seal_tag"),
            "match_rate": summary_payload.get("match_rate"),
            "attack_success_rate": summary_payload.get("attack_success_rate"),
            "leak_rate": summary_payload.get("leak_rate"),
            "false_positive_rate": summary_payload.get("false_positive_rate"),
            "utility_loss": summary_payload.get("utility_loss"),
        },
        artifact_consistency_warnings=artifact_consistency_warnings,
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
        module_responsibility_distribution=dict(sorted(module_responsibility_distribution.items())),
        module_confidence_by_module=module_confidence_by_module,
        attribution_candidate_count=candidate_count,
        average_module_attribution_confidence=average_confidence,
        high_confidence_candidate_ratio=high_confidence_candidate_ratio,
        low_confidence_case_ids=sorted(low_confidence_case_ids),
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
        json.dumps(report.model_dump(mode="json", exclude_none=True), ensure_ascii=False, indent=2),
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
    include_similar_cases: bool = False,
    similar_top_k: int = 3,
) -> dict[str, object]:
    """Build and export failure analysis report for a given evaluation output set."""
    case_path = Path(case_results_path)
    sum_path = Path(summary_path)
    out_dir = Path(output_dir) if output_dir is not None else case_path.parent
    report = build_failure_report(
        case_results_path=case_path,
        summary_path=sum_path,
        include_similar_cases=include_similar_cases,
        similar_top_k=similar_top_k,
    )
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
