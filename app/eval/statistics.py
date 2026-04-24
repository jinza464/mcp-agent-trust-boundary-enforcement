"""Lightweight statistical helpers for research evaluation reports."""

from __future__ import annotations

import random
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from app.eval.metrics import EvalSummary, summarize_results
from app.eval.runner import EvalCaseResult

ResultLike = EvalCaseResult | Mapping[str, Any]


def _as_float(value: object, *, default: float = 0.0) -> float:
    if value is None:
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _get_field(item: ResultLike, field: str, default: Any = None) -> Any:
    if isinstance(item, EvalCaseResult):
        return getattr(item, field, default)
    return item.get(field, default)


def _field_to_metric_value(item: ResultLike, metric_name: str) -> float:
    if metric_name in {"matched_expectation", "is_attack", "is_benign", "involves_sink"}:
        return 1.0 if bool(_get_field(item, metric_name, False)) else 0.0
    value = _get_field(item, metric_name)
    if hasattr(value, "value"):
        return _as_float(value.value)
    return _as_float(value)


def _case_id(item: ResultLike) -> str | None:
    raw = _get_field(item, "case_id")
    if raw is None:
        raw = _get_field(item, "id")
    if raw is None:
        return None
    text = str(raw).strip()
    return text or None


def _group_key(item: ResultLike, primary: str, fallback: str = "unknown") -> str:
    raw = _get_field(item, primary)
    if raw is None:
        raw = _get_field(item, fallback)
    text = str(raw).strip() if raw is not None else ""
    return text or "unknown"


def _summarize_group(items: list[ResultLike]) -> dict[str, object]:
    validated = [item for item in items if isinstance(item, EvalCaseResult)]
    summary: EvalSummary | None = summarize_results(validated) if len(validated) == len(items) else None
    matched = sum(1 for item in items if bool(_get_field(item, "matched_expectation", False)))
    attack = sum(1 for item in items if bool(_get_field(item, "is_attack", False)))
    benign = sum(1 for item in items if bool(_get_field(item, "is_benign", False)))
    sink = sum(1 for item in items if bool(_get_field(item, "involves_sink", False)))
    payload: dict[str, object] = {
        "total_cases": len(items),
        "matched_cases": matched,
        "match_rate": matched / len(items) if items else 0.0,
        "attack_cases": attack,
        "benign_cases": benign,
        "sink_cases": sink,
    }
    if summary is not None:
        payload["summary"] = summary.model_dump(mode="json")
    return payload


def bootstrap_confidence_interval(
    values: Iterable[float | int | bool],
    *,
    n_bootstrap: int = 1000,
    confidence: float = 0.95,
    seed: int = 42,
) -> dict[str, float | int]:
    """Return a deterministic bootstrap CI for the sample mean."""
    sample = [_as_float(value) for value in values]
    n = len(sample)
    if n == 0:
        return {"mean": 0.0, "lower": 0.0, "upper": 0.0, "confidence": confidence, "n": 0}
    if n_bootstrap <= 0:
        raise ValueError("n_bootstrap must be positive.")
    if not 0.0 < confidence < 1.0:
        raise ValueError("confidence must be in (0, 1).")

    mean = sum(sample) / n
    rng = random.Random(seed)
    boot_means: list[float] = []
    for _ in range(n_bootstrap):
        draw = [sample[rng.randrange(n)] for _ in range(n)]
        boot_means.append(sum(draw) / n)
    boot_means.sort()

    alpha = 1.0 - confidence
    lower_index = max(0, min(n_bootstrap - 1, int((alpha / 2.0) * n_bootstrap)))
    upper_index = max(0, min(n_bootstrap - 1, int((1.0 - alpha / 2.0) * n_bootstrap) - 1))
    return {
        "mean": mean,
        "lower": boot_means[lower_index],
        "upper": boot_means[upper_index],
        "confidence": confidence,
        "n": n,
    }


def compare_configs_paired(
    baseline_results: Sequence[ResultLike],
    candidate_results: Sequence[ResultLike],
    metric_name: str,
) -> dict[str, object]:
    """Compare two configs by aligning cases on case_id and measuring paired deltas."""
    baseline_by_id = {case_id: item for item in baseline_results if (case_id := _case_id(item)) is not None}
    candidate_by_id = {case_id: item for item in candidate_results if (case_id := _case_id(item)) is not None}
    paired_ids = sorted(set(baseline_by_id).intersection(candidate_by_id))

    deltas: list[float] = []
    wins = losses = ties = 0
    for case_id in paired_ids:
        baseline_value = _field_to_metric_value(baseline_by_id[case_id], metric_name)
        candidate_value = _field_to_metric_value(candidate_by_id[case_id], metric_name)
        delta = candidate_value - baseline_value
        deltas.append(delta)
        if delta > 0:
            wins += 1
        elif delta < 0:
            losses += 1
        else:
            ties += 1

    mean_delta = sum(deltas) / len(deltas) if deltas else 0.0
    return {
        "metric_name": metric_name,
        "paired_count": len(paired_ids),
        "baseline_only_count": len(set(baseline_by_id) - set(candidate_by_id)),
        "candidate_only_count": len(set(candidate_by_id) - set(baseline_by_id)),
        "delta": mean_delta,
        "mean_delta": mean_delta,
        "wins": wins,
        "losses": losses,
        "ties": ties,
        "case_deltas": [{"case_id": case_id, "delta": deltas[index]} for index, case_id in enumerate(paired_ids)],
    }


def group_metrics_by_family(results: Sequence[ResultLike]) -> dict[str, dict[str, object]]:
    """Group case-level metrics by case_family with attack_type fallback."""
    grouped: dict[str, list[ResultLike]] = {}
    for item in results:
        key = _group_key(item, "case_family", "attack_type")
        grouped.setdefault(key, []).append(item)
    return {key: _summarize_group(items) for key, items in sorted(grouped.items())}


def group_metrics_by_primary_module(results: Sequence[ResultLike]) -> dict[str, dict[str, object]]:
    """Group case-level outcomes by module attribution fields."""
    grouped: dict[str, list[ResultLike]] = {}
    for item in results:
        key = (
            _group_key(item, "likely_responsible_module")
            if _get_field(item, "likely_responsible_module") is not None
            else _group_key(item, "primary_target_module")
        )
        grouped.setdefault(key, []).append(item)
    return {key: _summarize_group(items) for key, items in sorted(grouped.items())}
