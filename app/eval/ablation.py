"""Ablation helpers for trust-boundary enforcement evaluation."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from app.eval.attack_cases import EvalAttackCase, default_attack_cases
from app.eval.metrics import EvalSummary, summarize_results
from app.eval.runner import AblationConfig, EvalCaseResult, run_all_cases


class AblationRunOutput(BaseModel):
    """Unified output for ablation runs: case-level results plus summary metrics."""

    model_config = ConfigDict(extra="forbid")

    config: AblationConfig = Field(..., description="Applied ablation switches.")
    case_results: list[EvalCaseResult] = Field(default_factory=list, description="Case-level evaluation results.")
    summary: EvalSummary = Field(..., description="Summary metrics for the run.")


def run_ablation(
    cases: list[EvalAttackCase] | None = None,
    config: AblationConfig | dict | None = None,
) -> AblationRunOutput:
    """Run evaluation under one ablation config and return results+summary."""
    cfg = config if isinstance(config, AblationConfig) else AblationConfig.model_validate(config or {})
    selected = cases or default_attack_cases()
    case_results = run_all_cases(selected, ablation_config=cfg)
    summary = summarize_results(case_results)
    return AblationRunOutput(config=cfg, case_results=case_results, summary=summary)
