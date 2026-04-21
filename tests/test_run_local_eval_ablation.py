"""Tests for local eval entrypoint with ablation presets."""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from app.eval.run_local_eval import run_local_eval


def test_run_local_eval_baseline_and_ablations() -> None:
    root = Path("data") / "test_outputs" / f"ablation-run-{uuid4().hex}"
    root.mkdir(parents=True, exist_ok=True)
    try:
        baseline = run_local_eval(output_dir=root / "baseline", ablation_name="baseline")
        no_tt = run_local_eval(output_dir=root / "no_trust_tagging", ablation_name="no_trust_tagging")
        no_mv = run_local_eval(output_dir=root / "no_metadata_validation", ablation_name="no_metadata_validation")
        no_sg = run_local_eval(output_dir=root / "no_sink_guard", ablation_name="no_sink_guard")

        assert baseline["summary"].total_cases > 0
        assert baseline["exported_paths"]["cases"].exists()
        assert baseline["exported_paths"]["summary"].exists()

        assert no_tt["ablation_config"].disable_trust_tagging is True
        assert no_mv["ablation_config"].disable_metadata_validation is True
        assert no_sg["ablation_config"].disable_sink_guard is True
    finally:
        if root.exists():
            for child in root.glob("*"):
                if child.is_dir():
                    for item in child.glob("*"):
                        item.unlink()
                    child.rmdir()
            root.rmdir()
