"""Run the sealed thesis experiment configurations.

This script is intentionally a thin orchestration layer over
``app.eval.run_local_eval.run_local_eval``. It does not redefine metrics,
case expectations, or ablation behavior.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.eval.run_local_eval import run_local_eval  # noqa: E402


DEFAULT_OUTPUT_ROOT = REPO_ROOT / "results" / "thesis_experiment_v1_final"
CONFIGURATIONS: tuple[str, ...] = (
    "baseline",
    "no_trust_tagging",
    "no_metadata_validation",
    "no_sink_guard",
)


def _run_git(args: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def _git_metadata() -> dict[str, Any]:
    tags_raw = _run_git(["tag", "--points-at", "HEAD"]) or ""
    status_raw = _run_git(["status", "--short"]) or ""
    return {
        "commit_hash": _run_git(["rev-parse", "HEAD"]),
        "commit_hash_short": _run_git(["rev-parse", "--short", "HEAD"]),
        "branch": _run_git(["branch", "--show-current"]),
        "tags_at_head": [line for line in tags_raw.splitlines() if line],
        "describe": _run_git(["describe", "--tags", "--always", "--dirty"]),
        "dirty": bool(status_raw.strip()),
        "status_short": status_raw.splitlines(),
    }


def _path_payload(paths: dict[str, Path]) -> dict[str, str]:
    return {key: str(path) for key, path in paths.items()}


def _summary_payload(summary: object) -> dict[str, object]:
    if hasattr(summary, "model_dump"):
        return summary.model_dump(mode="json")
    if isinstance(summary, dict):
        return dict(summary)
    return {"summary_repr": repr(summary)}


def run_experiments(
    *,
    output_root: Path = DEFAULT_OUTPUT_ROOT,
    emit_failure_report: bool = False,
) -> dict[str, object]:
    """Run all thesis baseline configurations and write an experiment manifest."""
    output_root.mkdir(parents=True, exist_ok=True)
    started_at = datetime.now(UTC)
    manifest: dict[str, object] = {
        "experiment_name": "thesis_experiment_v1_final",
        "started_at": started_at.isoformat(),
        "python_version": sys.version,
        "python_executable": sys.executable,
        "repository_root": str(REPO_ROOT),
        "output_root": str(output_root),
        "git": _git_metadata(),
        "configurations": list(CONFIGURATIONS),
        "emit_failure_report": emit_failure_report,
        "runs": {},
    }

    runs: dict[str, object] = {}
    for configuration in CONFIGURATIONS:
        config_output_dir = output_root / configuration
        payload = run_local_eval(
            output_dir=config_output_dir,
            ablation_name=configuration,
            emit_failure_report=emit_failure_report,
        )
        run_record: dict[str, object] = {
            "configuration": configuration,
            "output_dir": str(config_output_dir),
            "summary": _summary_payload(payload["summary"]),
            "exported_paths": _path_payload(payload["exported_paths"]),
            "runtime_semantics_snapshot": payload.get("runtime_semantics_snapshot", {}),
        }
        if "failure_report_paths" in payload:
            run_record["failure_report_paths"] = _path_payload(payload["failure_report_paths"])
        runs[configuration] = run_record

    manifest["runs"] = runs
    manifest["completed_at"] = datetime.now(UTC).isoformat()
    manifest_path = output_root / "experiment_manifest.json"
    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Run sealed thesis experiment configurations.")
    parser.add_argument(
        "--output-root",
        default=str(DEFAULT_OUTPUT_ROOT),
        help="Output root for experiment artifacts.",
    )
    parser.add_argument(
        "--emit-failure-report",
        action="store_true",
        help="Also export failure analysis artifacts for each configuration.",
    )
    args = parser.parse_args()

    manifest = run_experiments(
        output_root=Path(args.output_root),
        emit_failure_report=args.emit_failure_report,
    )
    print(f"experiment_manifest: {manifest['manifest_path']}")
    for configuration, run in manifest["runs"].items():
        summary = run["summary"]
        print(
            f"{configuration}: "
            f"match_rate={summary.get('match_rate')} "
            f"attack_success_rate={summary.get('attack_success_rate')} "
            f"leak_rate={summary.get('leak_rate')}"
        )


if __name__ == "__main__":
    main()
