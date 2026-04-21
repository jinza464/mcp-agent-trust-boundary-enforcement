"""Plot ablation comparison figures from exported summary report."""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib.pyplot as plt


DEFAULT_INPUT = Path("data/eval_outputs/ablation_summary_report.json")
DEFAULT_OUTPUT_DIR = Path("data/eval_outputs/figures")
ORDER = ["baseline", "no_trust_tagging", "no_metadata_validation", "no_sink_guard"]


def _load_rows(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("ablation_summary_report.json must contain a list of rows.")
    by_name = {str(row.get("configuration")): row for row in payload}
    return [by_name[name] for name in ORDER if name in by_name]


def _values(rows: list[dict], key: str) -> list[float]:
    return [float(row.get(key, 0.0)) for row in rows]


def _plot_grouped_bar(
    rows: list[dict],
    metrics: list[str],
    title: str,
    output_path: Path,
) -> None:
    labels = [row["configuration"] for row in rows]
    x = list(range(len(labels)))
    width = 0.22

    fig, ax = plt.subplots(figsize=(10, 5))
    for idx, metric in enumerate(metrics):
        offset = (idx - (len(metrics) - 1) / 2) * width
        ax.bar([i + offset for i in x], _values(rows, metric), width=width, label=metric)

    ax.set_title(title)
    ax.set_xlabel("Configuration")
    ax.set_ylabel("Rate")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=0)
    ax.set_ylim(0.0, 1.05)
    ax.legend()
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    fig.tight_layout()
    fig.savefig(output_path, dpi=200)
    plt.close(fig)


def plot_ablation(
    input_json: str | Path = DEFAULT_INPUT,
    output_dir: str | Path = DEFAULT_OUTPUT_DIR,
) -> dict[str, Path]:
    """Generate security and utility ablation comparison figures."""
    input_path = Path(input_json)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rows = _load_rows(input_path)
    if not rows:
        raise ValueError("No ablation rows found for expected configurations.")

    security_path = out_dir / "ablation_security_comparison.png"
    utility_path = out_dir / "ablation_utility_comparison.png"

    _plot_grouped_bar(
        rows,
        metrics=["match_rate", "attack_success_rate", "leak_rate"],
        title="Ablation Security Comparison",
        output_path=security_path,
    )
    _plot_grouped_bar(
        rows,
        metrics=["false_positive_rate", "utility_loss", "escalation_rate"],
        title="Ablation Utility Comparison",
        output_path=utility_path,
    )

    return {"security_figure": security_path, "utility_figure": utility_path}


def main() -> None:
    outputs = plot_ablation()
    print(f"security_figure: {outputs['security_figure']}")
    print(f"utility_figure: {outputs['utility_figure']}")


if __name__ == "__main__":
    main()
