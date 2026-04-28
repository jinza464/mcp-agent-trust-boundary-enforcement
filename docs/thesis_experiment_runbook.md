# Thesis Experiment Runbook

## 1. 实验版本说明

本项目当前存在两个需要明确区分的实验版本：

- `research-prototype-v1.0`：thesis baseline。论文主实验和基线指标应优先以该封板版本为准。
- `research-prototype-v1.1-rc1`：增强分析版本。该版本加入 artifact consistency、audit 可靠性、lineage-aware sink context、可选 statistics / PatternMemory 分析产物，以及 non-tools MCP feature guard smoke layer。

v1.1-rc1 可以用于补充分析、扩展实验说明和工程可靠性展示，但不应在没有说明的情况下替代 v1.0 thesis baseline。

## 2. 环境准备

建议使用 Python 3.12。

在正式实验前，请确认当前工作区处于预期 tag 或分支，并安装项目依赖。示例：

```powershell
python --version
python -m pip install -r requirements.txt
```

如果项目使用其他依赖管理方式，请以仓库当前配置为准。

正式运行前必须先执行测试：

```powershell
python -m pytest
```

如果全量测试失败，不应继续生成正式论文实验 artifact。

## 3. 正式实验运行命令

一键运行四组 thesis baseline 实验：

```powershell
python scripts/run_thesis_experiments.py
```

默认输出目录：

```text
results/thesis_experiment_v1_final/
```

四组配置分别输出到：

```text
results/thesis_experiment_v1_final/baseline/
results/thesis_experiment_v1_final/no_trust_tagging/
results/thesis_experiment_v1_final/no_metadata_validation/
results/thesis_experiment_v1_final/no_sink_guard/
```

如需指定输出目录：

```powershell
python scripts/run_thesis_experiments.py --output-root results/thesis_experiment_v1_final
```

如需同时生成 failure analysis artifact：

```powershell
python scripts/run_thesis_experiments.py --emit-failure-report
```

## 4. 输出文件说明

每个配置目录下会包含：

- `eval_case_results.json`：case-level 评测结果。
- `eval_summary.json`：summary-level 指标。

实验根目录会包含：

- `experiment_manifest.json`：正式实验 manifest，记录：
  - git commit hash；
  - 当前分支；
  - HEAD tag；
  - dirty status；
  - Python 版本；
  - Python executable；
  - run timestamp；
  - 每组配置的输出路径和 summary snapshot。

注意：manifest 只记录运行环境和产物位置，不改变评测逻辑。

## 5. 汇总论文结果表格

生成论文可复制表格：

```powershell
python scripts/summarize_thesis_results.py
```

默认读取：

```text
results/thesis_experiment_v1_final/
```

默认输出：

```text
results/thesis_experiment_v1_final/reports/thesis_metrics_table.csv
results/thesis_experiment_v1_final/reports/thesis_metrics_table.md
results/thesis_experiment_v1_final/reports/ablation_comparison.md
```

`thesis_metrics_table.md` 可直接复制到论文草稿或实验记录中。核心列包括：

- `configuration`
- `match_rate`
- `attack_success_rate`
- `leak_rate`
- `false_positive_rate`
- `utility_loss`
- `execution_completion_rate`
- `intervention_rate`
- `hard_block_rate`
- `confirmation_rate`

`ablation_comparison.md` 给出相对 baseline 的 delta。该脚本只读取已有 `eval_summary.json` 字段，不从 case-level 结果重新计算业务指标。

如果某个字段缺失，脚本会：

- 在表格中标记为 `MISSING`；
- 在 Markdown warning 区域写出缺失字段；
- 在 stderr 输出 warning。

脚本不会静默填 `0`。

## 6. 注意事项

正式实验期间请遵守以下规则：

1. 不要修改策略逻辑。
2. 不要修改 `attack_cases` 的 `expected_action` / `expected_risk`。
3. 不要修改 metrics 口径。
4. 不要混用不同 tag 或不同分支生成的 artifact。
5. 每次正式实验前先运行 `python -m pytest`。
6. 如果工作区 dirty，必须在 `experiment_manifest.json` 中保留该事实，并在论文实验记录中说明。
7. v1.0 和 v1.1-rc1 的 artifact 应分目录保存，不要覆盖或混用。

## 7. 推荐正式流程

建议按以下顺序执行：

```powershell
git status --short
git tag --points-at HEAD
python -m pytest
python scripts/run_thesis_experiments.py
python scripts/summarize_thesis_results.py
```

完成后检查：

```powershell
Get-Content results/thesis_experiment_v1_final/experiment_manifest.json
Get-Content results/thesis_experiment_v1_final/reports/thesis_metrics_table.md
Get-Content results/thesis_experiment_v1_final/reports/ablation_comparison.md
```

如果需要将结果用于论文，请记录：

- 使用的 git commit；
- 使用的 tag；
- pytest 是否通过；
- 实验运行时间；
- 是否存在 dirty workspace。
