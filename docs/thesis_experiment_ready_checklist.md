# Thesis Experiment Ready Checklist

本文档用于封存当前 thesis experiment baseline 的实验准备状态。后续如需继续开发新功能，应单独开分支，避免直接污染当前封板版本。

## 1. 代码封板状态

- 全量 `pytest` 已通过。
- 当前版本适合作为 thesis experiment baseline。
- 当前版本已经完成数据边界、协议对象、策略解释、runtime/eval 语义、平台服务层和最终缺失拼图的最小闭环。
- 后续新增功能应单独开分支，不应直接污染封板版本。
- 论文实验结果应基于当前固定 case pack、统一 metrics 口径和已通过测试的代码状态生成。

## 2. 核心模块完成情况

| 阶段 | 模块 | 状态 |
|---|---|---|
| 第一阶段 | 数据边界收紧 | 完成 |
| 第二阶段 | MCP 协议对象化 | 完成 |
| 第三阶段 | 策略证据树与规则图 | 完成 |
| 第四阶段 | runtime/eval 语义统一 | 完成 |
| 第五阶段 | 平台层与服务层收口 | 完成 |
| 最终阶段 | 缺失拼图补齐 | 完成 |

## 3. 必跑测试命令

```powershell
pytest
pytest tests/test_eval_metrics.py
pytest tests/test_eval_runner.py
pytest tests/test_api_platform.py
pytest tests/test_tool_registry.py
pytest tests/test_attack_cases.py
pytest tests/test_eval_ablation.py
pytest tests/test_agent_client.py
pytest tests/test_sink_guard.py
pytest tests/test_protocol_models.py
pytest tests/test_lineage.py
pytest tests/test_eval_statistics.py
pytest tests/test_pattern_memory.py
pytest tests/test_concurrency.py
```

## 4. 实验产物建议核验

- baseline summary 与 case results 已生成并可读。
- no_trust_tagging、no_metadata_validation、no_sink_guard ablation summary 已生成并可比较。
- ablation summary report JSON/CSV 已生成。
- failure report JSON/Markdown 已生成。
- ablation security/utility figures 已生成。
- 文档 `docs/experiment_scope.md` 已明确实验能力边界。

## 5. 封板后开发约束

- 不直接修改当前封板分支上的 expected action/risk。
- 不在未重新跑完整 pytest 的情况下修改 metrics 口径。
- 不在未更新实验范围说明的情况下把预留能力写成主实验能力。
- 不在当前封板版本中引入真实 MCP transport、真实并发调度或重型外部依赖。

## 6. 论文实验使用建议

- 主实验表格使用 `summarize_results(...)` 和 ablation report 导出的指标。
- failure analysis 使用 failure report 的 case-level 证据和 module confidence。
- 系统实现章节可以描述 protocol models、lineage graph、pattern memory 和 runtime governance，但应标明哪些是扩展能力。
- limitations/future work 应明确真实 MCP transport、embedding retrieval、AnyIO structured concurrency、更大 adaptive benchmark 和更强统计显著性检验仍是后续工作。
