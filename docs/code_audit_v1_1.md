# Code Audit v1.1 Candidate Report

## 1. Executive Summary

- 当前 `research-prototype-v1.0` 适合作为 thesis experiment baseline；已完成数据边界、MCP 协议对象化、策略证据树、runtime/eval 语义统一、平台服务层收口和最终缺失拼图补齐。
- 用户确认全量 `pytest` 已通过：`140 passed`。本次审计未重新运行测试，只做只读源码与文档核验。
- 主实验链路已经相对稳定，尤其是 `runner -> runtime_semantics -> metrics/failure_report -> ablation_report` 的语义链条已基本统一。
- 当前最需要保护的是 benchmark 可复现性：不要在 v1.0 上改 `attack_cases` expected values、metrics 口径、decision priority、sink guard 核心行为。
- v1.1 最值得增强的方向不是改策略结果，而是加强 artifact consistency、audit flush 可靠性、lineage graph 接入、统计报告接入和扩展能力边界文档。
- 最终阶段新增的 `RequestLineageGraph`、`PatternMemory`、`statistics.py`、`RuntimeExecutionGovernance`、Sampling/Roots/Elicitation contexts 属于“已实现最小能力”，但多数尚未深度进入主实验指标链路。
- 论文写作时必须区分“已参与实验指标”和“系统扩展能力展示”，尤其不能声称 PatternMemory、真实 cancellation scope、真实 MCP transport 已参与主实验。
- 建议保留 `research-prototype-v1.0` 作为论文实验封板版本；后续改动应创建 `v1.1` 分支，不应污染封板 tag。

## 2. Audit Scope

本次审计覆盖：

- Eval 语义链路：
  - `app/eval/runtime_semantics.py`
  - `app/eval/runner.py`
  - `app/eval/metrics.py`
  - `app/eval/failure_report.py`
  - `app/eval/run_local_eval.py`
  - `app/eval/ablation_report.py`

- Attack case 与 benchmark 基础设施：
  - `app/eval/attack_cases.py`
  - `tests/test_attack_cases.py`
  - `tests/test_eval_runner.py`
  - `tests/test_eval_ablation.py`

- MCP protocol object 与 runtime 接入：
  - `app/mcp/protocol_models.py`
  - `app/mcp/agent_client.py`
  - `app/mcp/lineage.py`
  - `app/registry/tool_registry.py`
  - `app/services/runtime_service.py`

- Policy / decision / sink：
  - `app/decision/decision_engine.py`
  - `app/policy/capability_policy.py`
  - `app/tagging/trust_tagger.py`
  - `app/sink/sink_guard.py`

- 扩展模块：
  - `app/eval/pattern_memory.py`
  - `app/eval/statistics.py`
  - `app/core/concurrency.py`

- Platform / service / audit：
  - `main.py`
  - `app/api/routes/*.py`
  - `app/api/routes/dependencies.py`
  - `app/services/runtime_service.py`
  - `app/services/evaluation_service.py`
  - `app/services/report_service.py`
  - `app/services/audit_service.py`

- 文档：
  - `README.md`
  - `docs/experiment_scope.md`
  - `docs/thesis_experiment_ready_checklist.md`
  - `results/thesis_experiment_v1/SEAL_INFO.md`

本次不覆盖：

- 不重新设计策略逻辑。
- 不修改任何代码或文档。
- 不重新跑 benchmark 或 pytest。
- 不复核所有实验输出文件的数值正确性。
- 不验证真实 MCP transport，因为当前项目仍是本地 mock/runtime prototype。

## 3. P0: Must Review Before Any v1.1 Code Change

### P0-1: Eval artifact semantic consistency 需要先建立一致性保护

- Location:
  - `app/eval/runner.py`
  - `app/eval/metrics.py`
  - `app/eval/failure_report.py`
  - `app/eval/runtime_semantics.py`

- Finding:
  - 当前 `runner.py` 已通过 `compute_execution_semantics(...)` 生成 `completed_execution`、`execution_degraded`、`intervention_triggered` 等字段。
  - `metrics.py` 和 `failure_report.py` 也通过统一语义层重算或读取语义字段。
  - 但当它们消费历史 JSON artifact 或手工构造结果时，仍可能信任已有的 persisted runtime fields。若旧 artifact 与当前 action/sink semantics 不一致，可能造成 summary 与 failure report 解释不完全一致。

- Risk:
  - 论文指标表与 failure analysis 可能在使用旧产物时出现语义漂移。
  - 风险不是当前测试失败，而是 v1.1 新增实验时混用旧 artifact 导致解释不一致。

- Why not change in v1.0:
  - 当前封板产物已与现有测试通过状态一致。
  - 直接改变 artifact 读取或强制校验可能改变现有导出行为，影响 thesis baseline 可复现性。

- Recommended v1.1 action:
  - 增加轻量 `semantics_version` 或 artifact consistency validator。
  - 当 persisted `completed_execution` / `execution_degraded` / `intervention_triggered` 与 action-derived semantics 冲突时，给出 warning 或 fail-fast。
  - 保持 v1.0 结果只读，不回写历史 artifact。

- Regression tests:
  - `pytest tests/test_eval_runner.py`
  - `pytest tests/test_eval_metrics.py`
  - `pytest tests/test_eval_failure_report.py`
  - `pytest tests/test_run_local_eval_ablation.py`
  - `pytest tests/test_eval_ablation.py`

- Thesis impact:
  - thesis baseline 可继续使用。
  - 论文中应说明当前指标来自统一 runtime/eval semantics；若使用历史 JSON，应保证它们来自同一封板版本。

### P0-2: AuditService flush 失败时存在 buffer 丢失风险

- Location:
  - `app/services/audit_service.py`
  - `AuditService.flush()`
  - `AuditService._flush_batch(...)`

- Finding:
  - 当前 `flush()` 逻辑先把 `self._buffer` 置空，再调用 `_flush_batch(batch)` 写入 JSONL。
  - 如果写盘失败，内存 buffer 已经清空，调用方可能丢失尚未持久化的审计事件。

- Risk:
  - 不影响当前 benchmark 指标。
  - 但会影响平台层审计可靠性，尤其是后续 v1.1 若把 audit artifact 用于实验追溯或答辩展示，该问题会变得重要。

- Why not change in v1.0:
  - 当前 thesis baseline 已通过测试，audit JSONL 不是主实验指标来源。
  - 修改 flush 行为属于平台可靠性增强，不应在封板 tag 上改。

- Recommended v1.1 action:
  - 调整为“写入成功后再清空 buffer”。
  - 或使用 local batch copy，失败时恢复 buffer。
  - 增加 flush failure 单元测试，模拟 `_flush_batch` 抛错后 buffer 仍保留。

- Regression tests:
  - `pytest tests/test_api_platform.py`
  - `pytest tests/test_api_governance.py`
  - `pytest tests/test_eval_failure_report.py`
  - 新增 `tests/test_audit_service.py`

- Thesis impact:
  - 当前论文主指标无影响。
  - 若论文系统实现章节提到 audit buffering，应表述为“轻量 JSONL buffering prototype”，不要夸大为强可靠审计队列。

### P0-3: MCP 非 tools feature 已建模但尚未进入真实执行路径

- Location:
  - `app/mcp/protocol_models.py`
  - `app/mcp/agent_client.py`
  - `app/mcp/lineage.py`
  - `app/services/runtime_service.py`

- Finding:
  - `McpRequestEnvelope` 已真实进入 runtime 主路径。
  - `handle_query(...)` 会把 legacy query 转为 `feature="tools"` 的 `McpRequestEnvelope`。
  - `handle_mcp_request(...)` 已是协议化入口。
  - 非 tools feature 当前主要是 recognized but not executed，final status 可以进入 `not_executed_feature_scope`。
  - `McpResponseEnvelope`、`SamplingRequestContext`、`RootsExposureContext`、`ElicitationContext` 已存在，但主要是协议对象层和扩展能力，不是主 benchmark 执行路径。

- Risk:
  - 论文中容易把“协议对象已补齐”写成“完整 MCP feature runtime 已实现”。
  - v1.1 若直接加入 sampling/roots/elicitation 执行语义，可能改变现有 runtime 行为和测试边界。

- Why not change in v1.0:
  - 当前 benchmark 与 case pack 主要围绕 tools feature。
  - 非 tools feature 深度接入属于新实验范围，应单独分支推进。

- Recommended v1.1 action:
  - 先增加 protocol feature coverage tests 和 docs。
  - 再按 feature 独立接入 sampling guard、roots exposure guard、elicitation safety。
  - 不要一次性修改主 decision/sink 逻辑。

- Regression tests:
  - `pytest tests/test_protocol_models.py`
  - `pytest tests/test_agent_client.py`
  - `pytest tests/test_api_platform.py`
  - 新增非 tools feature runtime tests。

- Thesis impact:
  - 当前可写为“协议对象化 runtime 入口已实现，tools feature 已接入主链路”。
  - Sampling/Roots/Elicitation 应写成“已实现协议上下文模型和后续扩展能力”。

### P0-4: Adaptive / gray-zone case 语义需要人工复核，但不应直接改 expected values

- Location:
  - `app/eval/attack_cases.py`
  - `tests/test_attack_cases.py`
  - `tests/test_eval_runner.py`

- Finding:
  - 当前 case pack 为 53 cases。
  - 已有 family 分布包括 `metadata_drift_security`、`gray_zone_benign`、`sink_exfiltration_security`、`benign_baseline`、`adaptive_adversary`、`core_attack`。
  - `build_case_lookup()` 和 `summarize_case_families()` 已存在。
  - 需要人工复核的是：部分 `adaptive_adversary` case 是否真正体现 adaptive attacker，还是普通攻击场景的命名强化。

- Risk:
  - 风险主要在论文表述。
  - 如果夸大 adaptive adversary 覆盖，会削弱实验可信度。
  - 如果直接改 expected_action / expected_risk，会破坏 thesis baseline。

- Why not change in v1.0:
  - v1.0 已封板，case id、expected action/risk、metrics 都应保持稳定。
  - 任何 case expectation 变更都应属于 v1.1 或新 benchmark 分支。

- Recommended v1.1 action:
  - 只做人工标注复核和论文措辞修正。
  - 若确需新增 adaptive cases，应追加新 case id，不重排旧 id，不改旧 expected values。
  - 为 `summarize_case_families(detailed=True)` 产物增加论文附录说明。

- Regression tests:
  - `pytest tests/test_attack_cases.py`
  - `pytest tests/test_eval_runner.py`
  - `pytest tests/test_eval_ablation.py`

- Thesis impact:
  - 当前可以写 gray-zone benign 和 sink-sensitive coverage。
  - adaptive attacker 应谨慎写为“initial adaptive-style cases”或“adaptive-inspired cases”，不要写成完整 adaptive benchmark。

## 4. P1: Recommended v1.1 Enhancements

### P1-1: 将 `inspect_sink_with_context(...)` 接入 agent runtime 主路径

- Location:
  - `app/mcp/agent_client.py`
  - `app/sink/sink_guard.py`

- Current state:
  - `sink_guard.py` 已实现 `SinkDecisionContext` 和 `inspect_sink_with_context(...)`。
  - legacy `inspect_sink(...)` 内部会构造最小 context。
  - `agent_client.evaluate_sink(...)` 当前仍主要调用 `inspect_sink(...)`，没有充分传入 `request_lineage`、`capability_result`、`upstream_trust_label`。

- Recommended enhancement:
  - 在 `agent_client.evaluate_sink(...)` 中构造 `SinkDecisionContext`。
  - 传入 `request_lineage`、policy decision action、capability result、trust label 和 sink metadata。
  - 保持旧 `inspect_sink(...)` 兼容入口。

- Expected benefit:
  - 让 lineage-aware sink decision 真正参与主 runtime。
  - 支撑论文中更强的“lineage-aware sink enforcement”表述。

- Implementation risk:
  - 中等。可能改变 sink_action、leak_possible、confirmation 行为。
  - 必须在 v1.1 分支单独评估对 benchmark 的影响。

- Regression tests:
  - `pytest tests/test_sink_guard.py`
  - `pytest tests/test_agent_client.py`
  - `pytest tests/test_eval_runner.py`
  - `pytest tests/test_eval_metrics.py`

- Thesis impact:
  - 不影响 v1.0 thesis baseline。
  - v1.1 可作为增强实验或 additional study。

### P1-2: 将 `RequestLineageGraph` 接入 trace / audit / failure report

- Location:
  - `app/mcp/lineage.py`
  - `app/mcp/agent_client.py`
  - `app/services/audit_service.py`
  - `app/eval/failure_report.py`

- Current state:
  - `RequestLineageGraph` 支持 event/edge、ancestor 查询、untrusted ancestor 判断和 JSON summary。
  - 当前未深度接入 agent runtime、sink guard 或 failure report 主链路。

- Recommended enhancement:
  - 在 `handle_mcp_request(...)` 中可选构建 lineage graph。
  - 将 root request、tool invocation、sink output 记录为 graph events。
  - failure report 可读取 graph summary 辅助解释 untrusted propagation。

- Expected benefit:
  - 更清楚表达 prompt injection / delegated invocation / sink payload provenance 的跨 boundary 传播。
  - 提升 failure analysis 的研究解释力。

- Implementation risk:
  - 中等。若将 graph 结果影响决策，会改变 benchmark；建议先只作为 trace artifact，不参与 action。

- Regression tests:
  - `pytest tests/test_lineage.py`
  - `pytest tests/test_agent_client.py`
  - `pytest tests/test_eval_failure_report.py`

- Thesis impact:
  - v1.1 可写成 stronger provenance tracing。
  - v1.0 仍只能写“lineage graph 已实现为扩展能力”。

### P1-3: 将 statistics helpers 接入 ablation report 的可选导出

- Location:
  - `app/eval/statistics.py`
  - `app/eval/ablation_report.py`
  - `app/services/evaluation_service.py`

- Current state:
  - `statistics.py` 已实现 bootstrap CI、paired comparison、family grouping、module grouping。
  - 当前不是默认 summary 的强制字段，也未深度接入 ablation report。

- Recommended enhancement:
  - 在 ablation report 中增加可选统计附录，例如 `include_statistics=True`。
  - 对 match_rate、ASR、leak_rate、FPR、utility_loss 做 bootstrap CI。
  - 对 baseline vs ablation 做 paired comparison。

- Expected benefit:
  - 支撑论文结果表的置信区间和 paired comparison。
  - 不改变原有 metrics 口径。

- Implementation risk:
  - 低到中。主要风险是误用 CI 解释；需要文档说明 bootstrap 是 lightweight helper。

- Regression tests:
  - `pytest tests/test_eval_statistics.py`
  - `pytest tests/test_eval_ablation_report.py`
  - `pytest tests/test_run_local_eval_ablation.py`

- Thesis impact:
  - 可增强论文实验可信度。
  - v1.0 若没有导出 CI，不应在主实验表中声称已完成统计显著性体系。

### P1-4: PatternMemory 作为 failure report 的可选相似案例召回

- Location:
  - `app/eval/pattern_memory.py`
  - `app/eval/failure_report.py`
  - `app/eval/attack_cases.py`

- Current state:
  - PatternMemory 是 JSONL + token overlap 检索。
  - 支持从 attack cases 构建 records。
  - 当前未接入 metadata_validator、sink_guard 或 failure_report 主输出。

- Recommended enhancement:
  - 在 failure report 中增加可选 `similar_cases` 字段。
  - 使用 PatternMemory 从 failure cases 或 attack cases 中召回相似 pattern。
  - 默认不影响 metrics，不参与 decision。

- Expected benefit:
  - 增强 failure analysis 的解释性。
  - 为 future embedding-backed retrieval 预留接口。

- Implementation risk:
  - 低。只要保持 optional artifact，不影响主指标。

- Regression tests:
  - `pytest tests/test_pattern_memory.py`
  - `pytest tests/test_eval_failure_report.py`
  - `pytest tests/test_attack_cases.py`

- Thesis impact:
  - 可作为系统扩展能力展示。
  - 不应写成 v1.0 主实验指标来源。

### P1-5: 增加 eval artifact semantics version 与 seal metadata

- Location:
  - `app/eval/run_local_eval.py`
  - `app/eval/metrics.py`
  - `results/thesis_experiment_v1/SEAL_INFO.md`

- Current state:
  - `run_local_eval.py` 已使用 case-level semantics snapshot，避免 `round(rate * total)` 反推 count。
  - `SEAL_INFO.md` 标记 `research-prototype-v1.0`，但 Date 仍为“请填写当前日期”。

- Recommended enhancement:
  - 在 eval output 中增加 `semantics_version`、`case_pack_version`、`seal_tag`。
  - 在 `SEAL_INFO.md` 填写实际封板日期。
  - 不改已有指标字段。

- Expected benefit:
  - 降低论文复现实验时 artifact 混用风险。
  - 提升封板产物可信度。

- Implementation risk:
  - 低。属于 metadata 增强，但仍建议放在 v1.1 分支或补充文档产物中。

- Regression tests:
  - `pytest tests/test_run_local_eval_ablation.py`
  - `pytest tests/test_eval_metrics.py`
  - `pytest tests/test_eval_ablation.py`

- Thesis impact:
  - 有助于答辩和论文 artifact 追溯。
  - 不应改变 v1.0 指标数值。

### P1-6: 对 `summarize_case_families(...)` 增加稳定 typed output

- Location:
  - `app/eval/attack_cases.py`

- Current state:
  - `summarize_case_families(cases=None, detailed=False)` 已存在。
  - 默认返回 `dict[str, int]`，`detailed=True` 返回更复杂 summary。
  - 这对测试兼容友好，但长期类型边界略弱。

- Recommended enhancement:
  - v1.1 可新增 `summarize_case_families_detailed(...)` 或 Pydantic summary model。
  - 保留旧函数兼容，不改变 case ids 或 expected values。

- Expected benefit:
  - 更适合论文附录导出和 family-level analysis。
  - 降低调用方误解 simple/detailed 返回结构的风险。

- Implementation risk:
  - 低。只要不改现有默认行为。

- Regression tests:
  - `pytest tests/test_attack_cases.py`
  - `pytest tests/test_eval_ablation.py`

- Thesis impact:
  - 可支撑 case family 分布说明。
  - 不影响 v1.0 主实验结果。

### P1-7: 加强 AuditService 可靠性测试与 close lifecycle 测试

- Location:
  - `app/services/audit_service.py`
  - `main.py`

- Current state:
  - `main.py` lifespan shutdown 会优先调用 `audit_service.close()`。
  - `AuditService` 已支持 buffer、flush、close。
  - 当前缺少针对 flush failure、close idempotency、closed write rejection 的专门测试。

- Recommended enhancement:
  - 新增 `tests/test_audit_service.py`。
  - 覆盖 threshold flush、manual flush、close、write-after-close、flush failure buffer retention。

- Expected benefit:
  - 提升平台审计层可信度。
  - 为后续服务化和实验审计做准备。

- Implementation risk:
  - 低。主要是测试和小规模实现修补。

- Regression tests:
  - `pytest tests/test_api_platform.py`
  - 新增 `pytest tests/test_audit_service.py`

- Thesis impact:
  - 主要影响系统实现章节，不影响主指标。

### P1-8: 补非 tools feature 的 protocol guard 最小测试链

- Location:
  - `app/mcp/protocol_models.py`
  - `app/mcp/agent_client.py`
  - `tests/test_protocol_models.py`
  - `tests/test_agent_client.py`

- Current state:
  - 非 tools feature 可通过 `McpRequestEnvelope` 表达。
  - mock runtime 不执行非 tools feature，返回清晰的 not-executed feature scope 语义。
  - Sampling/Roots/Elicitation contexts 主要是模型层能力。

- Recommended enhancement:
  - 增加针对 `feature="sampling"`、`feature="roots"`、`feature="elicitation"` 的 runtime smoke tests。
  - 确认这些请求不会进入 mock tool execution。
  - 暂不改变业务逻辑。

- Expected benefit:
  - 锁定协议边界。
  - 避免未来误把非 tools feature 当 tools 执行。

- Implementation risk:
  - 低。只要保持 not-executed semantics。

- Regression tests:
  - `pytest tests/test_protocol_models.py`
  - `pytest tests/test_agent_client.py`

- Thesis impact:
  - 支撑“协议对象已覆盖多个 MCP feature scope”的表述。
  - 仍不能声称已实现完整 feature runtime。

## 5. P2: Maintainability Improvements

### P2-1

- Location:
  - `README.md`

- Suggested cleanup:
  - README 的 Project Structure 仍包含较多 “placeholders” 表述。
  - 建议 v1.1 文档分支中更新为当前真实模块职责，但不要重写整份 README。

- Risk if ignored:
  - 新读者可能低估当前实现成熟度，或误解代码仍是 scaffold。

- Suggested timing:
  - v1.1 文档整理 Sprint。

### P2-2

- Location:
  - `app/eval/attack_cases.py`

- Suggested cleanup:
  - `summarize_case_families(detailed=False)` 与 `detailed=True` 返回结构不同。
  - 可新增 typed detailed summary model，同时保留旧接口。

- Risk if ignored:
  - 低。主要是类型可读性和论文附录导出便利性问题。

- Suggested timing:
  - v1.1 case infrastructure Sprint。

### P2-3

- Location:
  - `app/eval/failure_report.py`

- Suggested cleanup:
  - `module_confidence`、`module_attribution_confidence`、`secondary_module_candidates`、`secondary_responsible_modules` 为兼容保留了相近字段。
  - 可在 v1.1 文档中明确 primary field，逐步减少重复命名。

- Risk if ignored:
  - 中低。不会影响指标，但会增加下游 report consumer 的理解成本。

- Suggested timing:
  - v1.1 report schema cleanup Sprint。

### P2-4

- Location:
  - `app/sink/sink_guard.py`

- Suggested cleanup:
  - `SinkDecisionContext` 为兼容保留了 `Any` / `dict[str, Any]` 边界。
  - v1.1 可以在不破坏 legacy `inspect_sink(...)` 的前提下逐步收紧上下文类型。

- Risk if ignored:
  - 中低。弱类型上下文可能延缓后续 lineage graph 接入质量。

- Suggested timing:
  - v1.1 sink lineage integration Sprint。

### P2-5

- Location:
  - `app/mcp/protocol_models.py`

- Suggested cleanup:
  - 协议模型已经较完整，但 response/context 模型尚未有统一 export list 或协议对象边界说明。
  - 可补 `__all__` 或模块级文档，降低重复导入风险。

- Risk if ignored:
  - 低。主要是维护性问题。

- Suggested timing:
  - v1.1 protocol documentation Sprint。

### P2-6

- Location:
  - `app/eval/statistics.py`

- Suggested cleanup:
  - 当前统计函数足够轻量，但 `bootstrap_confidence_interval` 的 CI 解释应在 docstring 中强调是 percentile bootstrap helper，不是完整显著性检验框架。
  - 可补 metric direction 参数，明确 win/loss 的解释方向。

- Risk if ignored:
  - 中。统计结果可能被论文写作误读。

- Suggested timing:
  - v1.1 statistics integration Sprint。

### P2-7

- Location:
  - `app/services/evaluation_service.py`
  - `app/services/report_service.py`

- Suggested cleanup:
  - service 层已是薄层，但 audit event payload 和返回 path 语义可进一步统一为 `audit_path`。
  - 当前 `audit_event` 实际返回 JSONL 文件路径，而不是单事件文件。

- Risk if ignored:
  - 低。API 可用，但命名可能误导调用者。

- Suggested timing:
  - v1.1 platform cleanup Sprint。

### P2-8

- Location:
  - `results/thesis_experiment_v1/SEAL_INFO.md`

- Suggested cleanup:
  - `Date` 字段仍是“请填写当前日期。”
  - 建议在封板产物中补实际日期，但不要改变实验结果文件。

- Risk if ignored:
  - 低。主要影响 artifact 管理和答辩材料整洁度。

- Suggested timing:
  - 文档封存时。

## 6. DOC: Documentation-Only Clarifications

### DOC-1

- Topic:
  - PatternMemory 当前能力边界。

- Clarification to add:
  - `PatternMemory` 是 JSONL + token overlap 的轻量 pattern memory，当前未接入 metadata_validator、sink_guard 或主 metrics。

- Where to document:
  - `docs/experiment_scope.md`
  - 论文 limitations / system extension 小节。

- Why code change is not needed now:
  - 代码已实现最小可测模块；当前风险是论文夸大，不是实现错误。

### DOC-2

- Topic:
  - RuntimeExecutionGovernance 与真实 cancellation scope 的区别。

- Clarification to add:
  - `RuntimeExecutionGovernance` 只是 timeout/cancellation/partial failure 的语义模型，未实现 AnyIO task group、真实 cancel scope 或后台 worker。

- Where to document:
  - `docs/experiment_scope.md`
  - 论文 future work。

- Why code change is not needed now:
  - 当前封板目标是语义预留，不是 async runtime 改造。

### DOC-3

- Topic:
  - Sampling / Roots / Elicitation context 的接入深度。

- Clarification to add:
  - 这些 context 已实现协议对象层，但尚未进入主 benchmark 指标或真实 feature execution。

- Where to document:
  - `docs/experiment_scope.md`
  - 论文 system design / discussion。

- Why code change is not needed now:
  - 非 tools feature 深度接入属于 v1.1+ 新实验范围。

### DOC-4

- Topic:
  - `McpResponseEnvelope` 当前不是 runtime response 的唯一来源。

- Clarification to add:
  - 当前 runtime 主返回仍是 `AgentExecutionResult` / API envelope；`McpResponseEnvelope` 是协议对象层补齐，不是全链路响应替换。

- Where to document:
  - `docs/experiment_scope.md`
  - 论文 implementation detail。

- Why code change is not needed now:
  - 替换 runtime response 会扩散到 route/API/test，不适合 v1.0。

### DOC-5

- Topic:
  - Bootstrap / paired comparison statistics 的解释边界。

- Clarification to add:
  - `statistics.py` 提供轻量可复现 helper，不等价于完整显著性检验体系。

- Where to document:
  - 论文 experiment setup / limitations。

- Why code change is not needed now:
  - 当前主实验表仍由 `summarize_results(...)` 和 ablation report 支撑。

### DOC-6

- Topic:
  - Adaptive adversary case coverage。

- Clarification to add:
  - 当前 `adaptive_adversary` family 应谨慎表述为 adaptive-style 或 adaptive-inspired scenarios，不应声称覆盖完整 adaptive attacker benchmark。

- Where to document:
  - 论文 benchmark description / limitations。

- Why code change is not needed now:
  - 直接改 case expected values 会破坏封板 baseline。

### DOC-7

- Topic:
  - Audit JSONL buffering 可靠性边界。

- Clarification to add:
  - 当前 audit service 是轻量研究原型级 JSONL buffer，不是事务型、安全审计日志系统。

- Where to document:
  - `docs/experiment_scope.md`
  - 系统实现章节。

- Why code change is not needed now:
  - audit 不参与主实验指标；可靠性增强可放 v1.1。

### DOC-8

- Topic:
  - README 中 “placeholders” 表述。

- Clarification to add:
  - 当前项目已超过 scaffold 阶段，README project structure 应在 v1.1 文档整理时更新。

- Where to document:
  - `README.md`

- Why code change is not needed now:
  - 文档措辞问题，不影响 thesis baseline 运行。

## 7. Do-Not-Modify List for thesis baseline

- `app/eval/attack_cases.py` 中已有 case id、case order、expected_action、expected_risk。
  - 原因：这些字段定义 benchmark baseline，改动会导致所有实验指标不可比。

- `app/eval/runtime_semantics.py` 中现有 execution semantics 口径。
  - 原因：`completed_execution`、`execution_degraded`、`intervention_triggered`、`leak_possible` 已被 runner/metrics/failure_report 统一使用，改动会影响论文主表。

- `app/eval/metrics.py` 的核心指标字段名和含义。
  - 原因：论文表格、ablation report 和 failure analysis 已围绕当前字段组织。

- `app/decision/decision_engine.py` 的决策优先级。
  - 包括 hard block、metadata confirmation、untrusted escalation、user authorization lift、dual medium sandbox。
  - 原因：这是当前策略 baseline 的核心语义。

- `app/sink/sink_guard.py` 的核心 sink heuristics 和当前 legacy `inspect_sink(...)` 行为。
  - 原因：leak_rate、utility_loss、false_positive_rate 对 sink 行为敏感。

- `app/eval/ablation.py` / ablation config 名称。
  - 包括 `baseline`、`no_trust_tagging`、`no_metadata_validation`、`no_sink_guard`。
  - 原因：论文 ablation 横向比较依赖这些名称和开关语义。

- API route path 与 response envelope。
  - 包括 `/health`、`/api/v1/tools`、`/api/v1/runtime/execute`、`/api/v1/evaluation/run`。
  - 原因：平台测试和演示脚本依赖当前路径和结构。

- `research-prototype-v1.0` tag 对应 commit。
  - 原因：这是 thesis baseline 的复现锚点，后续改动应进入 v1.1 分支。

## 8. Suggested v1.1 Development Order

### Sprint 1

- Goal:
  - 建立 artifact consistency 与封板元数据保护。

- Files:
  - `app/eval/runtime_semantics.py`
  - `app/eval/runner.py`
  - `app/eval/metrics.py`
  - `app/eval/failure_report.py`
  - `app/eval/run_local_eval.py`
  - `results/thesis_experiment_v1/SEAL_INFO.md`

- Tasks:
  - 增加 `semantics_version` / `case_pack_version` metadata。
  - 增加 artifact consistency validator。
  - 补 seal date。
  - 不改变指标计算口径。

- Tests:
  - `pytest tests/test_eval_runner.py`
  - `pytest tests/test_eval_metrics.py`
  - `pytest tests/test_eval_failure_report.py`
  - `pytest tests/test_run_local_eval_ablation.py`

- Stop condition:
  - 旧 v1.0 artifact 可读，新 v1.1 artifact 带版本信息，主指标无非预期漂移。

### Sprint 2

- Goal:
  - 修补 AuditService 可靠性边界。

- Files:
  - `app/services/audit_service.py`
  - `main.py`
  - `tests/test_audit_service.py`

- Tasks:
  - flush 成功后再清空 buffer。
  - 增加 flush failure test。
  - 增加 close idempotency 和 write-after-close tests。

- Tests:
  - `pytest tests/test_api_platform.py`
  - `pytest tests/test_api_governance.py`
  - `pytest tests/test_audit_service.py`

- Stop condition:
  - flush failure 不丢 buffer；lifespan shutdown 正常 close audit service。

### Sprint 3

- Goal:
  - 让 lineage-aware sink context 进入 runtime 主路径，但先不改变 benchmark expected values。

- Files:
  - `app/mcp/agent_client.py`
  - `app/sink/sink_guard.py`
  - `app/mcp/lineage.py`

- Tasks:
  - 在 `evaluate_sink(...)` 中构造 `SinkDecisionContext`。
  - 可选记录 `RequestLineageGraph` trace artifact。
  - 保持 legacy `inspect_sink(...)` 兼容。

- Tests:
  - `pytest tests/test_agent_client.py`
  - `pytest tests/test_sink_guard.py`
  - `pytest tests/test_eval_runner.py`
  - `pytest tests/test_eval_metrics.py`

- Stop condition:
  - lineage context 被真实传入 sink guard；如指标变化，必须明确记录为 v1.1 behavior change。

### Sprint 4

- Goal:
  - 将 statistics 与 PatternMemory 作为 optional report artifacts 接入。

- Files:
  - `app/eval/statistics.py`
  - `app/eval/pattern_memory.py`
  - `app/eval/ablation_report.py`
  - `app/eval/failure_report.py`

- Tasks:
  - ablation report 可选输出 bootstrap CI / paired comparison。
  - failure report 可选输出 similar cases。
  - 保持默认 metrics 不变。

- Tests:
  - `pytest tests/test_eval_statistics.py`
  - `pytest tests/test_pattern_memory.py`
  - `pytest tests/test_eval_ablation_report.py`
  - `pytest tests/test_eval_failure_report.py`

- Stop condition:
  - Optional artifacts 可生成，默认 benchmark summary 不改变。

### Sprint 5

- Goal:
  - 非 tools MCP feature guard smoke layer。

- Files:
  - `app/mcp/protocol_models.py`
  - `app/mcp/agent_client.py`
  - `tests/test_protocol_models.py`
  - `tests/test_agent_client.py`

- Tasks:
  - 补 sampling / roots / elicitation request smoke tests。
  - 保持 non-tools feature 不进入 mock execution。
  - 文档说明 recognized-but-not-executed semantics。

- Tests:
  - `pytest tests/test_protocol_models.py`
  - `pytest tests/test_agent_client.py`
  - `pytest tests/test_api_platform.py`

- Stop condition:
  - 非 tools feature 边界清晰，不改变 tools benchmark。

## 9. Regression Test Matrix

| Change Area | Tests to Run | Why |
|---|---|---|
| eval semantics | `pytest tests/test_eval_runner.py tests/test_eval_metrics.py tests/test_eval_failure_report.py` | 验证 completed/degraded/intervention/leak 语义一致 |
| attack cases | `pytest tests/test_attack_cases.py tests/test_eval_runner.py tests/test_eval_ablation.py` | 保护 case id、expected values、family summary 和 ablation 可比性 |
| agent runtime | `pytest tests/test_agent_client.py tests/test_protocol_models.py` | 验证 handle_query 兼容层和 handle_mcp_request 协议入口 |
| sink guard | `pytest tests/test_sink_guard.py tests/test_agent_client.py tests/test_eval_runner.py` | sink action 和 leak_possible 对指标高度敏感 |
| API platform | `pytest tests/test_api_platform.py tests/test_api_governance.py` | 验证 lifespan、app.state、Depends、response envelope 不破坏 |
| audit service | `pytest tests/test_api_platform.py` 和新增 `pytest tests/test_audit_service.py` | 验证 JSONL buffer、flush、close 生命周期 |
| pattern memory | `pytest tests/test_pattern_memory.py` | 验证 token overlap、JSONL persistence、pattern_type filter |
| statistics | `pytest tests/test_eval_statistics.py` | 验证 bootstrap CI、paired comparison、family/module grouping |
| concurrency | `pytest tests/test_concurrency.py` | 验证 timeout/cancellation/partial failure 语义模型 |
| ablation report | `pytest tests/test_eval_ablation_report.py tests/test_run_local_eval_ablation.py` | 验证 EvaluationService 与 ablation_report 调用链 |
| tool registry | `pytest tests/test_tool_registry.py tests/test_agent_client.py` | 验证 lineage-aware registry 字段和 legacy JSON 兼容 |
| full baseline | `pytest` | v1.1 任何合并前必须完整回归 |

## 10. Thesis Writing Impact

### 已实现并可写入实验方法

- Evidence-tree decision engine。
- Rule-table capability policy。
- Trust tagging with provenance-aware inference fields，但主指标直接依赖 trust label。
- Metadata validation 与 protocol-level drift hints。
- Sink guard 主执行控制与 legacy-compatible sink inspection。
- Unified runtime/eval semantics。
- Ablation infrastructure。
- Failure report with module confidence / secondary module candidates。
- FastAPI lifespan + app.state + service layer，作为系统原型演示与平台封装。

### 已实现但应写作系统扩展能力

- `McpResponseEnvelope`。
- `SamplingRequestContext`。
- `RootsExposureContext`。
- `ElicitationContext`。
- `RequestLineageGraph`。
- `PatternMemory`。
- `statistics.py` bootstrap / paired comparison helpers。
- `RuntimeExecutionGovernance`。
- Audit JSONL buffering。

### 应写入 limitations / future work

- 尚未接入真实 MCP transport。
- 非 tools MCP feature 目前不是完整 runtime execution path。
- `RequestLineageGraph` 尚未深度连接 agent_client / sink_guard / failure_report 主链路。
- `PatternMemory` 尚未参与主实验指标。
- `statistics.py` 尚未形成完整显著性检验体系。
- `RuntimeExecutionGovernance` 尚未实现真实 AnyIO cancellation scope。
- 当前 case pack 规模有限，adaptive adversary 覆盖应谨慎表述。
- 当前 runtime 是 local mock prototype，不是生产级多租户安全网关。

## 11. Final Recommendation

- 是否建议继续使用 `research-prototype-v1.0` 作为 thesis baseline？
  - 建议继续使用。当前封板状态、测试通过状态和文档边界已经足以支撑 thesis experiment baseline。

- 是否建议在 v1.0 上继续改代码？
  - 不建议。v1.0 应保持只读封板状态，尤其不要改 attack cases、metrics、decision ordering、sink guard 核心逻辑和实验产物。

- 是否建议创建 v1.1 分支？
  - 建议创建。v1.1 应作为候选增强分支，目标是增强可靠性、接入扩展能力和改进论文附属分析，而不是重写 baseline。

- v1.1 第一个 Sprint 应该做什么？
  - 建议先做 “artifact consistency + seal metadata” Sprint。
  - 具体包括：增加 semantics/case_pack version metadata、增加 artifact consistency validator、补全 `SEAL_INFO.md` 日期、明确旧 artifact 与 v1.1 artifact 的边界。
  - 该 Sprint 风险最低，最能保护 thesis baseline，同时为后续 lineage、statistics、pattern memory 接入建立安全边界。