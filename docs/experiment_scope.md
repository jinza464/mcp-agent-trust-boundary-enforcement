# 实验范围与原型能力边界说明

本文档用于固化当前研究原型中“已接入主实验链路的能力”和“研究原型预留能力”的边界。论文写作、实验设置、系统实现说明和答辩展示应以本文档为准，避免把尚未进入主指标链路的模块写成已经影响 benchmark 结果的能力。

## 1. 当前项目定位

本项目是一个面向 MCP-enabled LLM Agents 的 client-side trust boundary enforcement 研究原型。系统重点验证客户端侧如何在工具注册、来源信任推断、能力识别、元数据漂移、决策合成、sink 执行控制和评测分析之间建立可解释的防护链路。

当前版本适合作为论文实验 baseline 和系统原型展示，但它不是生产级安全网关。项目当前重点是协议边界建模、策略解释、运行时/评测语义统一、实验可复现和模块贡献分析，而不是提供完整的生产级 MCP transport、多租户隔离、真实并发调度或长期在线防护系统。

因此，论文中应明确使用“研究原型”“本地评测链路”“mock/runtime prototype”等表述，不应夸大为生产级安全基础设施。

## 2. 已接入主实验链路的能力

以下模块已经参与当前 benchmark、evaluation 或 metrics 的主链路。

- `decision_engine evidence tree`
  - 已参与主实验链路。
  - `decision_engine` 输出 `action`、`risk_level`、`reasons`、`findings` 和 confirmation/escalation 语义。
  - evidence tree 增强决策解释性，但不会单独改变指标；指标仍来自最终 action、risk 和 runtime/eval 语义。

- `capability_policy rule table`
  - 已参与主实验链路。
  - `classify_capabilities(...)` 影响能力识别、风险归类和 downstream decision。
  - rule table 结构用于解释 capability finding 和模块贡献。

- `trust_tagger provenance fields`
  - 已参与主实验链路的一部分。
  - `tag_source(...)` / `infer_trust(...)` 输出 trust label，并影响 decision path。
  - provenance fields 主要提供来源解释；当前主指标直接依赖的是 trust label，而不是单独统计 provenance 字段。

- `sink_guard lineage-aware context`
  - sink guard 主逻辑已参与主实验链路。
  - `inspect_sink(...)` 是当前 runner 中 sink 检查的主要入口，影响 `sink_action`、`leak_possible`、intervention 和 utility 相关指标。
  - lineage-aware context 已作为扩展入口存在，但不是所有 benchmark case 都提供完整 lineage graph。

- `runtime_semantics`
  - 已参与主实验链路。
  - `compute_execution_semantics(...)` 统一解释 `completed_execution`、`execution_degraded`、`intervention_triggered`、`hard_blocked`、`confirmation_required` 和 `leak_possible`。
  - 当前 execution-related metrics 应以该模块为语义来源。

- `failure_report module confidence`
  - 已参与 failure analysis 产物。
  - failure report 输出模块责任、置信度和次要候选模块，用于解释 mismatch、successful attack、leak-prone、false positive 和 utility loss 案例。
  - 它影响 failure analysis 解释，不直接改变 benchmark 决策结果。

- `ablation infrastructure`
  - 已参与主实验链路。
  - baseline、no_trust_tagging、no_metadata_validation、no_sink_guard 等配置通过 ablation infrastructure 运行并导出 summary/report。
  - ablation 结果用于分析模块贡献和安全-可用性权衡。

- `FastAPI platform/service layer`
  - 已完成平台层与服务层收口。
  - 它支撑 API 演示、共享 service、审计缓冲和报告导出，但不直接改变 benchmark 指标口径。

这些模块共同影响当前实验中的 `action`、`risk_level`、`completed_execution`、`execution_degraded`、`intervention_triggered`、`leak_possible` 和 failure analysis 归因。

## 3. 已实现但主要作为研究扩展能力的模块

以下模块已经实现最小能力，但尚未深度接入当前主实验指标。论文中可以作为系统扩展能力、设计预留、discussion 或 future work 描述，不应写成当前主实验指标的直接来源。

- `McpResponseEnvelope`
  - 已实现协议响应 envelope。
  - 当前主要用于协议对象层完整性展示，尚未成为主 runtime 返回结构的唯一来源。

- `SamplingRequestContext`
  - 已实现 sampling 请求上下文。
  - 可表达 sampling 与 root user request、server origin、allowed tools 和 user approval 的关系。
  - 当前尚未作为主 benchmark 指标来源。

- `RootsExposureContext`
  - 已实现 roots exposure 上下文。
  - 可表达 exposed roots、exposure reason、server origin 和 user approval。
  - 当前尚未接入 roots guard 主实验指标。

- `ElicitationContext`
  - 已实现 elicitation 上下文。
  - 可表达 elicitation prompt、requested fields、sensitive fields、server origin 和 user approval。
  - 当前尚未接入 elicitation safety 主实验指标。

- `RequestLineageGraph`
  - 已实现轻量内存 provenance graph。
  - 支持 event/edge、ancestor 查询、不可信祖先判断和 JSON summary。
  - 当前尚未成为所有 benchmark case 的统一 trace 来源。

- `PatternMemory`
  - 已实现 JSONL + token overlap 检索。
  - 可用于历史 drift 模式索引、攻击片段近邻检索和 failure case 相似召回。
  - 当前未接入 metadata_validator、sink_guard 或主 metrics。

- `bootstrap / paired comparison statistics`
  - 已实现轻量统计工具。
  - 可用于 bootstrap confidence interval、paired comparison、family-level 和 module-level grouping。
  - 当前尚未成为默认 evaluation summary 的强制输出。

- `RuntimeExecutionGovernance`
  - 已实现 timeout、cancellation、partial failure 和 fail-closed 的语义模型。
  - 当前没有真实 cancellation scope、AnyIO task group 或后台 worker。

## 4. 当前 benchmark 指标来源

当前实验指标主要来自以下模块。

- `attack_cases`
  - 提供固定 case pack、case family、expected action/risk、sink plan 和 benign/attack 标注。

- `runner`
  - 通过 `run_case(...)` 和 `run_all_cases(...)` 执行 case-level policy、sink 和 ablation 流程。

- `runtime_semantics`
  - 统一执行完成、干预、退化、硬阻断、确认门和 leak 语义。

- `metrics`
  - 通过 `summarize_results(...)` 汇总主表指标。

- `failure_report`
  - 生成 failure analysis、模块归因和 case-level 证据池。

- `ablation_report`
  - 汇总 baseline 与 ablation 配置差异，支撑模块贡献分析。

当前核心指标包括：

- `match_rate`
- `attack_success_rate`
- `leak_rate`
- `false_positive_rate`
- `utility_loss`
- `execution_completion_rate`
- `intervention_rate`
- `hard_block_rate`
- `confirmation_rate`

## 5. 当前不声称的能力

当前项目不声称已经实现以下能力：

- 不声称已经实现真实 MCP transport。
- 不声称已经实现生产级并发调度。
- 不声称 `PatternMemory` 已经接入主实验指标。
- 不声称 `RuntimeExecutionGovernance` 已经实现真实 cancellation scope。
- 不声称统计模块已经完成完整显著性检验体系。
- 不声称系统能防御所有 adaptive attacks。
- 不声称当前本地 mock runtime 等价于生产多租户 MCP 运行环境。

## 6. 论文写作建议

### 可以写成“已实现并参与实验”的内容

- evidence tree decision engine。
- rule-table capability policy。
- provenance-aware trust tagging 的 trust label 推断链路。
- lineage-aware sink context 的兼容入口与 sink guard 主逻辑。
- unified runtime/eval semantics。
- metadata validation。
- ablation and failure report。
- FastAPI platform/service layer 作为系统原型演示基础。

### 可以写成“已实现的系统扩展能力”的内容

- protocol contexts for sampling / roots / elicitation。
- MCP response envelope。
- request lineage graph。
- pattern memory。
- statistics helpers。
- concurrency governance models。

### 应写成“后续工作”的内容

- real MCP transport integration。
- embedding-backed retrieval。
- true structured concurrency with AnyIO。
- larger adaptive benchmark。
- stronger statistical significance testing。
- 将 RequestLineageGraph、PatternMemory、Sampling/Roots/Elicitation guard 深度接入主实验链路。
