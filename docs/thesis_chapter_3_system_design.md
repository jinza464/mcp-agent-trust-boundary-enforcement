# 第 3 章 系统设计与实现

## 3.1 系统设计目标

MCP-enabled LLM Agents 通过工具、资源、提示、sampling、roots、elicitation 等协议能力扩展了语言模型与外部环境交互的范围，也相应扩大了信任边界。工具元数据可能来自不同服务器，提示内容可能由外部文档派生，资源访问和工具调用可能跨越用户、客户端与服务器之间的责任边界。若客户端缺少显式的边界建模，攻击者可以通过 prompt injection、metadata injection、tool shadowing、rug-pull、source-to-sink exfiltration 等路径，将不可信输入转化为高风险工具执行或外发行为。

本系统的设计目标是在 MCP client 侧建立一个可解释、可测试、可复现实验的 trust boundary enforcement 研究原型。系统并不试图替代 MCP transport，也不将自身定位为生产级安全网关，而是在客户端运行时对协议请求、工具身份、来源信任、能力声明、元数据漂移、策略决策和 sink 外发路径进行统一建模，使 agent 的每一次工具执行或风险干预都可以被追踪、解释和评估。

具体而言，系统需要实现四类目标。第一，协议对象化目标，即将 MCP 请求从普通字符串或本地 mock 参数提升为具有 request id、session id、feature scope、source role 和 request lineage 的协议对象。第二，策略解释目标，即将来源信任、能力识别、元数据验证和 sink 检查的结果组织为可审计的证据结构，而不是只输出单一 allow/deny 结果。第三，运行时约束目标，即在执行前统一评估 decision gate 与 sink gate，避免不可信来源直接驱动敏感操作。第四，实验复现目标，即将 runtime 语义、metrics、failure report 和 ablation artifact 的口径统一，以支撑后续实验章节中的模块贡献分析。

因此，本章关注的是系统设计与实现逻辑，而不是实验指标本身。第 4 章将进一步基于正式实验结果分析该系统在攻击成功率、误报、可用性损失和模块消融方面的表现。本章只在必要处简要呼应实验结论，用于说明设计选择与实验观察之间的关系。

## 3.2 系统总体架构

本系统采用分层架构，将 API 平台、MCP 协议对象、agent runtime、信任边界强制、sink 控制、评测报告和审计产物分离。该分层方式的核心目的不是引入复杂框架，而是避免安全语义散落在不同调用点中，使协议上下文、策略证据和实验语义能够沿同一条链路传播。

图 3-1 给出了系统总体架构的文字示意。用户请求或 MCP 协议请求首先进入 FastAPI 平台层，由 service 层转发给 MCPAgentClient。runtime 层将请求规范化为协议上下文和 RequestLineage，然后依次执行 trust tagging、metadata validation、capability policy、decision engine 和 sink guard。若策略和 sink gate 均允许，系统进入 mock runtime 执行；否则生成阻断、确认或升级结果。最终，runtime semantics、metrics、failure report 和 ablation report 负责将执行结果转化为实验指标与论文可用产物。

图 3-1 系统总体架构文字示意：

```text
User Query / MCP Request
        ↓
FastAPI Platform / RuntimeService
        ↓
MCPAgentClient
        ↓
Protocol Context & RequestLineage
        ↓
Trust Tagger → Metadata Validator → Capability Policy
        ↓
Decision Engine / Evidence Tree
        ↓
Sink Guard
        ↓
Mock Runtime / Execution Outcome
        ↓
Runtime Semantics / Metrics / Failure Report
```

表 3-1 概括了各层职责及其与实验链路的关系。可以看到，系统主链路并非单个策略函数，而是由多个职责明确的模块共同完成风险建模、证据聚合和执行控制。

表 3-1 系统分层职责

| 层次 | 代表对象或模块 | 主要职责 | 与实验链路的关系 |
|---|---|---|---|
| API 平台层 | FastAPI、RuntimeService、EvaluationService、ReportService | 提供统一 API 入口、共享 service 生命周期和响应 envelope | 支撑系统调用、评测运行和报告导出 |
| MCP 协议对象层 | McpRequestEnvelope、RequestLineage、协议上下文模型 | 表达 MCP feature、source role、session 与 lineage | 为 runtime 和 registry 提供协议上下文 |
| Agent runtime 层 | MCPAgentClient | 编排请求规范化、策略评估、sink 检查和 mock 执行 | 主执行路径，产生 trace 与 final_status |
| 信任边界强制层 | trust_tagger、metadata_validator、capability_policy、decision_engine | 识别来源、漂移、能力和决策动作 | 直接影响 action、risk_level 和干预语义 |
| Sink 控制层 | sink_guard | 检查外发、文件写入、状态变更等执行面风险 | 影响 sink_action、confirmation 和 leak_possible |
| Evaluation 与 reporting 层 | runner、metrics、failure_report、ablation_report | 执行 case、汇总指标、生成失败归因与消融报告 | 第 4 章实验结果来源 |
| Artifact / audit 层 | runtime_semantics、AuditService、manifest、JSONL | 统一语义版本、审计事件和实验产物元数据 | 防止 artifact 语义漂移，支持复现 |

该架构的关键特征在于，策略模块只负责产生结构化证据和建议动作，runtime 层负责组合执行，evaluation 层负责解释结果。通过这种分离，系统可以在不改变 benchmark case expected values 的前提下，对协议对象、证据树、审计产物和可选分析能力进行增量增强。

## 3.3 数据边界与核心模型设计

安全系统自身首先需要可靠的数据边界。如果 API 输入、工具元数据、策略输出和评测结果之间大量使用裸 `dict` 或 `Any` 穿透，则同一字段可能在不同模块中被解释成不同含义，进而导致策略判断和实验统计产生口径漂移。因此，系统第一阶段对 API schema、核心模型、配置对象、响应 envelope 和异常边界进行了收紧。

API schema 的作用是将外部请求限制在明确结构中。以 runtime 执行为例，请求中的 `source_metadata`、`sink_metadata` 和 `sink_payload` 不再只是任意业务字典，而被视为协议负载边界对象：它们允许保留 MCP feature 或实验 case 所需的灵活字段，但必须通过命名清晰的请求模型进入系统。这样既保留 JSON 序列化友好性，也避免不可信字段在未标注语义的情况下穿透到策略层。

响应层采用统一 envelope，将成功响应和错误响应分别约束为稳定结构。成功响应保留 `ok`、`request_id`、`timestamp`、`data` 和 `artifacts`，错误响应保留 `ok`、`request_id`、`timestamp` 和 `error:{code,message,details}`。这种设计使 API route 可以继续直接返回 JSON-compatible dict，同时让论文实验和平台测试能够依赖稳定响应边界。

异常层通过 `PlatformError`、`ValidationError` 和 `ServiceError` 维护稳定错误语义，并通过 `to_dict()` 输出 `code`、`message`、`details`。配置层通过 Pydantic v2 风格的 settings 对环境变量进行约束，包括应用名称、版本、API prefix、输出目录、case pack 和实验 artifact 开关。上述边界收紧不是额外功能，而是后续协议对象化、证据树决策和 artifact consistency 的基础。

表 3-2 总结了主要数据边界对象及其设计目的。

表 3-2 数据边界对象与设计目的

| 边界位置 | 代表对象 | 设计目的 |
|---|---|---|
| API 输入 | RuntimeExecuteRequest 等请求 schema | 限制外部输入形态，避免宽泛 payload 直接进入策略层 |
| API 输出 | success/error envelope | 保持路由响应结构稳定，便于测试和调用方解析 |
| 核心域模型 | ToolMetadata、ToolSnapshot、DecisionResult | 统一 registry、validator、decision 和 eval 的数据契约 |
| 异常边界 | PlatformError、ValidationError、ServiceError | 保持错误响应结构兼容且可扩展 |
| 配置边界 | Settings | 约束环境变量与输出路径，保证实验运行可复现 |

这种数据模型设计体现了一个基本原则：安全判断需要处理开放世界输入，但安全系统内部不能以开放世界方式传播所有字段。系统在边界处保留必要灵活性，在核心链路中尽量使用显式模型和稳定字段，从而降低语义歧义。

## 3.4 MCP 协议对象层设计

本系统将 MCP 从研究背景中的“主题词”进一步落实为协议对象。协议对象层的核心模型是 `McpRequestEnvelope`，它显式表达 `request_id`、`session_id`、`parent_request_id`、`feature`、`source_role`、`server_origin` 和 `payload`。其中 `feature` 覆盖 `tools`、`resources`、`prompts`、`sampling`、`roots` 和 `elicitation`，`source_role` 覆盖 host、client 和 server。`payload` 保留为协议负载边界对象，以容纳不同 MCP feature 的差异化请求体。

与请求对象对应，`McpResponseEnvelope` 用于表达协议响应侧的结构，包括 `request_id`、`session_id`、`feature`、`source_role`、`ok`、`status`、`payload`、`error` 和 `created_at`。该模型补齐了协议层的响应表达，但在当前主实验链路中，runtime 返回仍主要由 AgentExecutionResult 和 API envelope 承担。因此，`McpResponseEnvelope` 应被视为协议对象层的完整性补齐和后续扩展基础，而不是当前主指标的直接来源。

`RequestLineage` 用于记录请求关联关系和信任上下文，包括 `request_id`、`parent_request_id`、`root_user_request_id`、`source_role`、`feature`、`trust_label`、`session_id`、`server_origin` 和 lineage depth 等字段。该模型使一个工具调用不再只是孤立事件，而是可以被归入某个 root user request 和上游协议上下文中。它在 agent runtime、ToolRegistry 和 sink context 中均具有作用。

除 tools feature 外，系统还实现了 `SamplingRequestContext`、`RootsExposureContext` 和 `ElicitationContext`。这些对象分别表达 sampling 请求是否关联合法用户意图、roots exposure 暴露了哪些根路径、elicitation 请求要求用户提供哪些字段。当前系统对 sampling、roots 和 elicitation 具备协议对象与 smoke guard 能力，即能够识别这些 feature 并保证它们不会被误送入 tools mock execution 或 tools sink context，但尚未实现完整的 sampling runtime、roots exposure guard 或 elicitation safety runtime。

表 3-3 给出了协议对象及其语义边界。

表 3-3 MCP 协议对象语义

| 协议对象 | 表达内容 | 当前接入状态 |
|---|---|---|
| McpRequestEnvelope | 请求 id、session、feature、source role、server origin、payload | 已进入 agent runtime 主入口 |
| McpResponseEnvelope | 协议响应状态、payload、error、provenance | 已实现模型层，主要作为扩展能力 |
| RequestLineage | root request、parent request、trust label、feature scope | 已进入 registry 和 sink context |
| SamplingRequestContext | sampling 与 root user request、allowed tools、approval 的关系 | 已实现协议上下文与 smoke guard |
| RootsExposureContext | exposed roots、exposure reason、approval、server origin | 已实现协议上下文与 smoke guard |
| ElicitationContext | elicitation prompt、requested fields、approval、server origin | 已实现协议上下文与 smoke guard |

因此，当前系统的主执行路径仍是 tools feature。non-tools feature 被识别为 MCP feature，但在本研究原型中返回 not-executed / not-applicable 语义。这一设计避免了将 sampling、roots 或 elicitation 错误地当作普通工具调用执行，也为后续真实 MCP runtime 接入留下明确接口。

## 3.5 Request Lineage 与 Provenance 建模

MCP-enabled agent 的安全问题不仅取决于当前请求内容，还取决于该请求如何产生、从哪里派生、是否跨越不可信边界。一个看似可信的工具调用，可能源自外部文档中的 prompt injection；一个 sampling 请求，可能并非来自合法用户意图；一个 sink payload，可能携带由 untrusted upstream content 派生的信息。因此，系统引入 request lineage 与 provenance 建模，用于解释不可信内容如何在协议边界之间传播。

轻量 lineage/provenance 子系统由 `LineageEvent`、`ProvenanceEdge` 和 `RequestLineageGraph` 组成。`LineageEvent` 记录单个请求或运行时事件的 request id、parent request id、root user request id、event type、feature、source role、trust label、timestamp 和 metadata。`ProvenanceEdge` 记录事件之间的因果或派生关系，包括 from event、to event、relation、reason 和 trust transfer。`RequestLineageGraph` 维护事件和边，并提供 `add_event`、`add_edge`、`find_ancestors`、`has_untrusted_ancestor` 和 `summarize` 等方法。

该图结构的设计目标是研究可解释性，而不是生产级 trace 系统。它不引入图数据库，也不执行复杂图算法，而是提供一个可 JSON 化、可审计、可扩展的本地内存模型。`has_untrusted_ancestor` 可以判断某个请求是否存在不可信祖先，`summarize` 可以生成供 failure report 或 audit 使用的摘要。

在当前主链路中，`RequestLineage` 已进入 ToolRegistry 和 sink context。ToolRegistry 可以记录工具快照出现在哪个 request lineage 下，sink guard 可以根据 upstream trust label、decision action、capability result 和 request lineage 调整 sink 风险解释。v1.1 增强进一步将 lineage-aware sink context 接入 agent runtime 的 tools feature 主路径，使 sink guard 不只接收 payload 和 metadata，也能看到上游信任边界信息。

需要强调的是，`RequestLineageGraph` 当前更多是系统能力和后续扩展基础。它能够表达 prompt injection 如何跨 boundary 传播、sampling 请求是否可追溯到 root user request、sink payload 是否源自 untrusted source，但尚未成为所有 benchmark case 的统一 trace 来源。因此，论文中应将其描述为轻量 provenance 子系统，而不是完整工业 provenance 平台。

## 3.6 工具注册表与工具身份建模

在 MCP 场景中，工具身份不能只依赖工具名称。攻击者可以通过 tool shadowing 使用相同或相近名称伪装工具，也可以通过 rug-pull 在初始注册后改变工具描述、schema、server origin 或 capability。为此，系统实现了 `ToolRegistry`，用于记录工具身份历史、元数据快照和漂移审计。

工具身份由 `tool_id`、`name`、`version`、`provider`、`provider_identity`、`namespace`、`server_origin` 和 `source_uri` 等字段共同构成。注册表为每次观察生成 `ToolSnapshot`，记录 description hash、input/output schema hash、server origin、observed version、integrity state、trust label 和 runtime context。与只比较名称相比，这种身份建模更适合发现同名不同源、同源不同 namespace、版本回滚和 capability drift 等风险。

`ToolRegistry.register_tool()` 支持可选的 `request_lineage`。当 lineage 存在时，registry 会在 identity track 中记录 `last_seen_request_id`、`last_seen_session_id`、`feature_scope` 和 `lineage_root_request_id`，并将这些信息写入 snapshot 的 runtime context。这样，工具变化不再只是“某个工具变了”，而是可以进一步回答“该变化发生在哪个 MCP feature、哪个 session、哪个 root user request 的上下文中”。

注册表还提供 drift detection，用于比较旧 snapshot 与新 metadata。变化类别包括 descriptive change、schema change、server relocation、namespace conflict、rollback 和 suspicious capability drift。对于 tool shadowing 和 rug-pull 场景，registry 的作用是为 metadata validator 和 decision engine 提供历史基线，使系统能够识别工具身份和行为声明的异常演化。

该模块的设计体现了客户端侧防护的一个核心假设：MCP client 不能只信任当前服务器返回的工具描述，还必须保留历史观察和来源上下文。只有这样，系统才能对“看似合法但已经漂移”的工具元数据作出解释性判断。

## 3.7 Trust Tagging 模块设计

Trust Tagging 模块用于推断输入来源的信任标签。其核心输出是 `TrustLabel`，代表来源被判断为 trusted、semi-trusted、conditional、untrusted 或 unknown 等状态。该模块提供 `infer_trust()` 和 `tag_source()` 两类接口，其中 `tag_source()` 保持兼容，直接返回 trust label；`infer_trust()` 返回更完整的 `TrustInferenceResult`，包含 baseline prior、trust factors、downgrade reasons、trust score、provenance chain、evidence strength 和 derived_from_untrusted_content。

该模块首先依据 source type 给出 baseline prior。例如 user query 和 system config 通常具有较高先验，cached metadata 和 tool description 属于中间信任，external document 和 server notification 更容易被判定为 untrusted。随后，系统根据 integrity verification、signature validity、freshness、locality、registry consistency 和 prompt-like content 调整信任分数。如果内容包含类似 “ignore previous instructions”“system prompt”“without user confirmation” 等控制语句，信任分数会下降。

第三阶段后，trust tagging 增加了 provenance 表达能力。`provenance_chain` 可以记录 source type baseline、metadata-derived hints、upstream trust label、derived_from_source_type 和显式 provenance_chain 输入。`derived_from_untrusted_content` 用于显式表示当前来源是否由不可信上游内容派生，而不是只将该事实隐藏在 downgrade reasons 中。`evidence_strength` 则以 weak、medium、strong 等形式概括当前信任证据的强弱。

Trust tagging 并不单独决定最终安全动作。它的主要作用是为后续 capability policy、decision engine 和 sink guard 提供来源信任上下文。例如 untrusted source 与 medium/high capability risk 组合时可能触发 escalation；sink guard 在判断外发 payload 时也会考虑 upstream trust label。因此，trust tagging 是上下文证据模块，而不是独立的强阻断模块。

## 3.8 Metadata Validation 模块设计

Metadata Validation 模块负责检测工具元数据在时间上的演化风险。与 runtime payload 检查不同，metadata validation 面向的是非执行面风险：工具描述、schema、来源、namespace、version、invocation constraints 和协议能力声明是否发生了异常变化。该模块以 registry 中的旧 snapshot 和当前 `ToolMetadata` 为输入，输出 `MetadataValidationResult`，包括 findings、risk level、recommended action、changed fields、change categories、drift domains 和 structured findings。

该模块覆盖多类 drift。描述层面包括 description drift 和 prompt-like metadata injection；接口层面包括 input schema drift、output contract drift、parameter-level drift 和 invocation constraint drift；来源层面包括 provider/server relocation、namespace confusion 和 resource URI scope drift；行为层面包括 version rollback、capability advertisement drift、sampling-related control drift 和 roots scope broadening。这些规则共同服务于 metadata injection、tool shadowing、rug-pull 和 protocol capability expansion 等攻击模型。

协议级 drift 检测是该模块的扩展重点。对于 sampling，系统会检查 sampling policy、prompt template、system prompt 和相关 tags 是否漂移；对于 roots，系统会检查 allowed roots 或 root scope 是否扩大；对于 resources，系统会检查 resource URI scope 是否变化；对于 server capability advertisement，系统会检查是否新增 sampling、roots、resources 或 elicitation 等高影响 MCP feature。只有当相关旧语义和新语义都存在时，这些协议级规则才会触发，以避免无协议上下文时误报。

实验结果表明，metadata validation 在消融实验中贡献最显著。该结论说明非执行面风险证据对于 MCP agent 安全非常关键。然而，该模块也会对 benign schema evolution 或 same-provider minor contract drift 产生确认成本。因此，本章将其视为核心防线之一，同时在设计上保留 future work：schema compatibility analysis、minor version policy 和 provider-scoped allowlist。

## 3.9 Capability Policy 与规则表设计

Capability Policy 模块用于从工具元数据中推断工具可能具备的安全相关能力。MCP 工具描述、schema 和约束不一定直接声明“危险能力”，但其中可能包含网络发送、文件写入、状态修改、凭证访问、隐藏调用和工具链委托等信号。若不对这些能力进行归类，decision engine 和 sink guard 将缺少关键风险输入。

系统将能力归类表示为 `PolicyCapability`，包括 benign_read、read_secret、file_write、network_send、state_change、hidden_invocation、credential_access 和 toolchain_delegation 等。能力推断不仅依赖文本关键词，也依赖 schema token、invocation constraints、declared capability、policy labels、capability profile 和 context signals。该模块输出 `CapabilityClassificationResult`，包含 detected capabilities、risk level、text findings、structured findings、direct exfiltration capable、latent exfiltration capable 和 orchestration capable。

第三阶段后，系统将原本较分散的规则整理为 rule table / DSL 风格。`RuleSource` 表示规则来源，如 text、schema、constraints、context、declaration、policy_label、capability_profile 和 derived；`RuleMatcherConfig` 描述匹配配置；`CapabilityRule` 定义稳定 rule_id、目标 capability、source 和特征；`RuleMatch` 连接规则命中与结构化 finding。每条 `CapabilitySignalFinding` 都可携带 rule_id，从而支持后续 evidence tree 和 failure attribution。

规则表设计的好处在于可测试性和可迁移性。当前规则仍以内嵌 Python table 实现，以保证 benchmark 行为稳定；未来可以迁移到 YAML/TOML 或更系统的 policy DSL。该模块的局限也较明确：对 adaptive synonym、paraphrase 和语义改写类攻击的泛化能力不足。第 4 章的 failure analysis 显示，少量 successful attacks 正是利用了这种词面规则敏感性。

## 3.10 Decision Engine 与 Evidence Tree

Decision Engine 是信任边界强制链路中的策略聚合模块。它接收工具元数据、来源信任标签、source metadata、capability result、metadata validation result、旧 snapshot 和用户授权状态，输出最终 `DecisionAction`、`RiskLevel`、reasons、findings 和是否需要用户确认。其核心设计目标是将多个模块的局部证据组合为可解释的最终动作，而不是把策略判断隐藏在不可审计的条件分支中。

系统保留 `PolicyStageResult` 表达阶段级规则评估结果，并引入 `RuleNode` 和 `DecisionEvidenceTree`。`RuleNode` 记录 rule_id、stage、triggered、severity、proposed_action、reasons 和 children；`DecisionEvidenceTree` 记录 root_action、aggregate_risk 和节点列表。最终 `DecisionResult.evidence` 中同时保留 `evidence_tree` 和兼容旧消费者的 `policy_trace`。这种设计使每个最终动作都可以追溯到 hard block、metadata、source trust、capability、dual medium aggregation 和 user authorization lift 等规则节点。

Decision Engine 的优先级设计保持明确语义。例如 hidden invocation 或 read-secret + network-send 组合会触发 hard block；high metadata risk 会触发 require_confirmation；untrusted source 与 non-low risk 组合会触发 escalate；high capability risk 会触发 confirmation；单独 medium metadata 或 medium capability 风险通常作为 advisory，只有双 medium 条件被强化时才进入 sandbox。用户授权可以将 require_confirmation lift 为 allow，但 aggregate risk 不随之降低，并在 evidence tree 中通过 `aggregation:user_authorization_lift` 节点解释。

图 3-2 给出了简化的 evidence tree 示意。实际系统中的节点会包含 rule_id、severity、proposed_action 和 reasons，用于 failure report 与审计解释。

图 3-2 DecisionEvidenceTree 简化示意：

```text
DecisionEvidenceTree
├── metadata_validator: prompt_like_metadata_detected
├── capability_policy: network_send_detected
├── trust_tagger: untrusted_source
├── aggregation:dual_medium_to_sandbox
└── aggregation:final_action
    ├── hard_block_policy
    ├── metadata_policy
    ├── source_trust_policy
    └── capability_policy
```

该设计的意义在于，决策不再只是一个黑盒动作。论文实验中的 failure analysis 可以引用 evidence tree 与 policy trace，说明某个 case 为什么被 deny、require_confirmation、escalate、sandbox 或 allow。这也为后续引入 adaptive attacker 规则、MCP feature-specific policy 或更复杂授权链提供了结构化扩展点。

## 3.11 Sink Guard 与外发路径控制

Sink Guard 是执行前最后一道安全边界。前面的模块主要判断工具来源、元数据演化和能力声明，而 sink guard 关注“即将发生的执行行为是否会向外部发送数据、写入文件、读取凭证或改变状态”。在 agent 系统中，许多攻击并不止于策略绕过，而是在最后一步通过 external endpoint、callback、file write 或 state change 完成外泄或持久化影响，因此 sink 控制是必要的执行面防线。

该模块提供兼容入口 `inspect_sink()` 和结构化入口 `inspect_sink_with_context()`。后者接收 `SinkDecisionContext`，其中包含 request_lineage、upstream_trust_label、decision_action、capability_result、payload 和 sink_metadata。sink metadata 可表达 sink_type、endpoint、allowlisted domains、internal domains、file path、operation、user_authorized 和 authorization_chain_trusted 等上下文。这样，sink guard 可以同时看到 payload、本地 sink hints 和上游策略结果。

Sink Guard 的核心规则包括 endpoint classification、sensitivity signals、staged exfiltration markers、fragment suspicion、trusted internal sync exception 和 state change authorization 判断。endpoint 会被分类为 internal、allowlisted、external 或 unknown；payload 会被检查 token、password、api key、credential、PII、base64-like obfuscation、fragmented payload 和 staged transfer 等信号。对于 external endpoint 上的敏感或分片外发，系统倾向于 require_confirmation 或 deny；对于 trusted internal sync，若存在完整信任提示且 payload 不敏感，系统允许更宽松处理。

v1.1 增强将 lineage-aware sink context 接入 agent runtime tools feature 主路径。也就是说，sink guard 不再只依赖 payload 与 metadata，还可以看到 upstream trust label、decision action、capability result 和 request lineage。若 payload 明确源自 untrusted upstream，或 delegated/hidden invocation 与 external sink 组合出现，sink guard 会增加风险解释和确认倾向。non-tools feature 仍不会被强行送入 sink context。

该模块也体现了系统最明显的安全—可用性权衡。它可以降低 external endpoint、state change 和敏感 payload 外发风险，但也可能对 authorized config write、allowlisted callback、trusted internal sync 等 gray-zone workflow 触发确认。第 4 章将进一步通过消融实验和 failure analysis 说明该权衡。

## 3.12 Agent Runtime 执行流程

Agent Runtime 由 `MCPAgentClient` 实现。它保留 `handle_query()` 作为 legacy compatibility entrypoint，同时新增 `handle_mcp_request()` 作为协议化入口。前者将传统 user query、source metadata、sink metadata 和 user authorization 参数封装为 `McpRequestEnvelope(feature="tools")`，再交由后者处理。这样，旧调用方无需立即迁移，同时主 runtime 已经围绕 MCP 协议对象组织。

`handle_mcp_request()` 将执行过程拆分为五个阶段：`build_request_context()`、`evaluate_policy()`、`evaluate_sink()`、`execute_mock_runtime()` 和 `finalize_outcome()`。第一阶段从 envelope 中提取 user query、source type、source content、source metadata、sink payload、sink metadata 和 user authorization，并选择工具、构造 RequestLineage。第二阶段执行 trust tagging、capability classification、metadata validation 和 decision engine。第三阶段执行 sink inspection。第四阶段仅在 policy gate 和 sink gate 均允许时创建 invocation plan 并执行 mock runtime。第五阶段统一生成 final status、execution flags 和 final outcome。

图 3-3 给出了 runtime 执行流程。

图 3-3 协议化 runtime 流程：

```text
handle_mcp_request
    → build_request_context
    → evaluate_policy
    → evaluate_sink
    → execute_mock_runtime
    → finalize_outcome
```

表 3-4 总结了各阶段的输入输出语义。

表 3-4 Agent Runtime 阶段语义

| 阶段 | 输入 | 输出 | 安全意义 |
|---|---|---|---|
| build_request_context | McpRequestEnvelope | RequestRuntimeContext、RequestLineage、selected tool | 将协议请求规范化为运行时上下文 |
| evaluate_policy | Runtime context | trust label、capability result、metadata result、decision result | 聚合非执行面与策略证据 |
| evaluate_sink | Policy bundle、sink payload/metadata | sink result、sink gate status | 检查外发和状态变更路径 |
| execute_mock_runtime | Gate results | invocation plan、mock output | 仅在允许条件下进入 mock 执行 |
| finalize_outcome | Policy/sink/execution bundles | FinalExecutionOutcome、final_status | 统一最终状态与执行标志 |

Runtime trace 采用 `ExecutionTraceRecord` 记录 stage、event、timestamp 和 details。trace 中会包含 request id、session id、feature、source role、parent request id 和 root user request id 等协议上下文。tools feature 正常进入 policy、sink 和 mock execution；non-tools feature 被识别但不执行，trace 中会出现 sink inspection skipped 或 execution not started 等事件。tools sink 路径会记录 `sink_context_constructed`，用于证明 lineage-aware sink context 已进入主路径。

需要明确的是，当前 runtime 是研究原型中的 mock runtime，不是完整真实 MCP transport。mock runtime 的作用是稳定地产生 invocation plan、execution outcome 和 artifact，便于评测和论文实验复现。真实 MCP server/client 集成属于后续工作。

## 3.13 Runtime/Eval 统一语义设计

在实验系统中，执行语义必须保持一致。如果 runner、metrics 和 failure report 分别解释 completed execution、execution degraded、intervention triggered、hard blocked、confirmation required 和 leak possible，则同一个 case 可能在不同报告中被归为不同状态。为避免这种漂移，系统引入 `runtime_semantics.py` 作为唯一执行语义中心。

核心模型 `ExecutionSemantics` 包含 decision_action、sink_action、executed、completed_execution、execution_degraded、intervention_triggered、hard_blocked、confirmation_required、escalation_triggered、blocked_by_decision、blocked_by_sink 和 leak_possible。核心函数 `compute_execution_semantics()` 先基于 decision action 和 sink action 推断动作语义，再用 runtime 真值覆盖 executed、completed_execution 和 execution_degraded 等执行事实字段。这样，动作语义与运行时事实被明确区分。

该模块特别强调若“未完成执行且触发干预”，则在没有显式 runtime override 的情况下应视为 execution_degraded。这一语义与 eval runner 的 benchmark 行为保持一致。`leak_possible` 采取保守定义：只有在执行完成且 decision/sink gates 没有阻断，并且 sink action 明确允许相关外发语义时，才可能被标记为 true。若缺少足够 sink 语义，系统宁可不扩大推断。

为了支持 artifact consistency，系统还定义了 `RUNTIME_SEMANTICS_VERSION`、`CASE_PACK_VERSION` 和 `SEAL_TAG`，并在 eval summary 与 report artifact 中写入 `semantics_version`、`case_pack_version` 和 `seal_tag`。`validate_execution_artifact_consistency()` 可以对 persisted artifact 重新调用语义函数，比较 completed_execution、execution_degraded、intervention_triggered 和 leak_possible 是否一致；该 validator 只返回 warning 或可控异常，不会自动回写历史 artifact。

这种设计将 runtime 与 eval 的语义边界显式化，使第 4 章中的 execution completion、intervention、hard block、confirmation 和 leak 指标具有统一来源。它也降低了后续 v1.1 分支增强时混用旧 artifact 的风险。

## 3.14 Evaluation、Metrics 与 Failure Report

Evaluation 层用于将系统行为转化为可复现实验结果。`attack_cases` 定义 case inventory，包括 attack/benign 标注、case family、attack type、expected action、expected risk、sink 配置和模块目标等信息。`runner` 逐 case 调用 runtime 与策略链路，生成 case-level result。`metrics` 对 case-level result 进行汇总，输出 match_rate、attack_success_rate、leak_rate、false_positive_rate、utility_loss、execution_completion_rate、intervention_rate、hard_block_rate 和 confirmation_rate 等主指标。

`failure_report` 用于分析 mismatch、successful attack、leak-prone、false positive、utility loss 和 trade-off cases。它基于统一 runtime semantics 判断执行完成和干预状态，并生成 `FailureCaseSummary`、module confidence、secondary module candidates 和 attribution evidence。该模块不改变主决策结果，而是为论文 case study 和失败归因提供结构化证据。

`ablation_report` 用于对 baseline、no_trust_tagging、no_metadata_validation 和 no_sink_guard 等配置进行横向比较。它读取各配置 summary 和 case result，生成包含 delta、受影响 case family、主导变化指标和解释字段的报告。该模块支撑第 4 章中的模块贡献分析，但不改变底层 metrics 口径。

此外，系统还实现了两个可选分析能力。`statistics` 提供 bootstrap confidence interval、paired comparison、family-level grouping 和 module-level grouping，用于后续统计可信度增强；`PatternMemory` 提供本地 JSONL 与 token overlap 检索，可为 failure report 附加 similar patterns。二者当前属于 optional artifact，不参与主决策链路，也不是当前主实验指标的来源。

表 3-5 总结了评测相关模块职责。

表 3-5 Evaluation 与 reporting 模块职责

| 模块 | 主要职责 | 是否影响主指标 |
|---|---|---|
| attack_cases | 定义固定 case pack 与 expected semantics | 是，作为 benchmark 输入 |
| runner | 执行 case 并生成 case-level result | 是，产生原始评测结果 |
| metrics | 汇总主指标 | 是，论文主表来源 |
| failure_report | 失败归因与 case study 证据 | 不改变指标，提供解释 |
| ablation_report | 模块消融比较 | 不改变指标，汇总比较 |
| statistics | 可选统计附录 | 默认不改变主指标 |
| PatternMemory | 可选相似案例召回 | 不参与主决策链路 |

这种 evaluation 设计的关键在于，指标计算、失败解释和可选分析被分离。主指标由 runner、runtime semantics 和 metrics 产生；failure report 与 optional artifact 只解释结果，不反向影响系统行为。

## 3.15 平台层与服务层实现

平台层基于 FastAPI 实现，用于提供可调用、可测试和可扩展的研究原型入口。应用入口采用 lifespan 模式，在启动时初始化共享 service，并挂载到 `app.state`。这些 service 包括 RuntimeService、EvaluationService、ReportService 和 AuditService。路由层通过 FastAPI dependency 从 `app.state` 获取 service，避免每个请求重复 new service，也为后续共享 registry、case pack cache 和 runtime policy kernel 提供基础。

RuntimeService 是对 MCPAgentClient 的薄封装，负责列出已注册工具、转发 legacy query 和 protocol request。EvaluationService 负责协调 local eval、ablation report、figure 和 failure report 等底层 eval 模块，不复制评测逻辑。ReportService 负责调用 failure report builder/exporter，并可注入 AuditService 记录报告生成事件。这样的服务层设计保持了 route 与底层模块之间的隔离，也减少了接口漂移。

API route 继续保持原有路径和 response envelope。健康检查、工具列表、runtime execute、evaluation run 和 reports 等入口不因服务层收口而改变外部结构。错误处理仍通过 PlatformError、RequestValidationError 和通用 Exception handler 输出稳定 error envelope。该设计使系统可以用于论文演示和自动化测试，同时不将平台层复杂性扩散到策略模块。

AuditService 从逐条同步写盘升级为轻量 JSONL buffer + flush/close 机制。`write_event()` 将事件规范化为 `AuditEvent` 并写入内存 buffer，达到阈值或显式 flush/close 时批量追加到 `audit_events.jsonl`。Sprint 2 修补后，flush 只有在写盘成功后才清空 buffer；close 只有在 flush 成功后才标记 closed；close 后继续写入会明确拒绝。这一机制提升了研究平台审计 artifact 的可靠性，但仍不是生产级审计队列或后台 worker 系统。

因此，平台层的定位是研究原型平台，而不是高并发生产服务。它提供生命周期管理、依赖注入、共享 service、统一响应和审计 artifact，为实验运行、报告导出和系统展示提供支撑。

## 3.16 系统实现特点与可扩展性

本系统的第一个实现特点是协议对象化。传统本地 mock 工具执行原型容易以 user query 为中心组织逻辑，而本系统将 runtime 入口提升为 `McpRequestEnvelope`，并通过 `RequestLineage` 传递 root request、parent request、feature scope 和 trust label。这为后续真实 MCP transport 接入提供了清晰边界。

第二个特点是显式 trust boundary modeling。系统将来源信任、工具身份、元数据漂移、能力声明、决策动作和 sink 行为分别建模，再由 runtime 统一编排。与单一 allow/deny 规则相比，这种分层建模更适合分析 prompt injection、metadata injection、tool shadowing、rug-pull 和 source-to-sink exfiltration 等复合攻击。

第三个特点是 evidence-tree decision。Decision Engine 不只输出 action，还输出 evidence tree 和 policy trace。每个最终动作都能追溯到规则节点、阶段结果和聚合原因。这一设计使策略系统更可解释、可测试，也能支撑 failure analysis 中的模块归因。

第四个特点是 runtime/eval 语义统一。ExecutionSemantics 将 action-level gate 与 runtime truth 分离，并统一解释 completed execution、execution degraded、intervention、hard block、confirmation 和 leak possible。该机制减少了 runner、metrics 和 failure report 的语义重复，提升了论文实验 artifact 的一致性。

第五个特点是可选分析能力与主链路分离。PatternMemory、statistics helper、RuntimeExecutionGovernance、SamplingRequestContext、RootsExposureContext 和 ElicitationContext 均已实现最小能力，但当前不被写成主实验指标来源。它们作为系统扩展能力展示和后续研究基础存在，不改变 v1.0 thesis baseline 的核心指标。

未来扩展方向包括：接入真实 MCP transport；将 capability policy 迁移为 YAML/TOML policy DSL；将 PatternMemory 从 token overlap 升级为 embedding-backed retrieval；基于 AnyIO 实现真实 structured concurrency 与 cancellation scope；构造更大规模 adaptive benchmark；引入 schema compatibility analysis；建立 scoped authorization chain 与更细粒度 sink policy。这些方向均可在现有架构上增量实现，而无需推翻当前主链路。

## 3.17 本章小结

本章围绕面向 MCP-enabled LLM Agents 的客户端侧信任边界强制机制，介绍了系统的总体设计与实现。系统以 MCP 协议对象为入口，将工具元数据、来源信任、能力声明、元数据漂移、决策证据和 sink 行为纳入同一运行时链路，并通过分层模块实现可解释的安全控制。

在数据边界层，系统通过 Pydantic 模型、API schema、响应 envelope、异常边界和 settings 收紧输入输出语义。在协议对象层，系统通过 McpRequestEnvelope、McpResponseEnvelope、RequestLineage 以及 sampling、roots、elicitation 上下文模型，将 MCP feature 显式化。在信任边界强制层，trust tagging、metadata validation、capability policy、decision engine 和 sink guard 共同完成来源判断、漂移检测、能力识别、证据聚合和执行面控制。

在运行时层，MCPAgentClient 将 legacy query 和 MCP request 统一到协议化处理流程中，并通过 trace_records 和 final_status 输出可审计结果。在评测层，runtime_semantics 统一执行语义，runner、metrics、failure_report 和 ablation_report 共同支撑实验复现与模块贡献分析。在平台层，FastAPI lifespan、app.state、Depends、薄 service 层和 AuditService JSONL buffer 使研究原型具备稳定调用与 artifact 管理能力。

需要强调的是，该系统仍定位为研究原型。它尚未实现完整真实 MCP transport、生产级并发调度、完整 adaptive attack 防御或工业级 provenance 系统。其主要贡献在于为 MCP-enabled agent 场景提供一个可解释、可测试、可复现的客户端侧 trust boundary enforcement 设计，并为第 4 章的实验结果分析奠定系统基础。
