# 第 2 章 相关技术与理论基础

## 2.1 大语言模型智能体概述

大语言模型最初主要被视为面向自然语言输入输出的文本生成系统，其核心能力体现在语言理解、内容生成、对话交互和知识整合等方面。传统对话式 LLM 的安全问题通常集中在输出内容层面，例如有害内容生成、事实错误、隐私泄露和越狱提示等。然而，随着模型被嵌入应用系统并获得工具调用、资源访问、长期上下文管理和外部服务交互能力，LLM 的角色逐渐从“文本生成器”演化为“智能体”（agent）[需补充引用：LLM Agent 安全综述]。

LLM Agent 与普通聊天模型的根本差异在于行动能力。普通聊天模型通常只返回文本，而 agent 系统可以感知外部上下文、规划任务步骤、选择工具、调用 API、读取资源、写入文件、修改配置或触发网络请求。此时，模型输出不再只是被用户阅读的自然语言，而可能成为外部操作的中间表示或直接参数。因此，安全问题也从“模型回答是否安全”扩展为“模型驱动的行为是否安全”。

在典型 agent 系统中，模型、工具、资源、外部服务、用户和运行时平台构成闭环。用户提出任务后，模型可能检索资源、选择工具、调用服务器、处理返回结果，再基于结果继续推理或执行后续操作。这个闭环提升了任务自动化能力，也使攻击输入能够在多个组件之间传播。例如，外部网页中的恶意文本可能被模型当作指令执行，工具返回值可能影响下一步工具选择，资源内容可能被拼接进后续调用参数。这些风险在纯文本问答系统中通常只影响回答内容，而在 agent 场景中可能进一步影响真实外部状态。

因此，LLM Agent 安全需要关注行为链路而非单轮输出。输入过滤、输出审查和系统提示约束仍然重要，但不足以覆盖工具选择、权限边界、资源读取、元数据可信度和 sink 外发路径等问题。本文关注的正是具备可调用工具和资源访问能力的执行型智能体，而不是仅进行自然语言问答的模型。该研究定位决定了后续章节需要围绕 trust boundary、metadata validation、capability policy、decision evidence tree 和 sink guard 等概念展开。

在工具调用和资源访问被标准化之后，agent 系统的安全问题又进一步转向协议边界。MCP（Model Context Protocol）正是此类标准化接口的代表之一，它为 LLM 应用与外部工具、资源和提示模板之间的交互提供结构化协议。因此，要分析 MCP-enabled LLM Agents 的安全问题，必须首先理解 MCP 的交互对象、能力范围和信任边界。

## 2.2 MCP 协议与工具调用机制

MCP 的基本目标是在 LLM 应用与外部环境之间提供标准化连接机制，使模型应用能够以统一方式发现工具、读取资源、使用提示模板，并在特定场景下通过 client-exposed capability 完成更复杂的交互 [MCP 规范]。从系统结构上看，MCP 通常涉及 host、client 和 server 三类角色。host 承载用户交互与应用环境，client 负责与 MCP server 建立连接并进行协议交互，server 则暴露工具、资源、提示或其他能力。

MCP server features 通常包括 tools、resources 和 prompts。tools 使模型能够调用外部函数或操作接口，因此直接扩展了模型的行动能力；resources 为模型提供上下文输入，如文件、文档、数据库记录或服务端资源内容；prompts 则提供可复用提示模板或交互结构。三者虽然功能不同，但都可能成为安全载体：工具描述会影响模型如何选择和调用工具，资源内容可能包含间接提示注入，prompt 模板可能携带不适当的控制语义。

MCP 还包含若干 client-side 或 client-exposed capability，例如 sampling、roots 和 elicitation。sampling 允许 server 通过 client 请求模型生成，从而使 server 间接影响模型调用；roots 表达 client 可暴露给 server 的本地或工作区根路径，涉及资源范围和暴露边界；elicitation 则涉及 server 向用户请求额外信息，关系到用户交互、敏感字段和授权语义。这些能力进一步说明 MCP 不只是“工具调用接口”，而是一个跨越用户、客户端、模型和服务器的交互协议集合。

表 2-1 概括了主要 MCP feature 及其安全关注点。

表 2-1 MCP feature 与安全关注点

| MCP feature | 所属侧 | 主要作用 | 可能的安全关注点 |
|---|---|---|---|
| tools | server feature | 暴露可调用工具或操作接口 | 工具投毒、隐藏调用、过度权限、危险参数 |
| resources | server feature | 向模型提供外部上下文资源 | 间接提示注入、不可信内容传播、敏感信息混入 |
| prompts | server feature | 提供提示模板或交互模式 | 恶意模板、指令边界混淆、策略绕过 |
| sampling | client-exposed capability | server 通过 client 请求模型生成 | server 诱导模型调用、用户意图绑定不足 |
| roots | client-exposed capability | 暴露本地或工作区根路径范围 | 资源暴露过宽、路径越权、边界不清 |
| elicitation | client-exposed capability | server 向用户请求信息 | 敏感字段收集、用户同意语义不明确 |

需要强调的是，协议标准化不等于安全边界自动完备。MCP 提供的是连接、发现和交互规范，它有助于统一工具和资源接入方式，但不会自动判断某个工具是否可信、某段资源是否包含恶意指令、某次 sampling 是否与合法用户请求相关，也不会自动保证 sink 外发行为安全。因此，在 MCP-enabled agent 场景中，安全系统必须在协议交互之外建立额外的信任边界判断机制。

本文研究的 client-side trust boundary enforcement 正是针对这一问题。客户端处于用户意图、模型行为和 server-provided capabilities 的交汇处，能够观察请求来源、工具元数据、资源上下文、执行动作和 sink 路径。相比只在 server 侧或模型提示层做约束，client 侧更适合统一执行来源信任分析、metadata validation、capability policy、decision evidence tree 和 sink control。

## 2.3 LLM Agent 面临的主要安全威胁

LLM Agent 面临的安全威胁比普通 LLM 更复杂，原因在于攻击目标不再局限于输出文本，而是扩展到工具选择、外部调用、资源读取、状态变更和数据外发。攻击者可以利用自然语言、工具描述、资源内容、API 返回值或协议能力声明影响模型推理过程，并进一步驱动 agent 执行高风险操作 [OWASP LLM Top 10]。

这些威胁通常具有跨组件传播特征。恶意输入可以首先表现为普通文本，但随后进入 prompt 上下文、影响工具选择、改变调用参数，最终流向网络请求、文件写入或状态变更等 sink。与传统 Web 输入验证不同，agent 场景中的中间转换由模型推理完成，攻击意图可能被改写、摘要、分片或嵌入工具参数，因此单点过滤难以覆盖完整链路。

表 2-2 总结了本文关注的主要威胁类型、攻击入口和影响路径。

表 2-2 LLM Agent 主要安全威胁

| 威胁类型 | 攻击入口 | 影响路径 | 与本文关系 |
|---|---|---|---|
| Prompt Injection | 用户输入或提示内容 | 混淆系统指令与数据内容 | 需要 trust tagging 与 decision policy 限制传播 |
| Indirect Prompt Injection | 外部文档、网页、资源、工具返回值 | 不可信资源进入模型上下文后影响行为 | 需要 source provenance 与 metadata/context 检查 |
| Tool Poisoning | 工具描述、schema、提示模板 | 恶意元数据诱导错误工具选择或危险参数 | 需要 metadata validation 和 capability policy |
| Tool Shadowing | 相似名称、相似 schema、伪造 provider | 模型或 client 混淆工具身份 | 需要 ToolRegistry 与身份历史审计 |
| Rug-pull / Tool Mutation | 工具版本、origin、schema 漂移 | 初始可信工具后续变为危险工具 | 需要 snapshot 与 drift 检测 |
| Source-to-Sink Exfiltration | 敏感 source 或不可信 source | 被模型转化为外发 payload | 需要 sink guard 控制执行前路径 |
| Excessive Agency | 过宽工具权限或自动执行策略 | agent 超出用户意图执行操作 | 需要 capability policy 与 confirmation/escalation |
| Sensitive Information Disclosure | 资源、凭证、日志、上下文 | 敏感信息进入输出或外发通道 | 需要 source/sink 双端控制 |
| Capability Chaining | 多工具组合、委托调用 | 单个低风险能力组合成高风险链路 | 需要 evidence tree 聚合多模块证据 |
| Authorization / Consent Bypass | 用户确认、授权链、elicitation | 操作未获得充分同意或越过授权范围 | 需要显式确认门与授权语义建模 |

上述威胁的共同特点是“入口多样、传播隐蔽、影响外部化”。例如，Tool Poisoning 的入口是元数据，但影响对象可能是模型的工具选择；Indirect Prompt Injection 的入口是资源内容，但最终可能触发网络发送；Authorization Bypass 的入口可能是模糊用户意图，但结果可能是状态变更。因此，本文不能只研究提示过滤，而需要在 client runtime 中构建跨模块的信任边界强制机制。

本文后续章节中的 trust tagging、metadata validation、capability policy、decision evidence tree 和 sink guard 分别对应这些风险链路的不同位置。trust tagging 关注来源可信度，metadata validation 关注工具声明与历史演化，capability policy 关注工具能力，decision evidence tree 关注多证据聚合，sink guard 关注执行前外发和状态变更控制。该分层关系构成本文系统设计的理论基础。

## 2.4 Prompt Injection 与 Indirect Prompt Injection

Prompt Injection 的本质是指令与数据边界混淆。模型在处理自然语言上下文时，往往难以从语义上严格区分“应当遵循的指令”和“仅供分析的数据”。攻击者可以在输入中插入伪装成系统指令、开发者消息或操作建议的文本，诱导模型忽略原有约束、泄露敏感信息或执行非预期行为 [需补充引用：Indirect Prompt Injection 研究]。

Direct Prompt Injection 主要来自用户显式输入，例如用户直接要求模型忽略系统规则、泄露隐藏提示或绕过安全策略。在传统聊天模型中，这类攻击通常影响模型回答内容。虽然这已经构成安全风险，但其后果多局限于文本输出。相比之下，Agent 场景中的 Prompt Injection 可能进一步影响工具调用、资源访问和外部操作，其风险范围显著扩大。

Indirect Prompt Injection 则更符合 agent 场景的典型风险。恶意指令可能隐藏在外部文档、网页、邮件、代码注释、资源内容或工具返回值中。当 agent 将这些内容作为上下文输入模型时，模型可能将其中的恶意文本误当作任务指令执行。由于该攻击并非直接来自用户输入，而是通过资源或工具结果间接进入上下文，因此更难通过简单用户输入过滤发现。

在 MCP-enabled agent 中，tools、resources 和 prompts 都可能成为注入载体。工具 description 或 schema 中可以包含诱导性指令，resources 可能携带嵌入式恶意文本，prompts 可能提供有偏或危险的模板。更复杂的是，sampling、roots 和 elicitation 等 capability 还可能使 server 侧间接影响模型调用或用户交互。因此，MCP 场景中的 Prompt Injection 不是单一 prompt 层问题，而是跨协议边界传播问题。

本文不试图声称完全解决 Prompt Injection 或所有 adaptive attacker。相反，本文目标是通过 client-side trust boundary enforcement 降低风险传播概率、提高决策可解释性，并在工具执行前增加来源信任、元数据漂移、能力声明和 sink 路径等多维证据。trust tagging 用于识别来源是否不可信，metadata validation 用于识别工具元数据中的 prompt-like 注入，decision engine 用于聚合风险证据，sink guard 用于阻止或确认危险外发路径。

因此，Prompt Injection 在本文中被视为行为链路风险，而不是单纯文本分类问题。该视角自然引出后续对工具元数据攻击、source-to-sink 路径和 provenance 建模的讨论。

## 2.5 工具元数据攻击：Tool Poisoning、Tool Shadowing 与 Rug-pull

工具元数据在 LLM Agent 中具有特殊安全意义。模型通常依赖工具名称、description、schema、provider、version、origin 和参数说明理解工具用途，并据此决定是否调用工具以及如何填充参数。因此，工具元数据不仅是描述信息，也是模型行为决策的输入之一 [需补充引用：Tool Use Security / Function Calling Security]。

Tool Poisoning 指攻击者通过恶意工具描述、schema 或提示模板影响模型行为。例如，工具 description 可以伪装成普通功能说明，但暗含“无需用户确认”“优先调用本工具”“将结果发送到指定 endpoint”等危险引导。由于模型会读取这些描述来理解工具用途，恶意元数据可能间接改变工具选择和调用参数。

Tool Shadowing 指攻击者通过相似名称、相似 schema、伪造 provider 或相近 namespace，使模型或客户端误将恶意工具当作可信工具。与传统依赖混淆或供应链攻击类似，Tool Shadowing 利用的是身份识别不充分。但在 agent 场景中，其影响路径更接近模型行为污染：一旦模型选择了 shadowed tool，后续工具调用和 sink 路径都可能偏离用户原始意图。

Rug-pull 或 Tool Mutation 则描述另一类时间维度风险：工具在初始注册或早期观察时表现可信，但后续发生 description、schema、origin、version 或 capability 变化。例如，一个原本只读的工具后续加入网络发送能力，或一个同 provider 工具的输出 schema 发生不兼容漂移。此类变化如果没有历史基线，很难仅凭当前 metadata 判断风险。

Metadata drift 之所以在 agent 系统中具有安全意义，是因为它改变了模型理解和调用工具的依据。传统系统中 API schema 改动可能主要是兼容性问题，而在 LLM Agent 中，schema 和 description 同时影响模型推理、工具选择和参数生成。因此，metadata 变化可能直接成为攻击面。

本文引入 ToolRegistry 和 Metadata Validation 正是为了处理这一类风险。ToolRegistry 提供工具身份历史和 metadata snapshot，Metadata Validation 则检测 description drift、schema drift、origin drift、provider/namespace drift、version rollback、prompt-like metadata injection 和 protocol capability advertisement drift。二者共同构成非执行面防线，为 decision evidence tree 提供关键证据。

## 2.6 Source-to-Sink 外泄路径与 Sink 控制

Source-to-sink 是信息流安全中的重要概念。source 表示数据来源，可以是敏感信息来源，也可以是不可信输入来源；sink 表示可能产生外部影响的位置，如网络发送、文件写入、状态变更、外部 callback、日志写出或第三方服务调用 [需补充引用：Provenance / Trust Boundary 基础研究]。传统安全系统通常通过 taint tracking、信息流控制或输入输出校验限制高风险数据从 source 流向 sink。

在 LLM Agent 中，source-to-sink 路径更难分析。模型可能读取外部资源、摘要内容、结合用户请求重新组织信息，再将其转化为工具调用参数。此时，source 内容不一定以原文形式出现在 sink payload 中，可能经过改写、压缩、分片或隐藏在结构化参数里。因此，仅检测输入文本是否包含敏感词或恶意指令不足以保障安全。

图 2-1 给出了 Agent 场景下 source-to-sink 路径的简化流程。

图 2-1 Source-to-Sink 外泄路径示意：

```text
Untrusted / Sensitive Source
        ↓
Agent Reasoning / Tool Selection
        ↓
Capability & Decision Policy
        ↓
Sink Operation
        ↓
External Effect / Data Exfiltration
```

该流程说明，不可信或敏感 source 首先进入 agent reasoning，再影响工具选择与参数生成，随后经过 capability 与 decision policy，最终可能流向 sink operation。如果 sink 是 external endpoint、file write、state change 或 callback，则该行为可能产生外部影响或数据外泄。因此，安全控制不能只停留在输入侧，也必须在执行前对 sink 行为进行检查。

本文中的 sink guard 正是基于这种 source-to-sink enforcement 思路。它关注网络发送、文件写入、状态变更、凭证访问和外部 callback 等执行面路径，并结合 endpoint class、payload sensitivity、fragment suspicion、staged exfiltration markers、upstream trust label 和 user authorization chain 进行判断。其目标不是阻止所有 sink，而是在高风险 sink 上触发 deny、require_confirmation 或其他中间控制。

Sink 控制也是安全—可用性权衡最集中的位置。过松的 sink policy 可能导致外泄或未授权状态变更，过严的 sink policy 则可能干扰正常 workflow，例如授权配置写入、内部同步或 allowlisted callback。因此，本文在后续实验中不仅关注攻击成功率，也关注 false positive、utility loss、intervention rate 和 completion rate 等指标。

## 2.7 Trust Boundary 与 Provenance 建模

Trust boundary 指系统中不同信任域之间的边界。在传统软件系统中，常见边界包括用户输入与服务端逻辑、内部网络与外部网络、受信组件与第三方组件等。在 LLM Agent 场景中，trust boundary 更加细粒度和动态化：user、host、client、server、tool、resource、model context、external sink 之间都可能形成不同信任域。

单一输入过滤难以覆盖跨边界传播问题。一个请求可能最初来自可信用户，但其执行过程中读取了不可信网页；一个工具可能由可信 server 提供，但其 description 后续发生漂移；一个 sampling 请求可能由 server 触发，但需要追溯是否与 root user request 相关。若系统只看当前 payload，而不记录来源和传播链，就难以判断该操作是否仍处于合法信任边界内。

Provenance 与 lineage 建模用于解决这一问题。Provenance 关注数据或请求从何而来、经过哪些转换、由哪些组件派生；lineage 则更强调请求之间的父子关系、root user request 和跨协议 feature 的关联。通过 provenance，系统可以判断某个请求是否具有 untrusted ancestor；通过 lineage，系统可以判断某个 tool invocation、sampling request 或 sink payload 是否仍可追溯到合法用户意图。

在 MCP 场景中，sampling、tool invocation 和 sink payload 都需要 lineage 视角。sampling 请求如果无法关联 root user request，可能意味着 server 正在诱导模型调用；tool invocation 如果来自不可信资源内容，可能反映 indirect prompt injection 的传播；sink payload 如果由 untrusted upstream content 派生，则应进入更严格的外发控制。

本文引入 RequestLineage、ProvenanceEdge 和 RequestLineageGraph 等概念，正是为了表达这些跨边界关系。第 3 章将进一步说明这些概念如何在系统中被实现为协议对象、lineage graph、registry context 和 lineage-aware sink context。本章只强调其理论动机：Agent 安全不能只判断当前请求，还必须判断请求的来源、传播路径和信任继承关系。

## 2.8 安全策略决策与可解释防御

传统访问控制常以 allow/deny 二元决策为核心，但 LLM Agent 安全面临的风险往往并非绝对黑白。某些操作显然应被拒绝，例如隐藏调用或直接敏感信息外发；某些操作则可能在用户确认、授权范围或 sandbox 限制下执行；还有一些操作需要升级给更高权限主体或人工审查。因此，Agent 安全策略需要比二元决策更丰富的动作空间。

本文关注的决策动作包括 allow、deny、require_confirmation、escalate、sandbox、redact 等。require_confirmation 用于表达“风险存在但可由用户确认后继续”的中间状态；escalate 用于表达当前上下文不足以自动处理，需要更高层审查；sandbox 和 redact 则用于限制执行或输出范围。这些动作使系统能够在安全性和可用性之间形成更细粒度的控制，而不是将所有不确定场景都直接阻断。

RiskLevel 同样是必要概念。低风险、中风险、高风险和 critical 风险对应不同处理策略，也用于组合不同模块的证据。例如，来源不可信本身可能不足以 deny，但当它与高风险 capability 或 metadata drift 叠加时，就可能触发 escalate 或 confirmation。风险等级使策略系统能够表达“多个弱信号组合成强信号”的情况。

表 2-3 给出了本文使用的主要决策动作及其理论含义。

表 2-3 安全决策动作及适用场景

| 决策动作 | 含义 | 适用风险场景 |
|---|---|---|
| allow | 允许继续执行 | 未发现显著风险或风险已被充分约束 |
| deny | 直接阻断 | hidden invocation、direct exfiltration、critical drift 等高置信风险 |
| require_confirmation | 要求用户确认 | 高风险但可由显式授权缓解的操作 |
| escalate | 升级审查 | 不可信来源叠加非低风险、上下文不足以自动决策 |
| sandbox | 限制执行环境或能力范围 | 中等风险组合、需要隔离执行的操作 |
| redact | 限制或替换输出内容 | 输出包含敏感信息或需要降级展示的场景 |

可解释性是安全决策的重要要求。若系统只输出 deny 或 allow，后续很难判断是来源信任、metadata drift、capability inference 还是 sink path 触发了该动作。对于研究原型而言，这会削弱 failure analysis、消融实验和论文解释的可信度。对于实际系统而言，不可解释决策也会增加用户和开发者理解成本。

因此，本文采用 evidence tree / policy trace 的理论动机，是将规则触发、理由、证据和责任归因显式表达。Evidence tree 并不是简单日志，而是把每个阶段的 proposed action、risk level 和 reasons 组织为可审计结构。这样，后续实验可以解释某个 case 为什么被干预，也可以分析某个模块在消融后为何导致攻击成功率或 utility loss 变化。

## 2.9 安全评测、消融实验与 Adaptive Attacker

Agent 安全系统需要系统化 benchmark。单个示例无法说明系统是否真正提升安全性，也无法区分某个模块的贡献。由于 agent 风险涉及工具调用、资源输入、metadata drift、source-to-sink 路径和用户授权语义，评测集必须覆盖攻击样本、benign 样本和 gray-zone benign 样本。否则，系统可能通过过度阻断获得较低攻击成功率，却在正常任务中造成不可接受的可用性损失。

常见安全指标包括 attack success rate、false positive rate、utility loss、intervention rate 和 completion rate 等。ASR 用于衡量攻击路径成功绕过干预的比例；FPR 反映 benign 或 gray-zone benign 被过度干预的程度；utility loss 表示安全策略对正常任务完成的影响；intervention rate 表示系统触发 deny、confirmation、escalation 或类似动作的频率；completion rate 则表示任务最终完成执行的比例。这些指标必须联合解释，不能单独判断系统优劣。

消融实验用于评估模块贡献。若只观察完整系统表现，难以判断 trust tagging、metadata validation 或 sink guard 分别提供了多少防御作用。通过 baseline 与 no_trust_tagging、no_metadata_validation、no_sink_guard 等配置比较，可以观察去除某个模块后 ASR、FPR、utility loss、intervention rate 和 completion rate 的变化，从而分析模块在安全性与可用性权衡中的作用。

Adaptive attacker 是评测 agent 安全时必须考虑的概念。攻击者并不会始终使用显式危险关键词，而可能采用同义改写、语义弱化、分片传输、混淆编码或多步链路绕过静态规则。所谓 attacker moves second 的方法论强调，在防御规则公开或可推测的情况下，攻击者可以调整输入形式以适应防御 [需补充引用：Adaptive Attack Evaluation]。这对基于规则的 capability policy 和 metadata validation 构成挑战。

本文采用 baseline 与模块消融的方式，不是为了证明系统完全防御 adaptive attackers，而是为了系统化评估不同防线对攻击成功率和可用性代价的贡献。后续 failure analysis 进一步用于识别剩余攻击路径、误报来源和 trade-off cases。这种评测方法与本文的研究定位一致：构建一个可解释、可测试、可复现的 client-side trust boundary enforcement 原型，并诚实呈现其剩余风险。

因此，第 4 章中的实验设计并不是简单指标汇总，而是围绕威胁模型、模块贡献和安全—可用性权衡展开。第 2 章所讨论的 Prompt Injection、metadata attack、source-to-sink、provenance 和 evidence tree，构成这些实验指标和 failure analysis 的理论基础。

## 2.10 本章小结与本文研究定位

本章从 LLM Agent 的演化出发，说明了安全问题如何从传统对话式模型中的输出安全扩展为执行型智能体中的行为安全。Agent 一旦具备工具调用、资源读取和外部操作能力，攻击输入就可能不再停留于文本输出，而是进一步影响工具选择、调用参数、状态变更和数据外发。

MCP 为 LLM 应用与工具、资源、提示模板以及 client-exposed capability 之间提供标准化接口，但协议标准化并不自动提供完整安全边界。tools、resources、prompts、sampling、roots 和 elicitation 分别引入不同形式的信任边界问题，需要在 client 侧进行额外建模与约束。本文正是在这一背景下研究 MCP client-side trust boundary enforcement。

本章还分析了 Prompt Injection、Indirect Prompt Injection、Tool Poisoning、Tool Shadowing、Rug-pull、Source-to-Sink Exfiltration、Excessive Agency、Sensitive Information Disclosure、Capability Chaining 和 Authorization / Consent Bypass 等威胁。这些威胁共同说明，单一 prompt 过滤或单一 allow/deny 决策不足以保障 agent 行为安全。

为应对上述风险，本文采用来源信任分析、元数据验证、能力识别、provenance / lineage 建模、evidence tree 决策、sink control、模块消融和 failure analysis 等方法。其研究定位是在 MCP client 侧构建一个可解释、可测试、可复现的信任边界强制原型，而不是声称实现生产级安全网关、完整真实 MCP transport 或完全防御所有 adaptive attacks。

第 3 章将在本章理论基础之上，进一步介绍系统设计与实现，包括协议对象层、ToolRegistry、trust tagging、metadata validation、capability policy、decision evidence tree、sink guard、runtime/eval semantics 和平台服务层。第 4 章将基于正式实验结果，对系统有效性、模块贡献、失败案例和安全—可用性权衡进行分析。
