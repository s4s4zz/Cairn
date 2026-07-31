# Java 审计语义运行时可核查性升级计划（AutoCVE / DeepAudit 对标）

**状态：** Proposed

**日期：** 2026-07-31

**修订：** 2026-07-31 评审后重排交付顺序

**适用对象：** 子项目五、六交付的语义审计与独立盲审运行时：
`cairn/src/cairn/semantic/`（Semantic Reviewer）、
`cairn/src/cairn/verify/`（Independent Reviewer）以及两者共用的
`semantic/conversation.py` 会话驱动。

**本次交付范围：**

1. 先完成契约兼容、敏感数据策略、Artifact 生命周期与 CI/发布门槛；
2. 再依次交付 P3 工具轨迹、P2 拒绝分类、P1 有界修复、P4 有界并发；
3. P5 确定性知识包与 P6 复核期追问移出本计划，分别独立立项。

本计划不新增漏洞类别、确定性探针或 Sink 规则，不改变 Finding 晋升规则，也不
放宽 §7.5 语义输出契约。工具轨迹只能证明平台观察到哪些调用及结果，**不能证明
模型理解、采纳或认真阅读了这些结果**；报告不得把访问轨迹表述成认知证明。

**与假设-验证回路计划的关系：**
[有界假设-验证回路](2026-07-29-java-audit-hypothesis-verification-loop.md)
是动态验证之后的外层回边。本计划 P1 是一次语义会话内部、默认关闭的输出修复，
两者不共享轮次或状态。外层回路不得看到上一轮自然语言推理；P1 为定位被拒条目，
会保留模型自己的上一轮结构化回答，但平台只反馈机器可读校验错误，不加入方向性
建议。

**与工作台过程可见性计划的关系：**
[运行过程表达优化](2026-07-29-java-audit-workbench-process-visibility.md)
已经呈现运行级和任务级数据。本计划只为其新增经过脱敏的 scope 级汇总；完整调用
轨迹保持 Sensitive，不进入普通 Coverage 或报告正文。

**对标来源：**

- [AutoCVE 架构文档（固定提交）](https://github.com/larlarua/AutoCVE/blob/2fed828f2321cb7d718aadbccbfededeb03756b0/docs/ARCHITECTURE_DESIGN.md)
- [DeepAudit README v3.0.4（固定提交）](https://github.com/lintsinghua/DeepAudit/blob/833d8580340d7fceb88dc3999b10a86fd46cd78d/README.md)

外部项目的产出数字是其项目方公开陈述，不是 Cairn 的效果证据。若后续复制代码、
prompt、规则或知识内容，必须另外记录来源提交、许可证与内容摘要。

---

## 1. 结论与交付单元

AutoCVE 的 Agent Runtime 在会话状态、工具调用记录、终止原因和有界纠错方面有
可借鉴之处；DeepAudit 展示了审计过程可见性与知识辅助的产品价值。Cairn 借鉴的是
工程机制，不是二者允许 Agent 自主扩展能力或直接确认漏洞的信任模型。

本计划包含四个前置门槛和四个能力增量：

| 编号 | 交付项 | 目标 | 默认状态 |
| --- | --- | --- | --- |
| G0 | 契约兼容与滚动升级 | 新旧 Worker/Orchestrator 可共存、可回滚 | 强制 |
| G1 | 敏感数据分级与最小化 | 完整轨迹不泄露到 Coverage、报告或普通日志 | 强制 |
| G2 | Artifact 保留、删除与 GC | 轨迹增长有上限，删除可重试、可观测 | 强制 |
| G3 | CI、镜像与发布门槛 | 每次变更可验证、镜像可定位、回滚有目标 | 强制 |
| P3 | 语义工具调用轨迹 | 记录可核查的访问事实并生成安全汇总 | 开启 |
| P2 | 拒绝原因分类与数据链路 | 让丢弃原因可聚合、可报告、可改进 | 开启 |
| P1 | 契约拒绝的有界修复 | 降低表述缺陷造成的漏报 | 默认关闭 |
| P4 | 单轮多工具有界并发 | 在不削弱超时和预算的前提下降低墙钟时间 | 默认关闭 |

以下两项只保留决策记录，不属于本计划的实现或验收范围：

| 编号 | 独立立项 | 独立立项原因 |
| --- | --- | --- |
| P5 | 索引证据驱动的确定性知识包 | 现有 inventory 缺 Shiro/Fastjson、依赖版本及包供应链契约 |
| P6 | 复核期追问 | 需要新的敏感 Transcript、RBAC、保留策略和模型任务协议 |

硬顺序为：

```text
G0 契约兼容
  -> G1 敏感数据策略
  -> G2 Artifact GC
  -> G3 CI / 发布 / 回滚
  -> P3 敏感轨迹与安全汇总
  -> P2 完整分类与数据链路
  -> P1 默认关闭后灰度
  -> P4 Broker 修复后的有界并发
```

任何后续项不得以“代码已写完”为由绕过前一项的验收门槛。

---

## 2. 已核实的现状

以下事实均已对照 2026-07-31 的
`java-audit-subprojects-2-4` 分支代码核实。

### 2.1 输出拒绝没有修复机会

`SemanticReviewer.run` 当前执行
`explore()` -> `request_final_answer()` -> `parse_findings()`，只判定一次。
`IndependentReviewer` 对单个 verdict 同样只判定一次，但其失败语义是
`inconclusive`，不是 item rejection；首期 P1 不得把两者视为同一协议。

### 2.2 item 拒绝只有两个粗粒度原因

语义 Finding 的 item rejection 目前只使用
`SEMANTIC_OUTPUT_INCOMPLETE` 和 `SEMANTIC_OUTPUT_INVALID`。真实抛出点还包括：

- 顶层 payload 或 finding 结构错误、item 超限；
- 缺位置、调用链、可控性或其他必填叙述字段；
- 调用链起止角色错误、步骤不唯一、未抵达声明的 Sink；
- 路径不在 Snapshot、行号越界、位置字段类型错误；
- Pydantic 字段约束、枚举或未知字段错误。

当前契约允许 `cwe_ids=[]`，`category` 也只要求非空，因此
`NO_CWE` 和 `CATEGORY_UNKNOWN` **不是现有拒绝原因**。若未来要禁止空 CWE 或校验
category 闭集，必须作为单独的输出契约变更评审，不能伪装成原因码细化。

### 2.3 工具调用没有持久化

`ToolConversation` 只累计调用数量。Sandbox 输出只包含最终 result，因而零 Finding
scope 没有访问轨迹。新增轨迹能证明调用被派发及返回，不能证明模型实际使用了结果。

### 2.4 Broker 不能直接全并发

Broker 虽然只读 Snapshot，但仍有共享可变状态：

- 惰性 `_catalog`、`_inventory` 和 `_auth_bindings_cache`；
- `_call_count`；
- `search` 使用只在主线程生效的 `SIGALRM` 墙钟超时。

因此将现有 `invoke` 直接放入线程池会产生初始化竞态，并使 `search` 在线程中失去
正则超时保护。P4 必须先消除这些条件，不能以“只读”等同于“线程安全”。

### 2.5 工具参数可能包含仓库字节

`search.pattern`、`find_symbol.name`、route、symbol、path 和 module 都由模型生成。
模型可以把前一轮 `tool_result` 中看到的源码、密钥或业务标识原样放入下一次参数。
因此完整 arguments 与源码 Snapshot 同属 Sensitive 数据。

### 2.6 现有 Artifact 生命周期不完整

Sandbox Artifact 登记时通常不设置 `expires_at`，仓库内没有通用 Artifact GC。
删除 AuditRun 会删除数据库中的 Artifact 行，但没有可靠地删除内容寻址存储里的
对象。原文“随现有保留策略清理”的前提不存在。

### 2.7 现有 CI 不覆盖本计划

当前唯一 GitHub Actions workflow 监听旧的 `container/**` 路径，并使用当前仓库
不存在的 `./container` 构建上下文。它不会验证 Python、Web、迁移或
`sandbox-images/`，也不能为本计划提供可回滚的镜像 digest。

---

## 3. G0：契约兼容与滚动升级

G0 先建立兼容层，之后 P2/P1 才允许修改输出结构。

### 3.1 版本策略

- 新增 `cairn-semantic-result-v2`，保留 v1 reader。
- 若未来为 Independent Reviewer 增加修复协议，单独新增
  `cairn-verify-result-v2`；本计划首期不改 verify v1 的判定语义。
- 新增 Artifact 内部契约时分别命名，例如
  `cairn-semantic-tool-trace-v1` 与
  `cairn-semantic-trace-summary-v1`，不得借用 result 版本号。
- 严格模型继续 `extra="forbid"`；兼容通过显式 v1/v2 模型和 dispatcher 完成，
  不通过放松校验完成。

### 3.2 发布顺序

1. **兼容发布 C：** 数据库只做 expand 型迁移；Orchestrator 同时读取 v1/v2，
   Worker 仍只写 v1。
2. 验证 C 能读取历史 v1 Artifact、测试生成的 v2 Artifact 和混合任务结果。
3. **功能发布 F：** Worker 在 feature flag 开启时写 v2；默认 flag 仍关闭。
4. 排空旧 Worker 与在途任务后，才允许把 v2 设为默认。
5. 回滚目标至少是兼容发布 C，不能回滚到只认识 v1 的更早版本。

数据库迁移只增加 nullable/defaulted 字段或新表，首期不删除旧字段。降级不回滚
schema；已生成的 repair provenance 和 trace 引用必须保留。

### 3.3 Finding provenance

P1 需要在 Candidate 到 Finding 的链路保留按来源分组的不可变机器数据。Finding
不得只保存一组标量，因为同一 Finding 可能由多个 semantic scope、盲审或扫描器
候选合并。新增 `provenance.semantic_sources[]`，每个条目至少包含：

```text
source_task_id
subject_type
subject_key
source_ordinal
semantic_result_contract
repair_rounds_used
repaired_after_rejection
initial_rejection_codes
```

条目以 `(source_task_id, semantic_result_contract, source_ordinal)` 唯一；重放时按
该键幂等合并，不覆盖其他来源。该数据不拼入 `description`、`discovered_by` 或
自然语言 Evidence。API 与 UI 只读展示，人工复核不能改写其来源事实。

### 3.4 兼容性定义

`MAX_REPAIR_ROUNDS=0` 的目标改为**业务行为兼容**：

- 同一固定模型响应产生相同 findings、rejections 和 Coverage 数字；
- 不额外发起模型请求；
- 不改变 Finding 晋升和去重结果。

新增 contract 字段意味着输出字节可以不同，不再承诺“逐字节一致”。

混合 v1/v2 AuditRun 的聚合必须保留 contract 维度。v1 的两个粗粒度原因进入
`v1_coarse` bucket，不推断成 v2 细分类；只要存在无法重算的 v1 结果，
`classification_complete=false`。发布验收既要证明“能读”，也要证明混合聚合
不会伪造精度。

---

## 4. G1：敏感数据策略

### 4.1 两层数据模型

P3 产生两种严格分离的数据：

| 数据 | 内容 | 访问级别 | 消费者 |
| --- | --- | --- | --- |
| 完整 Trace Artifact | arguments、调用 ID、结果长度、错误码、耗时 | Sensitive | 有敏感 Artifact 权限的人工核查者 |
| Trace Summary | 按工具/结果的计数、唯一读取文件数、完整性状态 | 普通 Coverage 等级 | Coverage、报告、工作台 |

完整 Trace 不记录 `tool_result` 正文，但仍按 Sensitive 处理。Summary 不得包含
path、pattern、glob、symbol、route、module、错误详情或任何自由文本参数。

### 4.2 最小化与边界

- arguments 使用 Broker 已验证后的规范化结构；原始未知键和超长值不写入 Trace。
- 无效参数只记录参数字段名、长度、类型和稳定错误码，不原样记录攻击者可控值。
- Broker 拒绝只记录 `BrokerError.code`；面向模型的自由文本 message 不进入 Trace。
- 每条记录和整个 Artifact 都有字节上限；超过上限时停止记录正文，Summary 标记
  `trace_truncated=true`，不得静默丢弃。
- 普通应用日志只记录 task ID、seq、tool name、outcome 和 Artifact ID，不记录
  arguments。
- Trace 下载复用 Sensitive Artifact 的 RBAC，并产生既有
  `ARTIFACT_DOWNLOADED` 操作日志。

### 4.3 安全汇总定义

Summary 至少包含：

```text
contract
subject_type
subject_key
calls_requested
calls_dispatched
calls_completed
calls_refused
calls_by_tool
outcomes
successful_read_file_calls
unique_files_read
trace_complete
trace_truncated
trace_artifact_id
```

`unique_files_read` 只输出数字，不输出路径。报告措辞使用“观察到 N 次成功文件读取”
而不是“模型已阅读 N 个文件”。

---

## 5. G2：Artifact 保留、删除与 GC

### 5.1 保留规则

- Semantic Trace 使用独立 `ArtifactKind`，创建时必须设置非空 `expires_at`。
- 默认保留期由管理员配置并写入 AuditRun 的有效 policy；首期默认 30 天。
- 法务保留或人工锁定必须是显式状态，不能通过把 `expires_at` 留空暗示。
- Summary 随 AuditRun 保留；完整 Trace 到期后，Summary 保留
  `trace_available=false` 和原 Artifact 摘要，不伪装成从未产生过。

### 5.2 删除队列

数据库事务与对象存储删除不能假装成一个原子操作。新增持久化删除队列：

1. Artifact 到期或 AuditRun 删除时，先把该 Artifact 引用标记为待删除，并在同一
   数据库事务中登记 `(artifact_id, storage_key)` 删除任务；
2. GC Worker/CLI 以有界 batch 领取任务；
3. 以 `storage_key` 加数据库锁并原子复查所有 Artifact 引用；仍有未到期、未删除
   或 legal hold 引用时，只完成当前引用的 tombstone，不删除共享对象；
4. 确认零活跃引用后标记对象为 `deleting`，新 Artifact 登记必须使用同一锁，不能
   附着到 `deleting` 对象；
5. 调用 `ArtifactStore.delete`，对象不存在按成功处理；
6. 成功后完成对象 tombstone；失败记录次数、最近错误和下次重试时间。

进程在对象删除后、数据库提交前崩溃时，下一次重试必须幂等完成。不得先删除唯一的
metadata 再期望从数据库找回 storage key。首期 AuditRun 只要包含 legal hold
Artifact，删除请求整体返回冲突，必须先显式解除 hold，不能由级联删除绕过。

### 5.3 可观测性

至少暴露：

- 待删除对象数和估算字节数；
- 最老待处理任务年龄；
- 最近成功时间、失败次数和永久失败数；
- 按 kind 的保留对象数量与字节数。

达到容量或 GC 延迟阈值时告警，但不得删除未到期或被显式保留的 Artifact。

---

## 6. G3：CI、镜像与发布门槛

在 P3 合并前修复现有 workflow 的触发路径和构建上下文，并建立以下 PR 门槛：

1. Python 非 Docker 测试、类型/格式检查；
2. Web 单元测试、类型检查与生产构建；
3. PostgreSQL 迁移升级与离线 SQL 渲染；
4. semantic 镜像构建及无外部模型调用的 runner/contract smoke test；
5. Artifact GC 的本地存储与 PostgreSQL 故障重试测试；
6. P3/P2/P1/P4 各自的定向测试；
7. `docker compose config` 与镜像模板契约检查。

发布镜像使用不可变版本与 digest，不只覆盖 `:local`/`:latest`。发布产物记录
源码提交、基础镜像 digest、依赖锁、SBOM 和签名。部署记录保存兼容发布 C 与上一
功能发布的镜像 digest，作为明确回滚目标。

CI 不调用真实收费模型；协议测试使用固定响应 transport。真实模型只在受控 canary
中评估质量、延迟与费用，结果不作为可复算单元测试。

---

## 7. P3：敏感工具轨迹与安全汇总

### 7.1 事件契约

Trace 使用有序 JSONL 事件，而不是只在任务结束时一次性序列化内存列表。每个
`tool_use` 先获得内部 seq，并遵循以下状态机：

```text
request:
  seq · turn_index · tool_use_id? · validated_tool_name? · input_shape

dispatch（仅 prepare 成功且预算已预留）:
  seq · turn_index · tool_use_id · tool_name · arguments

completion:
  seq · outcome · reason_code · elapsed_ms · result_bytes

refusal（未派发）:
  seq · outcome · reason_code · rejected_field? · supplied_type? · supplied_length?
```

每个 request 必须终止于 refusal，或进入 dispatch 后终止于 completion。`outcome`
是闭集：

```text
ok
broker_refused
invalid_arguments
budget_exhausted
truncated_turn_not_executed
internal_failure
```

新增 `Broker.prepare(name, arguments)` 边界：它先验证工具名、字段、类型、长度并
产出规范化参数，再由 `execute(prepared_call)` 执行。request 不保存原始自由文本；
只有 prepare 成功后的 dispatch 才保存 arguments。无效请求的 tool name 只有在
命中允许列表时才记录，否则写 `unknown`；未知键名和值均不落盘。

`reason_code` 使用 Broker/Conversation 的稳定机器码，不复用 P2 的 Finding
rejection 码。`seq` 按 request 顺序分配；`completion` 可乱序写入，但消费者必须按
`seq` 关联和展示。`calls_requested` 是 request 数，`calls_dispatched` 是 dispatch
数，budget/truncation refusal 不计入 dispatched。

### 7.2 崩溃可见性

- request 在解析 tool_use 后原子追加；dispatch 在 execute 前原子追加；
  completion/refusal 在对应状态确定后原子追加。
- 每个事件 flush 到输出卷；半条 JSON 不得让此前记录不可读。
- Sandbox Manager 在 completed、failed、timeout 和 cancel 的终态都尝试收集
  已存在的 Trace；收集失败本身进入 Coverage。
- 有 dispatch 无 completion 的调用汇总为 `internal_failure` 且
  `trace_complete=false`。

### 7.3 登记与消费

Orchestrator 校验 Trace 契约、条数、seq 唯一性、状态迁移、大小及 task/subject
归属后，将其登记为独立 Sensitive Artifact，再从校验后的事件生成 Summary。
`subject_type` 首期为 `semantic_scope` 或 `verification_candidate`，对应
`subject_key` 分别是 scope key 或 `root_cause_key`。工作台普通视图只读取
Summary；完整下钻通过受权限保护的 Artifact 下载或专用只读端点完成。

### 7.4 价值边界

Trace 支持人工判断一个零 Finding scope 是否只做了表面访问，也能核对盲审是否
独立发起了文件、符号与 Sink 查询。但它不证明模型建立了调用链，更不自动改变
Finding、Verification 或 Coverage 的完成状态。

---

## 8. P2：拒绝原因分类与数据链路

### 8.1 container 与 item 原因码

首期只覆盖现有规则，不新增候选资格：

| 层级 | 原因码 | 现有失败族 |
| --- | --- | --- |
| container | `SEMANTIC_REJECT_OUTPUT_SHAPE_INVALID` | 顶层不是约定对象/数组 |
| container | `SEMANTIC_REJECT_ITEM_LIMIT_EXCEEDED` | 超过每 scope item 上限 |
| item | `SEMANTIC_REJECT_OUTPUT_SHAPE_INVALID` | finding 不是对象 |
| item | `SEMANTIC_REJECT_NO_LOCATION` | 缺代码位置 |
| item | `SEMANTIC_REJECT_NO_CALL_CHAIN` | 缺入口到 Sink 调用链 |
| item | `SEMANTIC_REJECT_CALL_CHAIN_INVALID` | 起止角色、唯一性或 Sink 对齐失败 |
| item | `SEMANTIC_REJECT_NO_CONTROLLABILITY` | 缺可控性说明 |
| item | `SEMANTIC_REJECT_REQUIRED_FIELD_MISSING` | 缺 message、preconditions、impact 等字段 |
| item | `SEMANTIC_REJECT_PATH_NOT_IN_SNAPSHOT` | 路径不存在或越出 Snapshot |
| item | `SEMANTIC_REJECT_LINE_OUT_OF_RANGE` | 行范围越出对应文件 |
| item | `SEMANTIC_REJECT_FIELD_INVALID` | 类型、枚举、未知字段或其他字段约束失败 |

每条 rejection 保留：

```text
level · ordinal? · reason_code · field? · detail
```

`field` 是受限路径，不包含模型输入值；`detail` 继续做长度限制和输入剥离。为可靠
区分 path 与 line，`SourceCatalog`/`NormalizationError` 必须先提供稳定机器码，
不得解析英文错误字符串。

为防止“缺 impact + 伪造路径”被误判为可修复，item 校验先完成结构、身份、位置和
调用链等全部不可修复预检，再检查可修复叙述字段。若同一 item 有多项错误，不可
修复原因优先；同一优先级按固定字段顺序选择一个主原因。

Scope 级 `SEMANTIC_OUTPUT_INVALID` / `SEMANTIC_OUTPUT_INCOMPLETE` 保留，不与上述
聚合码混用。Independent Reviewer 继续使用 `VERIFY_*` 码和 `inconclusive` 语义。

### 8.2 Coverage 聚合

新增版本化 `semantic_rejection_counts` 结构，分别统计 container 与 item
rejection，并包含 `raw_item_count?`、`evaluated_item_count`、
`accepted_item_count`、`rejected_item_count` 和 `dropped_item_count`。顶层非法时
`raw_item_count=null`；超过上限时 `dropped_item_count=raw-evaluated`，不能用一条
limit rejection 冒充被截断 item 数。

聚合同时按 reason、subject 和 result contract 计数。必须从已结算 task result
**重新计算并覆盖写入**，不能在重放时累加，否则幂等恢复会重复计数。混入 v1 时按
§3.4 标记 `classification_complete=false`。

原始 rejection 留在 Sensitive task result；普通 Coverage 只显示 reason、数量和
subject key，不显示 detail 或模型原文。

### 8.3 API、报告与前端

- Coverage schema 和报告 JSON 显式增加版本化 rejection 聚合字段；
- `coverage.ts` 为已知码提供准确说明，未知码只显示原码；
- `taskLabels.ts` 只处理任务错误，不作为 item rejection 的唯一映射；
- 报告分别给出 container 错误以及 raw/evaluated/accepted/rejected/dropped 分母；
- raw 已知时满足 `raw = accepted + rejected + dropped`；
- 同一 item 只能计入一个主原因，并遵循 §8.1 的不可修复优先级。

---

## 9. P1：默认关闭的有界修复

### 9.1 首期范围

首期只作用于 `SemanticReviewer`。Independent Reviewer 的单 verdict 修复可能把
原本的 `inconclusive` 变成 `confirmed`，必须等语义修复 canary 有数据后另行评审，
不复用 item repair 协议。

`max_repair_rounds` 是 policy 字段，默认 `0`，允许值首期仅 `0` 或 `1`；
`repair_canary_percent` 默认 `0`，允许值 `0..100`。两者都快照进 AuditRun 的有效
policy；仅 rounds 为 1 且 task 命中 canary 时才允许修复，重试沿用相同快照和
task ID。平台、Gateway grant 和 usage 都把 repair 请求计入 request、turn、token、
费用和 deadline；剩余 `max_turns_per_task` 或任一预算不足时不得发起。

### 9.2 可修复与不可修复

首期允许修复：

```text
SEMANTIC_REJECT_NO_CONTROLLABILITY
SEMANTIC_REJECT_REQUIRED_FIELD_MISSING
```

以下错误不可修复，也不向模型开放第二次提交：

```text
路径不在 Snapshot
行号越界
缺位置
缺调用链或调用链不成立
顶层/item 结构不可关联
item 超限
类别、严重级、置信度或其他身份字段非法
```

新增可修复码必须经过安全评审和 canary，不得通过配置自由扩展。

### 9.3 修复协议

1. 首轮 parse 后冻结全部已通过 item；二轮无权修改或删除它们。
2. 平台保留模型自己的首轮结构化回答作为会话历史。
3. 平台只追加 `ordinal`、`reason_code`、`field` 和 schema 要求，不引用或评价
   上一轮自然语言推理。
4. 二轮只能补获准缺失字段，不返回完整 Finding。schema 只接受：

```json
{
  "repairs": [
    {"ordinal": 3, "patch": {"impact": "补充的影响说明"}}
  ]
}
```

5. patch key 只能是该 ordinal 实际缺失的
   `controllability/message/attack_preconditions/impact/recommended_verification`；
   已存在字段及 location、call chain、rule/category/severity/confidence 等字段
   不可覆盖。
6. 平台把 patch 合并进保存的首轮原始 item；每个获准 ordinal 必须恰好出现一次，
   不得新增 ordinal、Finding 或扩大 item 总量。
7. 合并后的 item 重新经过完整 `parse_findings`、Snapshot 位置校验和 Candidate
   派生；没有任何字段沿用“相信模型”的快捷路径。
8. v2 结果增加 `repair_attempts[]`，记录 ordinal、初始码、允许字段、是否请求、
   outcome 和最终码。outcome 至少区分
   `passed/validation_failed/refused/transport_unavailable/truncated/deadline/budget_skipped`。
9. 二次请求的任何失败都不得丢弃首轮已通过 item，也不得把整个 scope 改成 failed；
   原 item 保持 rejection，并产生稳定 repair warning。
10. 最终结果为“冻结的首轮通过项 + 按原 ordinal 合并的二轮通过项”；成功项的
    provenance 保留初始码，失败项通过 `repair_attempts[]` 保留初始码与最终码。

### 9.4 灰度与回滚

- 初次发布 `repair_canary_percent=0`；canary 按 `sha256(task_id) % 100` 确定性
  选取，不由模型选择。
- 起始比例不高于 5%，每次提升都需要至少一个完整人工复核窗口。
- 监控修复触发率、修复通过率、人工驳回率、每 scope 增量 token、请求和延迟。
- 每档至少人工复核 50 个修复后候选；其驳回率的 95% Wilson 下界高于同窗口一次
  通过候选的上界 5 个百分点时停止扩量并归零。出现一次位置/身份字段绕过时立即
  归零，不等待样本门槛。
- 回滚只影响未来 task；已经晋升的 Finding 保留 repair provenance，不能静默删除。

---

## 10. P4：Broker 修复后的有界并发

P4 在 P3 稳定后实施，先用轨迹建立串行延迟基线。

### 10.1 执行策略

- 在进入会话前预热并冻结 catalog、inventory 与 auth bindings；
- 工具预算在派发前单线程预留，超出部分按原顺序返回
  `TOOL_BUDGET_EXHAUSTED`；
- 非 search 的无副作用调用进入有上限的执行器；
- `search` 进入独立、可终止的执行路径，保留硬墙钟超时；不得在线程中静默失去
  SIGALRM 保护；
- 首期 `max_parallel_tool_calls` 默认 4、硬上限 8，并受 Sandbox CPU/内存 policy
  约束；
- 返回给模型的 `tool_result` 顺序严格与 `tool_use` 顺序一致；
- Trace seq 按 request 顺序，elapsed 按各调用实际完成时间记录；
- 一个调用失败不取消同批其他只读调用，但 timeout/cancel 必须终止对应执行单元。

### 10.2 不变式

并发不得改变：

- 每个 `tool_use_id` 与 `tool_result` 的一一对应；
- 预算内/预算外调用的选择；
- Broker 返回 payload；
- warnings、findings、rejections 和 Coverage 的聚合逻辑；
- Sandbox 的网络、文件系统和进程能力。

这些不变式使用固定模型响应和可控延迟的 fake Broker 验证，不用两次真实模型运行
声称“模型输出确定”。

### 10.3 性能门槛

在至少包含四个独立慢调用的基准 fixture 上：

- 并发路径的单轮墙钟时间应比串行基线降低至少 30%；
- CPU、RSS、打开文件数和 Trace 大小不得超过预设上限；
- 单个超时 search 不得让同批调用或整个 scope 超过任务 deadline；
- 无可测收益时保持 P4 flag 为 0。

---

## 11. P5、P6 的独立立项条件

### 11.1 P5：确定性知识包

独立计划至少先解决：

- inventory 增加受支持的依赖坐标、已解析版本和证据来源；
- Shiro/Fastjson 等触发条件的确定性探测；
- 知识包 `id/version/sha256/source/license` manifest；
- 内容不可变、固定排序、缺包/损坏/回滚行为；
- system prompt 大小上限和选择优先级。

在这些条件完成前，不得声称“同 Snapshot 同 policy 得到同一知识包集合”。

### 11.2 P6：复核期追问

独立计划必须使用 Sensitive Transcript Artifact 或专用表。`audit_log` 只记录：

```text
action · finding_id · transcript_artifact_id · human_review_id · sha256
```

计划还需单独定义 reviewer RBAC、提问大小、输出契约、模型 grant、保留期、删除、
源码引用处理及“没有 Finding 写句柄”的服务边界。追问输出不得写入 Finding
evidence、不得触发状态转换，也不得被 Independent Reviewer 消费。

---

## 12. 发布阶段与验收

### R0：前置门槛

1. v1/v2 双读通过历史 Artifact、混合 Worker 和回滚测试；混合聚合保留 v1 coarse
   bucket 并标记分类不完整。
2. expand migration 可升级；兼容发布 C 可读取迁移前后数据。
3. 含敏感字符串的 fixture 先 `read_file`，再把该字符串作为 `search.pattern`；
   完整 Trace 保持 Sensitive，Summary、Coverage、报告和普通日志均无该字符串。
4. Viewer 无法读取 Trace；获权下载产生操作日志。
5. 到期、AuditRun 删除、对象已不存在、存储暂时失败和 GC 中途崩溃均能幂等收敛；
   共享 `storage_key` 的活跃引用不会被删除，legal hold 会阻止 AuditRun 删除。
6. 修复后的 CI 会实际验证 Python、Web、迁移和 semantic 镜像。
7. 发布记录能从源码提交定位到不可变镜像 digest，并能回滚到兼容发布 C。

### R1：P3

1. 成功和 Broker 拒绝遵循 request -> dispatch -> completion；无效参数、预算耗尽
   和截断调用遵循 request -> refusal，计数分别正确。
2. crash、timeout、cancel 后仍能收集已 flush 的事件，未完成调用清楚标记。
3. 同一固定调用序列两次生成相同 seq/tool/outcome 汇总；elapsed 不参与相等判断。
4. 超长、未知字段及含密钥的无效参数只留下安全形状元数据，原始键和值不进入 Trace。
5. semantic scope 与 Independent Reviewer fixture 都能按各自 subject key 归属。
6. 零 Finding scope 的报告只陈述观察到的调用，不出现“已阅读”“已证明”等措辞。

### R2：P2

1. 当前每个 container/item 拒绝路径都有且只有一个稳定主原因。
2. path 与 line 原因来自结构化 NormalizationError，不解析 message。
3. 同时缺叙述字段和伪造路径时，不可修复原因稳定胜出。
4. task 重放不会重复计数；raw/evaluated/accepted/rejected/dropped 满足 §8.2 不变式。
5. API、报告与前端显示相同数字；未知码不编造解释。
6. v1/v2 混合结果不把 v1 粗码推断成 v2 细码。
7. 空 CWE 和现有合法 category 在本阶段仍保持原有行为。

### R3：P1

1. rounds 或 canary percent 为 0 时不增加模型请求，固定响应的业务结果与兼容基线
   一致；AuditRun policy 快照使重试命中结果稳定。
2. 首轮部分通过、部分拒绝时，已通过 item 逐字段保持不变且不重复。
3. 仅缺可控性或必填叙述的 item 可进入一次修复。
4. patch 之外的首轮拒绝 item 字段逐字段不变；覆盖已有字段或提交非法 ordinal 被拒。
5. 路径伪造、行号越界、缺调用链及其与缺叙述字段的组合不产生 repair 请求。
6. refusal、transport failure、截断、deadline、非法响应和预算不足都保留首轮通过项
   与原 rejection，并写入稳定 repair outcome。
7. repair 请求计入 Gateway grant、usage、费用、deadline 和
   `max_turns_per_task`，任何一项不足均不突破上限。
8. Finding、API 和 UI 都能识别“修复后通过”，多来源合并与重放不覆盖 provenance。
9. canary 可确定性开启、扩容和一键归零，并执行 §9.4 的样本与停止门槛。

### R4：P4

1. 固定 tool_use batch 在串行/并发路径得到相同的有序 tool_result 映射。
2. 剩余预算小于 batch 时，两条路径选择相同调用并返回相同预算错误。
3. search 在线程、进程故障和超时条件下都不失去硬 deadline。
4. 并发上限、取消和资源限制有测试。
5. 基准达到 §10.3 的收益门槛；否则保持关闭。

P5、P6 不纳入 R0-R4，不得借本计划的“完成”状态开始实现。

---

## 13. 风险与停止条件

### 13.1 P1 通过率漂移

最高风险是模型根据错误提示补出形式完整但证据薄弱的叙述。位置/调用链类错误一律
不可修复，所有修复后候选显式标记，并以人工驳回率作为停止条件。

### 13.2 P3 存储与敏感面扩大

完整 arguments 增加了敏感数据副本。通过最小化、Sensitive RBAC、非空 TTL、
幂等 GC、容量指标和可见截断控制风险。存储或 GC 指标越过阈值时停止扩大保留期，
不能改为把完整 arguments 降级写入 Coverage。

### 13.3 P3 证据被过度解释

调用轨迹只证明平台观察到的访问事件。任何 UI、报告或文案把它描述成“模型确认”
“模型理解”或“独立重建成功”均视为验收失败。

### 13.4 P4 资源放大

并发会放大 CPU、文件描述符和正则计算。硬并发上限、独立 search deadline 和
Sandbox deadline 任一失效时，P4 必须回退到串行。

---

## 14. 不在本计划范围内

- P5 知识包与 P6 复核追问的实现；
- Independent Reviewer 的 repair round；
- 扫描器独有候选的语义分诊；
- 漏洞类别、确定性探针或 Sink 规则新增；
- Finding 晋升规则、§7.8 确认规则或完成闸门变更；
- 语义 scope 切分、静态调用图和任务级并发调度；
- 让模型自主决定修复轮次、并发度、知识包或 scope；
- 用真实模型重复运行来证明确定性。
