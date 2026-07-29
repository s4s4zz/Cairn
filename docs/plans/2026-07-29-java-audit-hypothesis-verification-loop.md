# Java 审计有界假设-验证回路计划

**状态：** Proposed

**日期：** 2026-07-29

**适用对象：** 主路线七个子项目交付的 Audit Orchestrator，特别是
`semantic_auditing` 与 `dynamic_verifying` 两个阶段之间的信息流。

**与现有路线的关系：** 本计划是主路线之上的能力增量，不新增审计类型、不新增
漏洞类别、不改变外层流水线的确定性骨架。它只把一条**有界的**回边加进状态机，
让"动态验证给出 inconclusive"这个已经产生但无人消费的信号，能够驱动一次受控的
重新求证。

**成本约束：** 本计划**不含成本闸门**。轮次上限是常量，预算谓词预留为恒真的
插入点，待后续在审计任务创建时以运行级设置接入。

---

## 1. 结论与目标

当前流水线是单向无回边的：语义审计出候选，动态验证给结论，机器复核收口，
人工处置。任何一个阶段产生的"我不确定"都不会回流。

具体表现为一类系统性缺口：**动态验证返回 `inconclusive` 时，这条信息只被写进
`Verification.reasoning` 和一条 coverage warning（`engine.py:1275-1281`），
没有任何下游组件消费它。** 一个"这里像命令注入，但我没能确认调用者"的判断，
产生之后就停在那里，直到人工复核时由人重新读一遍代码。

目标是把这条死路变成一次**有界的**假设-验证循环：

- 平台根据 inconclusive 的原因码生成**具体的、结构化的假设**
- 语义阶段在受控轮次内针对该假设重新求证
- 结论并回原 Finding，或在轮次用尽后记为显式的 coverage 缺口

**不是**让模型自主决定继续挖掘。轮次、假设内容、终止条件全部由平台的确定性
谓词控制。

---

## 2. 问题陈述

### 2.1 系统内没有静态调用图

`bytecode_sink_candidates`（`analysis/bytecode_sinks.py:88-152`）遍历
`index.calls`，按 `target_owner` + `target_name` 前缀匹配固定规则表，
**不做任何调用者传播**。源码侧的 `_SINK_PATTERNS`（`analysis/indexer.py:75-113`）
是正则，同样只匹配字面调用点。

调用图推理被完全外包给模型：`semantic/prompt.py:163` 要求模型"把外部可控值沿
call graph 传播"，`semantic/broker.py:381` 要求它"confirm reachability by
reading the code"。

### 2.2 包装函数暴露的具体缺口

以本项目内的包装为例：

```java
class Utils { static void runCommand(String cmd) { Runtime.getRuntime().exec(cmd); } }
class AdminController { void handle(String p) { Utils.runCommand(p); } }
```

- 字节码规则**能**匹配到 `Runtime.exec`，但候选的位置是 `Utils.runCommand`
- `AdminController → Utils.runCommand` 这一跳没有任何静态代码去追
- 候选自带的 message 就写着 `Reachability and attacker control have not been
  established`，`confidence` 硬编码为 `"low"`，`recommended_verification` 写着
  `Trace callers and arguments from an externally reachable entrypoint`
- 源码正则完全不匹配 `Utils.runCommand(p)` 这个调用点

补这一跳的只有模型。模型在首轮没补上时，动态验证会给出 `inconclusive`——
而这正是本计划要消费的信号。

### 2.3 `audit_intents` 是一张从未启用的表

`AuditIntentStatus` 有 `pending` / `claimed` / `concluded` / `cancelled` 四态，
`AuditIntent.claimed_by_task_id` 列存在。但全代码库中 `CLAIMED` **从未被写入**，
`claimed_by_task_id` 从未被赋值。intent 建出来是 `pending`
（`engine.py:2170-2177`），机器复核阶段由 `_conclude_intents` 批量置为
`concluded`（`engine.py:2086-2102`）。

该函数的 docstring 明确写着：

> Nothing downstream re-derives the plan, so concluding them here is what makes
> the graph an accurate record of what was decided.

本计划正是让这句话不再成立——让下游真的重新推导计划。

---

## 3. 结构约束

实施前必须承认的既有事实：

| 约束 | 位置 | 影响 |
| --- | --- | --- |
| 运行状态转移表严格前向 | `domain/state_machines.py:30-51` | `DYNAMIC_VERIFYING → SEMANTIC_AUDITING` 会被 `transition_audit_run` 拒绝，回边不能靠回跳实现 |
| 语义阶段的 coverage 从 0 重算 | `engine.py:739-746` | 重进 `SEMANTIC_AUDITING` 会覆盖写坏首轮覆盖率数字 |
| 语义任务已有幂等重放 | `engine.py:2268-2288` | 任务已结算则复用结果不重复付费，崩溃恢复天然正确 |
| 一次运行共用一个验证沙箱 | `engine.py:755-765` | 复验不应新建环境 |
| `plan_semantic_reviews` 确定性 | `orchestrator/semantic_tasks.py:173-183` | 排序与内容可复算，回路必须保持该性质 |
| 编排器单线程串行 | `engine.py:583`、`engine.py:693` | 增加轮次即线性增加墙钟时间 |

---

## 4. 状态机

新增一个显式的回路状态，**不复用** `SEMANTIC_AUDITING`。

```python
# server/domain/enums.py
class AuditRunStatus(StrEnum):
    ...
    HYPOTHESIS_REVIEW = "hypothesis_review"

class AuditStage(StrEnum):
    ...
    HYPOTHESIS_REVIEW = "hypothesis_review"
```

```python
# server/domain/state_machines.py
AuditRunStatus.DYNAMIC_VERIFYING: {
    AuditRunStatus.MACHINE_REVIEW,
    AuditRunStatus.HYPOTHESIS_REVIEW,
},
AuditRunStatus.HYPOTHESIS_REVIEW: {AuditRunStatus.DYNAMIC_VERIFYING},
```

同步更新：

- `_ACTIVE_AUDIT_RUN_STATUSES`（`state_machines.py:18-28`），否则取消与失败转移不可用
- `engine._ELIGIBLE_STATUSES`（`engine.py:122-131`），否则 `process_next` 不会认领处于该状态的运行

`process_run` 的分支：

```python
if status is AuditRunStatus.DYNAMIC_VERIFYING:
    self._dynamic_verify(audit_run)     # 现有实现，末尾不再直接转 MACHINE_REVIEW
    continue
if status is AuditRunStatus.HYPOTHESIS_REVIEW:
    self._hypothesis_review(audit_run)
    continue
```

阶段推进的决定权交给 `_reopen_plan`（见第 6 节），由 `_dynamic_verify` 末尾调用。

### 为什么不直接回跳

1. 首轮 coverage 语义会被第二轮覆盖写坏（`engine.py:739-746`）
2. 首轮数字必须保持"单趟全量"的含义，否则 CP0 基线漂移
3. 阶段在 UI 上来回跳，读者无法理解；独立阶段可显示"假设复验 · 第 2 轮"
4. 转移表保持可审计：全表**唯一的环**就是这一对，一眼可见

---

## 5. 数据模型

### 5.1 `audit_intents` 增列

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `round` | `int NOT NULL DEFAULT 0` | 轮次；首轮语义审计产生的 intent 为 0 |
| `parent_intent_id` | `UUID NULL` 自引用 | 串起同一条假设的演进链 |
| `hypothesis` | `JSON NOT NULL DEFAULT '{}'` | 本轮要模型回答的具体问题 |

四个状态启用：

```
pending    已生成，待本轮语义任务领取
claimed    本轮任务已领取，claimed_by_task_id 写入
concluded  本轮得到 supported / refuted 结论
cancelled  轮次用尽仍为 still_unknown，同时写 coverage gap
```

`_conclude_intents`（`engine.py:2086-2102`）的批量收口保留，但改为只对
"已达轮次上限或已有结论"的 intent 生效，不再无条件清空 `pending`。

### 5.2 `AuditCoverage` 增列

| 列 | 类型 | 说明 |
| --- | --- | --- |
| `review_rounds_used` | `int NOT NULL DEFAULT 0` | 实际使用的复验轮数 |
| `reopened_scopes` | `JSON NOT NULL DEFAULT '[]'` | 每轮重开的 scope_key、触发原因码、结论 |

### 5.3 不改动的模型

`Finding`、`Verification`、`Evidence`、`FindingLocation` 结构不变。
`Verification.verdict = INCONCLUSIVE` 已经是回路的输入，回路只读不改。

---

## 6. 唯一决策点

```python
def _reopen_plan(self, audit_run: AuditRun) -> ReopenPlan:
    """给定数据库状态，返回下一轮要复验的 scope 列表。纯确定性。"""
```

输入全部来自数据库，输出按 fingerprint 排序。谓词全部成立才重开：

1. 存在 Finding，其最强动态结论为 `INCONCLUSIVE`
   （复用 `engine.py:1783-1798` 已有的 helper）
2. 该 Finding 可映射回一个 scope（location → module / category）
3. 该 scope 的 `max(intent.round) < MAX_REVIEW_ROUNDS`（常量，初值 2）
4. 本轮将生成的假设集合 **≠** 上一轮（对 `hypothesis` 规范化后比较哈希），
   防止原地打转
5. `_budget_allows(audit_run)` —— **本计划中恒返回 `True`**，是后续接入
   运行级成本设置的唯一插入点

结果为空 → 转 `MACHINE_REVIEW`；非空 → 转 `HYPOTHESIS_REVIEW`。

> **模型不参与该判定。** 模型只能产出结论，不能请求追加轮次。这是整个回路
> 可复算性的根基。

---

## 7. 假设由平台生成

假设不是模型的自由发挥，而是从 inconclusive 原因码到固定模板的确定性映射：

| inconclusive 原因类别 | 生成的假设 | 重开 |
| --- | --- | --- |
| 入口未确认 / 探针找不到可达路由 | 找出 `{sink_symbol}` 的所有调用者，判断是否存在从外部入口到它的路径，以及参数是否外部可控 | 是 |
| 参数可控性未判定 | 列出到达该 sink 的每个参数的来源，逐个判断能否由请求控制 | 是 |
| 需要认证态或角色 | 确认该入口的鉴权注解与所需角色，说明未授权用户能否到达 | 是 |
| 类别无确定性探针 | —— | 否（首期） |
| 环境缺失、应用未就绪、传输失败 | —— | **否** |

最后一行是设计要点：**只对"知识不足"重开，不对"环境不足"重开。**
环境问题重开多少轮结论都一样，只会消耗预算并制造"我们努力过"的假象。
环境类 inconclusive 继续按现有路径记为 coverage 缺口。

第一行即为第 2.2 节包装函数缺口的正式解法。

---

## 8. 第 N 轮的执行

新任务类型 `AuditTaskType.HYPOTHESIS_REVIEW`，`scope_key` 追加轮次后缀：

```
semantic:{module}:{surface}:{category}:r{n}
```

`SCOPE_KEY_PREFIX`（`semantic/findings.py:39`）保持 `"semantic"` 不变，
仅追加 `:r{n}`。由此：

- `get_or_create_semantic_task`（`orchestrator/tasks.py:105-140`）的幂等直接继承
- `_execute_semantic_scope` 已有的"任务已结算即复用结果、不重复付费"逻辑
  （`engine.py:2268-2288`）自动适用于复验任务，崩溃恢复无需新增代码

模型输入：

- 首轮 scope 的全部上下文
- 本轮 `hypothesis`
- 上一轮的**结构化** inconclusive 证据：原因码、已确认项、未确认项

**不提供**上一轮的自然语言推理过程（见第 15 节）。

工具集不变，仍为 `ToolBroker` 的七个只读工具
（`read_inventory` / `list_modules` / `read_file` / `search` / `find_symbol` /
`list_entrypoints` / `list_sinks`）。**回路不给模型任何新能力**，只给新问题。

输出契约仍为 `SemanticReviewResult`，追加对假设的三选一判定：

```
supported | refuted | still_unknown
```

每种判定都必须附证据位置；`still_unknown` 必须给出原因码。

---

## 9. 结果并回主链

| 判定 | 处理 |
| --- | --- |
| `supported` | 走现有 `_persist_semantic_result` 与 Finding Pipeline，按 `root_cause_key` **合并进已有 Finding**（不新建），新的调用者链以 `role=propagation` / `entrypoint` 追加为 `FindingLocation`；intent → `concluded` |
| `refuted` | 走现有拒绝路径，理由写入 `Verification.reasoning`；intent → `concluded` |
| `still_unknown` | intent 保持 `pending` 等待下一轮；已达轮次上限则 → `cancelled` 并写 coverage gap |

合并而非新建是硬要求：同一个根因在报告里出现两条 Finding，比不复验更糟。

---

## 10. 回到动态验证

`HYPOTHESIS_REVIEW` 结束后转回 `DYNAMIC_VERIFYING`。该轮**只验证本轮发生变化的
Finding**（新增 location 或状态变化），不重跑全量。

沙箱沿用现有"一次运行一个验证环境"的设计（`engine.py:755-765` 的注释解释了
为什么不能一个 Finding 一个沙箱）。若上一轮的验证环境已销毁，则按现有逻辑
重建一次，并把重建计入 `reopened_scopes` 记录。

---

## 11. 可复算性保证

回路引入循环，循环是可复算性的天敌。以下四条是必须成立的不变量：

1. **轮次上限是常量**，写进 policy，计入 `policy_version`
2. **每轮 scope 按 fingerprint 排序**，`plan_semantic_reviews` 的确定性性质
   （`semantic_tasks.py:178-183`）必须在复验路径上同样成立
3. **终止条件是纯谓词**，不由模型决定是否再来一轮
4. **每轮输入取自数据库**，不依赖模型上下文残留或对话历史

同一 Snapshot + 同一 policy version，两次运行必须产生相同的轮数、相同的
scope 序列、相同的 coverage 数字。

---

## 12. Coverage 与报告

新增的诚实表述要求：

- `review_rounds_used` 写入 coverage 并出现在报告
- 报告新增一节"经 N 轮复验仍未定论"，逐条列出 scope、假设与最后一次原因码
- 打满轮次仍为 `still_unknown` 的，**必须记为 coverage gap**

硬约束：

> **"复验过"不等于"已审"。** `sensitive_sinks_analyzed` 只统计得到结论的项。

这条如果破了，回路就从能力增强退化为自欺工具——这与平台"敢说哪些没审到"的
根本价值直接冲突。

---

## 13. 前端

- `StageTimeline.definitions` 增加 `hypothesis_review` 阶段
- 该阶段的 summary 显示轮次进度："第 2/2 轮 · 3 个 scope 复验中"
- 同一 scope 在不同轮次的任务需要能区分展示（`scope_key` 已带 `:r{n}`）

附带影响：回路会让"界面只有快照、没有叙事"的现有问题从难受变为不可接受。
同一个 scope 出现两次、结论从 `still_unknown` 变为 `supported`，快照式 UI
无法表达。运行事件日志面板在本计划落地时应同步提供。

---

## 14. 落地顺序

| 步骤 | 内容 | 验证 |
| --- | --- | --- |
| 1 | 状态机 + 枚举 + Alembic 迁移 + 空回路（`_reopen_plan` 恒返回空） | 全量测试绿，运行行为零变化 |
| 2 | 假设模板第一类（调用者追踪），仅对有确定性探针的类别开放 | 构造包装函数 fixture，验证第二轮能定位调用者 |
| 3 | 结果并回 + coverage 记账 | 验证合并不新建、gap 如实记录 |
| 4 | 前端阶段展示 + 事件日志 | Vitest + 手工走查 |
| 5 | 放开更多假设模板；轮次上限接入运行创建设置 | 回归 + 基线复算 |

第 1 步单独交付的意义：管道全部铺通但行为不变，可以先确认状态机、迁移、
任务幂等和恢复路径没有引入回归，再开启实际的回路逻辑。

---

## 15. 风险

### 15.1 Confirmation drift（最高风险）

模型顺着自己上一轮的错误判断继续推进，轮次越多越确信，最终把一个误报
"验证"成高置信度 Finding。

对策已内置于设计：

- 假设由平台从原因码生成，模型不能自己设定要证明什么
- 证据从数据库结构化读取
- **模型看不到自己上一轮的自然语言推理**，只看到结构化结论与原因码

### 15.2 墙钟时间线性增长

编排器串行（`engine.py:583`、`engine.py:693`），2 轮上限意味着最坏两倍时长。
回路落地后，静态扫描阶段的工具级并发将从"优化项"变为"必需项"。

### 15.3 轮次成为默认开销

若多数运行都触发复验，成本模型会显著偏离现状。缓解：首期仅对有确定性探针的
类别开放，并在 `reopened_scopes` 中记录触发率，作为后续接入运行级成本设置的
决策依据。

---

## 16. 验收标准

1. 构造一个"控制器 → 项目内包装函数 → `Runtime.exec`"的 fixture，首轮得到
   `inconclusive`，第二轮能定位调用者链并给出 `supported`，且结论**合并进
   原 Finding** 而非新建
2. 环境缺失导致的 `inconclusive` **不触发**任何复验轮次
3. 同一 Snapshot + 同一 policy version 连续两次运行，轮数、scope 序列与
   coverage 数字完全一致
4. 轮次用尽仍未定论的项，出现在报告的"仍未定论"一节，且不计入
   `sensitive_sinks_analyzed`
5. 在复验轮次中途杀死编排器并重启，运行从当前轮次继续，不重复消费已结算任务
6. 关闭回路（`MAX_REVIEW_ROUNDS = 0`）时，全量行为与本计划实施前逐字节一致

---

## 17. 不在本计划范围内

- 成本闸门与运行级预算设置（`_budget_allows` 恒真，后续接入）
- 静态调用图（WALA/Soot 等），见闭源平台计划 CP1 及之后
- 任务级并发调度
- 新增漏洞类别或新增确定性探针
- 语义 scope 切分策略的改变（跨模块 scope 合并不在本计划内）
- 让模型自主决定复验轮次或自主扩展 scope
