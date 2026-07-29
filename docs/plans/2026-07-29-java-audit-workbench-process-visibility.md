# Java 审计工作台运行过程表达优化计划

**状态：** 已实现（P1 全部、P2 除阶段时间戳外、P3 部分）；交付记录见第 18 节

**日期：** 2026-07-29

**适用对象：** `cairn/web` 的运行详情链路——`AuditRunDetailView.vue`、
`StageTimeline.vue`、`useAuditRunEvents.ts`，以及为其供数的
`AuditRunService.event_snapshot`。

**与现有路线的关系：** 本计划是子项目七交付的工作台之上的表达层增量。不新增
审计能力、不改变审计结论、不触碰权限与 Artifact 授权边界。

**与假设-验证回路计划的关系：** 互为前置。
[有界假设-验证回路](2026-07-29-java-audit-hypothesis-verification-loop.md)
会让同一个 scope 在不同轮次出现多次、结论从 `still_unknown` 变为 `supported`。
快照式界面无法表达这种演进，因此本计划的第 5.1 节 B、C 两项应先于回路的
第 2 步落地。

---

## 1. 结论与目标

当前运行详情页能回答"**现在**是什么状态"，不能回答：

- 这一路**发生过**什么（何时进入哪个阶段、哪个任务重试过）
- 时间**花在哪**（一次运行 40 分钟，是谁吃掉的）
- 已经**发现了**什么（运行途中的 Finding 漏斗）
- 哪些**没审到**（覆盖缺口在运行中不可见，且默认值会撒谎）

目标是让运行详情页成为"审计过程"的完整陈述，而不是一张状态快照。

---

## 2. 现状诊断

以下每条均已对照代码核实。

### 2.1 SSE 已送达但被前端丢弃的字段

`event_snapshot`（`server/services/audit_runs.py:206-245`）每次都带
`finding_counts` 和 `coverage_warning_count`。`applyEvent`
（`AuditRunDetailView.vue:65-81`）只取 `status` / `current_stage` /
`progress` / `warning_count` / `failure_*` / `completed_at` 和 `task_counts`，
**其余字段直接丢弃**。

用户最关心的"现在挖出什么了"，数据早已送到浏览器，界面上没有。

### 2.2 只有快照，没有叙事

每收到一个事件即调用 `refreshTasks()` 全表重拉
（`AuditRunDetailView.vue:79`）。刷新本身做了串行合并处理（`:91-103`），
但事件本身**不留痕**：界面永远只呈现最新快照，无法回答"什么时候进入的这个
阶段""哪个任务重试过几次""卡在哪一步"。

SSE 因此退化为事件驱动的轮询。

### 2.3 Coverage 的默认值会撒谎

`_coverage()`（`engine.py:2725-2747`）在 `_preprocess` 的**第一行**就被调用
（`engine.py:317`），即覆盖率行在盘点和构建之前就已存在。因此前端从预处理
开始就能取到它并渲染——不是"缺席"，而是**渲染了错误的内容**：

| 字段 | 构造默认值 | 真实赋值时机 | 中途界面表现 |
| --- | --- | --- | --- |
| `build_status` | `FAILED`（`:2739`） | 构建产出 manifest 之后（`:386` 附近） | 构建完成前一直显示"**构建失败**" |
| `entrypoints_analyzed` | `0`，且盘点后被显式重置为 `0`（`:363`） | 语义阶段结束（`:739-746`） | 长时间显示 `0 / 47 · 0%` |
| `sensitive_sinks_analyzed` | 同上（`:365`） | 同上 | 长时间显示 `0 / 128 · 0%` |

前端 `coverage-footer` 用 `StatusBadge` 直接渲染 `build_status`
（`AuditRunDetailView.vue:231`），不区分"尚未构建"与"构建失败"。

**这是本诊断中危害最高的一条**：它在一次正常运行的中途稳定地报告失败与零覆盖。

### 2.4 Worker 列几乎是常量

`task.worker_name` 在绝大多数任务上是同一个常量
`settings.orchestrator_worker_name`（`engine.py:2478`）。只有三类带角色后缀：
`:poc-author`（`:917`）、`:dynamic-verifier`（`:1172`）、复核类（`:1767`）。

整个静态扫描阶段每一行印同一个字符串，却在阶段行的七列 grid 中占据
`minmax(110px, 1fr)`（`StageTimeline.vue:423-425`）。

### 2.5 时间去向不可见

界面没有任何时间轴。每个任务只显示 `duration(started_at, finished_at)`，
无法横向比较，也无法看出一次运行的墙钟时间由谁主导。

编排器是串行的（`engine.py:583`、`engine.py:693`），**每一步的耗时都直接推迟
其后所有步骤**——正因为串行，"时间花在哪"比在并行系统里更需要被看见。

### 2.6 任务产物不可达

`AuditTask.output_artifact_ids` 在类型中存在（`types/api.ts:166`），模板从不
渲染。后端 `/api/v1/artifacts/{id}` 与角色校验都已具备。正在执行的扫描任务
只有一句静态文案（`StageTimeline.vue:214-217`），无法核对。

### 2.7 过程与结果被两个页面切断

`FindingStatus` 本身就是一条流水线：
`candidate → validating → machine_confirmed → awaiting_human_review →
confirmed / rejected / accepted_risk`。

这条漏斗就是审计过程的实质，但只能跳到 `/findings?audit_run_id=` 翻列表查看。

### 2.8 排版密度

`.task-facts dt` 为 `8px`、`dd` 为 `9px`（`StageTimeline.vue:592-604`）。
窄屏直接 `display: none` 丢弃 Worker / 耗时 / 重试三列（`:630-633`、`:642-644`）。

### 2.9 任务列表不翻页

`auditRunApi.tasks` 固定 `limit: 500` 且无 offset 循环
（`api/resources.ts:109`），路由上限同为 500。任务数超过 500 时静默截断。

---

## 3. 已修复，不在本计划范围

以下两项已于本轮修复并附测试，列出以免重复：

1. **任务总数双算** —— `task_counts` 已是服务端全量分组，前端再叠加
   `tasks.length` 造成翻倍。改为 `taskTotal` computed，以服务端计数为准，
   首个 SSE 事件到达前回退到已加载列表。
2. **阶段面板自动折叠** —— `:open` 直接绑派生状态，阶段由 `running` 变
   `succeeded` 时强制收起用户正在阅读的面板。改为"只自动展开、从不自动收起"，
   并以 `@toggle` 记住用户的显式选择。

新增测试 3 项（`StageTimeline.test.ts` 2 项、`AuditRunDetailView.test.ts` 1 项），
已确认在旧代码上失败。

---

## 4. 设计原则

### 4.1 缺口不能比成功更不显眼

`skipped` / `partial` / `inconclusive` 目前的视觉重量与 `pending` 接近
（灰色 `Minus`，`StageTimeline.vue:306-309`），读者会当成"没事"。而它们恰恰
是报告里必须写进 coverage gap 的内容。

平台的核心价值是"敢说哪些没审到"，界面必须与之一致。

### 4.2 只画真实的执行形态

编排器串行执行（`engine.py:583`、`:693`），任务创建后在同一趟内立即启动
（`engine.py:2474-2480`），因此：

- **画顺序瀑布，不画并行泳道** —— 泳道会让读者以为背后有一组并发 worker，
  从而对运行时长形成错误预期
- **不画排队段** —— `created_at → started_at` 基本为零，唯一的例外是崩溃恢复
  后复用既有任务行，那反映的是中断，不是调度等待，应单独标注

数据结构上，瀑布的每行即 `{start, end}`；将来若引入任务级并发，同一组件加
lane 维度即可，无需重写。

### 4.3 不引入新的重型依赖

ECharts 已在依赖中（`SeverityChart.vue`）。时间轴与漏斗条用 CSS grid 或
轻量内联 SVG 实现，不再引入图表库或布局引擎。

---

## 5. 方案

### 5.1 P1：纯前端，无需后端改动

**A. 实时 Finding 漏斗条**

在运行头部渲染一条分段进度条，数据取自 SSE 已送达的 `finding_counts`：
候选 / 验证中 / 机器确认 / 待人工 / 已确认 / 已驳回。`coverage_warning_count`
同时接入警告计数。零后端改动。

**B. 运行事件日志面板**

本地保留 snapshot 数组，对相邻两个 snapshot 做 diff，生成人类可读的流水：

```
12:03:11  进入静态扫描
12:05:40  sast 第 2 次尝试
12:07:02  新增 3 个候选（累计 11）
12:09:55  静态扫描完成 · 4 成功 1 跳过
```

这是把"过程"变成叙事最低成本的做法，也让 SSE 的历史不再被浪费。面板需支持
终态后保留（不随流断开而清空）。

**C. 顺序瀑布**

一行一个 task，按执行顺序排列，共用一根时间轴，条长即实际耗时，按阶段分组。
`timeout_seconds` 画为条末端的虚线刻度，显示该步距离被杀掉还有多远。

回答的核心问题："这次 40 分钟，是 CodeQL 占了 30 分钟，还是语义审计 6 个
scope 各 5 分钟。"

**D. Coverage 三态化**

区分"未知 / 进行中 / 已定"，不再把默认值当结论：

- 运行尚未进入构建阶段时，`build_status` 显示"尚未构建"，**不显示"失败"**
- `*_analyzed` 在其产出阶段完成前显示"待统计"，**不显示 `0%`**
- 判定依据取 `run.current_stage` 与阶段序，属纯前端推导

后端默认值本身的问题另行处理，见 5.2 H。

**E. Worker 列换成耗时占比**

该列改为"本阶段耗时占整次运行的比例"。带角色后缀的三类任务
（`:poc-author` / `:dynamic-verifier` / 复核）在任务行内以标签展示，不再占用
阶段行的一整列。

### 5.2 P2：需要小幅后端改动

**F. 阶段进入/退出时间戳**

当前阶段耗时由子任务时间反推（`StageTimeline.vue:183-197`），`ingesting` 与
`human_review` 没有子任务，永远显示 `-`。新增阶段转换记录后，瀑布图才完整，
报告中也才能写出"人工复核耗时 3 天"。

**G. 任务产物直达**

渲染 `output_artifact_ids` 为下载链接。后端接口与角色校验已具备，前端只需
接线，并对 `viewer` 隐藏敏感 Artifact 入口（沿用现有约束）。

**H. `build_status` 默认值**

`AuditCoverage` 构造默认 `FAILED`（`engine.py:2739`）在语义上是错的——尚未
构建不等于构建失败。两条路径：

1. **前端推导**（本计划采纳）：按 `run.current_stage` 判定是否已过构建阶段，
   未过则显示"尚未构建"。零后端风险，可立即落地。
2. **后端增加 `not_started` 态**：正确但会触及 `BuildStatus` 枚举、报告
   summary、SARIF 与 CP0 契约。

**不在本计划中执行第 2 条。** 契约变更不应夹带在表达层计划里，应单独评估。
本计划只负责在界面上不再传播这个错误值，并把该问题显式记录在案。

**I. 任务列表翻页**

`auditRunApi.tasks` 增加 offset 循环，或在达到上限时显式提示"仅显示前 500 个
任务"。静默截断违反 4.1。

### 5.3 P3：表达质量

**J. 运行叙事摘要**

一段自动生成的总结：

> 扫描 12 个模块 / 3,400 个 Java 文件；5 个静态工具完成 4 个，findsecbugs 因
> 构建未产出字节码跳过；语义审计 3 个类别中 SSRF 类因模型预算耗尽未完成；
> 动态验证 6 个候选，确认 4 个、inconclusive 2 个；2 个高危待人工处置。

与 HTML 报告使用同一份数据，可直接复用。这是最能"把审计过程讲清楚"的一块，
因为它把 coverage gap 表达成因果，而不是罗列。

**K. 排版**

`8-9px` 提升至 `11-12px`；窄屏改为次行折行，不再 `display: none` 丢弃元数据。

---

## 6. 与假设-验证回路的接口

回路落地后，运行详情页需要额外支持：

- `hypothesis_review` 阶段进入 `StageTimeline.definitions`
- 该阶段 summary 显示轮次进度："第 2/2 轮 · 3 个 scope 复验中"
- 同一 scope 在不同轮次的任务需能区分（`scope_key` 已带 `:r{n}` 后缀）
- 事件日志需表达结论演进："scope X 由 still_unknown 变为 supported"

其中第 4 条依赖本计划的 B 项。**B、C 两项应先于回路第 2 步落地**，否则回路
产生的过程信息在界面上无处安放。

---

## 7. 落地顺序

| 步骤 | 内容 | 依赖 |
| --- | --- | --- |
| 1 | D（Coverage 三态化）+ I（翻页提示） | 无。修正当前会误导用户的显示 |
| 2 | A（漏斗条）+ B（事件日志） | 无。消费已送达的数据 |
| 3 | C（顺序瀑布）+ E（Worker 列替换） | 无 |
| 4 | F（阶段时间戳）+ G（产物直达） | 后端小改 |
| 5 | J（叙事摘要）+ K（排版） | 依赖 F 的完整时间数据 |
| 6 | 回路相关展示 | 回路计划第 1-3 步 |

第 1 步排在最前的理由：它修正的是**当前正在向用户传播错误信息**的显示，
优先级高于任何新增能力。

---

## 8. 验收标准

1. 一次正常运行在构建完成之前，Coverage 区域**不出现**"构建失败"字样，
   `*_analyzed` 不显示误导性的 `0%`
2. 运行详情页在不刷新的情况下，可从事件日志读出完整的阶段进入顺序与每次重试
3. 顺序瀑布能一眼看出单次运行中耗时最长的任务，且该任务与后端记录一致
4. 任务数超过 500 时界面显式提示截断
5. 运行途中的 Finding 计数与 `/findings?audit_run_id=` 页面的统计一致
6. 阶段面板的展开状态在整次运行期间不被程序强制改变（已修复项的回归保护）
7. 全部新增视图在 `vue-tsc --noEmit` 与 `vitest` 下通过，并覆盖终态、失败态、
   取消态三种运行

---

## 9. 风险

**9.1 事件日志的内存增长。** 长时间运行会累积 snapshot 数组。对策：只保留
diff 结果而非完整 snapshot，并设置条目上限（超出后折叠为"更早的 N 条"）。

**9.2 瀑布图在任务数多时不可读。** 大型多模块工程的语义 scope 可能数十个。
对策：默认按阶段折叠，展开后才显示阶段内的逐任务条目。

**9.3 前端推导构建状态与后端真值漂移。** 5.2 H 采用的前端推导依赖阶段序判断。
若后端未来调整阶段顺序，推导会失效。对策：把阶段序常量与 `AuditStage` 枚举
放在一处，并在 5.2 H 的第 2 条落地后移除该推导。

---

## 10. 不在本计划范围内

- 后端 `BuildStatus` 枚举变更及其对报告、SARIF、CP0 契约的影响
- Fact–Intent 内部探索图的高级诊断视图（设计文档 §10.8，需先有只读 API）
- 任务级并发带来的泳道视图（编排器当前串行，见 4.2）
- 报告 HTML 模板的改版
- 权限模型与 Artifact 授权边界的任何调整

---

## 18. 交付记录

### 18.1 新增模块

| 文件 | 职责 |
| --- | --- |
| `src/stages.ts` | 阶段序、标签与 `stageProgress` / `hasPassedStage` 三态谓词，全页唯一来源 |
| `src/runClock.ts` | `buildRunClock` 时间归一化与共享的 `stageState` |
| `src/taskLabels.ts` | 从 `StageTimeline` 抽出的任务/范围/原因码标签；类别名委托给 `utils.categoryLabel` |
| `src/coverage.ts` | Coverage 三态、`buildStatusDisplay`、四处缺口合并的 `collectGaps` |
| `src/composables/useRunNarrative.ts` | 快照差分生成事件行 |
| `src/components/RunNarrative.vue` | 运行头的一句话状态 |
| `src/components/ProcessBar.vue` | 阶段游标 + 漏洞流转条 + 缺口计数 |
| `src/components/RunWaterfall.vue` | 顺序瀑布，含超时刻度与产出标注 |
| `src/components/GapList.vue` | 统一未审范围表 |
| `src/components/RunEventLog.vue` | 运行事件面板，含两条限制说明 |

### 18.2 已落地条目

- **D** Coverage 三态化：`build_status` 在构建阶段通过前显示"尚未构建"；`success` / `partial`
  因为不可能是默认值而立即显示；`*_analyzed` 在产出阶段完成前显示"待统计"而非 `0%`
- **I** 任务列表截断提示：`meta.total` 超过已加载条数时显式告知
- **A** 漏洞流转条：消费此前被丢弃的 `finding_counts`
- **B** 运行事件日志：`diffSnapshots` 纯函数 + 面板
- **C** 顺序瀑布：共享时间轴、阶梯形态、跳过/失败占位不留白、超时刻度、条右挂候选数
- **E** Worker 列换为耗时占比；角色后缀改为任务行内标签，Worker 明细保留在任务行
- **G** 任务产物直达：`output_artifact_ids` 渲染为下载链接
- **H** 方案一（前端推导）；后端 `BuildStatus` 枚举未动
- **原则 4.1** `skipped` 全局由中性灰改为琥珀（`StatusBadge`、阶段标记、缺口表一致）

### 18.3 未落地条目

- **F 阶段进入/退出时间戳** —— 需要后端记录与迁移。`ingesting` 与 `human_review`
  在瀑布中显示"无子任务，暂无时间数据"，是当前能给出的诚实表述
- **J 运行叙事摘要段落** —— 运行头的一句话状态已实现，整段自动摘要未实现
- **K 排版** —— 字号已从 8-9px 提升至 10-12px；窄屏仍以 `display: none` 逐级丢弃
  阶段元数据，未改为次行折行
- **第 6 节回路相关展示** —— 依赖回路计划落地

### 18.4 验证

- `vue-tsc --noEmit` 通过
- `vitest` 15 文件 62 测试通过（实施前 11 文件 29 测试）
- `vite build` 通过；Monaco 与 ECharts 的 chunk 体积告警为既有情况

新增测试覆盖：`stages.test.ts`（含 `building` 永不作为 `current_stage` 出现的边界）、
`coverage.test.ts`（三态与缺口合并，含"不为未知原因码编造解释"）、
`runClock.test.ts`（串行阶梯、跳过锚点、超时余量、运行中延伸）、
`useRunNarrative.test.ts`（首个快照为基线不产生事件）、
`AuditRunDetailView.test.ts`（构建前不报失败、截断提示、漏斗消费、叙事重建）。
