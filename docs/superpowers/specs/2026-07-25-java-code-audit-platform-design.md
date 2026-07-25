# Cairn Java 代码审计平台专用化设计

**状态：** 已确认设计

**日期：** 2026-07-25

**目标版本：** Java 代码审计 MVP，随后演进为单租户生产级平台

**部署基线：** Linux + Docker Compose；后续兼容 Kubernetes

---

## 1. 执行摘要

本设计将 Cairn 从通用状态空间搜索和渗透测试编排器，收敛为只执行 Java 代码审计的单租户平台。

平台保留现有 Dispatcher 中已经具备价值的并发调度、Worker Adapter、心跳、超时、取消、会话和容器生命周期能力；替换通用 `Project / Fact / Intent / Hint` 产品模型、通用 Prompt、渗透测试 Worker 镜像和无沙箱本地执行模式；新增代码仓库、不可变源码快照、审计运行、结构化漏洞、证据、机器验证、人工复核、覆盖率和报告等代码审计领域能力。

目标流水线固定为：

```text
源码接入
→ Java 项目预处理
→ 隔离构建
→ 确定性工具扫描
→ AI 语义审计
→ 候选漏洞归一化与去重
→ 动态验证
→ 独立机器复核
→ 高危人工复核
→ 覆盖率检查
→ 生成报告
```

平台首期同时支持私有 Git、ZIP 和浏览器目录上传；覆盖业务代码漏洞、依赖漏洞、密钥泄露、配置和 IaC 风险；允许在强隔离沙箱中构建、启动目标项目并生成验证请求或最小 PoC；严重和高危漏洞必须经过独立机器复核以及人工确认；平台只提供修复建议，不生成代码补丁，也不写回源码仓库。

---

## 2. 已确认的产品边界

### 2.1 首期范围

- 只支持 Java 代码审计。
- 支持 Maven、Gradle及其 Wrapper，并支持多模块工程。
- 支持 Git、ZIP 和浏览器目录上传。
- 只允许用户从平台页面手动发起审计。
- 不提供 Git Webhook、CI/CD 自动触发或质量门禁。
- 执行综合审计：业务代码、依赖、密钥、配置及 IaC。
- 静态分析与 AI 语义分析并行互补。
- 允许隔离构建、启动项目、运行测试和生成最小 PoC。
- 严重和高危漏洞经过独立机器复核后进入人工复核。
- 中危、低危和信息类问题可由机器确认后进入报告，但必须披露验证方法和置信度。
- 只输出修复建议，不生成补丁草案，不向仓库写回代码。
- 单租户部署，但保留角色权限和操作审计。
- MVP 使用 Docker Compose；生产阶段增加 Kubernetes Job 后端。

### 2.2 明确不做

- 渗透测试、CTF、资产探测、端口扫描、外部攻击面扫描。
- 通用问题求解、自由形式 Origin/Goal、数学证明或任意 Agent 任务。
- Python、Go、JavaScript、C/C++、PHP、C#、Rust 等非 Java 语言的语义审计。
- 多租户、租户配额、跨租户隔离、计费和租户管理员。
- 自动修复、自动提交、自动创建 Pull Request。
- 首期 PDF 报告。
- 首期 Webhook、CI 插件和 SARIF 自动上传；仅生成 SARIF 文件。
- 原生 Windows 运行；Windows 用户使用 WSL2。
- Agent 直接在宿主机执行。

### 2.3 混合语言仓库规则

- 仓库不包含 Java 文件时，拒绝创建 Java 审计运行，并返回稳定错误码 `NO_JAVA_SOURCE`。
- 混合语言仓库可以创建审计运行，但只审计 Java、JVM 构建文件及与 Java 应用直接相关的配置和 IaC。
- 未支持语言、目录和文件必须进入 Coverage 的未审计范围，并出现在最终报告中。

---

## 3. 设计原则

1. **代码审计是唯一业务。** 所有公开模型、页面、API、任务和配置都使用代码审计术语。
2. **控制面与执行面分离。** API 和数据库不运行目标代码；目标代码只能进入专用执行沙箱。
3. **源码不可变。** 每次审计绑定不可变 Snapshot 和确定的内容哈希。
4. **Finding 必须结构化。** 自由文本不能直接成为正式漏洞。
5. **证据优先。** 文件位置、调用链、工具结果、运行日志、请求响应和验证结论必须可追溯。
6. **候选不等于确认。** 单个工具或单个模型只能产生 Candidate Finding。
7. **完成由状态机决定。** 模型无权自行宣布整次审计完成。
8. **构建即执行不可信代码。** Maven 和 Gradle 构建采用与动态 PoC 同级别的隔离。
9. **仓库内容是不可信数据。** README、Agent 指令文件、代码注释、构建日志和工具输出都不能改变平台指令。
10. **允许部分成功，但不得隐藏缺口。** 构建失败或扫描器不可用时继续可执行阶段，终态和报告必须披露警告。
11. **单租户不等于无权限。** 平台仍需要身份认证、角色授权和不可抵赖的操作日志。
12. **先建立正确领域模型，再增加规模。** 不用自由文本 Fact 临时模拟正式漏洞库。

---

## 4. 现有能力的保留、替换与删除

### 4.1 保留并改造

- Dispatcher 主循环和并发额度。
- Worker Adapter 抽象。
- Worker 健康检查。
- Intent/Reason 现有的心跳、租约、超时和取消思想。
- 任务执行后的收尾和证据回写思想。
- 容器生命周期管理接口，但其实现迁移到受限 Sandbox Manager。
- 人工反馈思想，但替换为 Finding Review 和 AuditRun 操作。
- 内部 Fact–Intent 探索图，仅作为 AI 语义审计的诊断与因果记录。

### 4.2 替换

- `Project` 替换为 `Repository + SourceSnapshot + AuditRun`。
- 自由文本 `Fact` 替换为内部 `AuditFact`，正式漏洞使用 `Finding`。
- 通用 `Intent` 替换为受审计类型约束的 `AuditTask` 和内部 `AuditIntent`。
- 通用 Prompt 组替换为不可选择的 Java 审计 Prompt 版本。
- Kali 渗透测试镜像替换为 Java 分析、构建和验证镜像。
- 当前单页 Alpine 页面替换为 Vue 3 + TypeScript 审计工作台。
- Dispatcher 直接调用 Docker 替换为受限 Sandbox Manager API。

### 4.3 删除或禁用

- 通用 Origin、Goal、Hint 创建入口。
- 对外 Fact/Intent 写接口。
- Bootstrap 直接解决任意问题的行为。
- 渗透测试和 CTF Prompt、文档、工具说明及 Worker 镜像。
- `runtime.execution: local`。
- Agent 的 `--dangerously-skip-permissions` 和 `--dangerously-bypass-approvals-and-sandbox` 启动方式。
- `network_mode: host`。
- Dispatcher 的宿主机 Docker Socket 挂载。
- 用户自定义任意 Prompt 组。
- 用户自定义 Linux Capability。

---

## 5. 目标架构

```text
┌────────────────────────────────────────────────────────┐
│                     Web 管理界面                        │
│ 仓库 / 发起审计 / 进度 / 漏洞 / 高危复核 / 报告 / 设置 │
└──────────────────────────┬─────────────────────────────┘
                           │ HTTPS / SSE
┌──────────────────────────▼─────────────────────────────┐
│                       Audit API                         │
│ Repository / Snapshot / AuditRun / Finding / Report    │
└───────────────┬─────────────────────────┬──────────────┘
                │                         │
┌───────────────▼────────────┐  ┌─────────▼──────────────┐
│         PostgreSQL          │  │     Artifact Store      │
│ 状态、索引、审计日志、元数据 │  │ 源码快照、日志、证据、报告 │
└────────────────────────────┘  └────────────────────────┘
                           │
┌──────────────────────────▼─────────────────────────────┐
│                  Audit Orchestrator                     │
│ 阶段状态机 / 任务生成 / 租约 / 重试 / 预算 / 完成门槛   │
└──────────────┬───────────────────────┬─────────────────┘
               │                       │
        受限 Sandbox API          LLM Gateway API
               │                       │
┌──────────────▼─────────────┐   ┌─────▼────────────────┐
│       Sandbox Manager       │   │     LLM Gateway       │
│ 模板校验 / 创建 / 等待 / 销毁 │   │ 路由 / 短期令牌 / 脱敏 │
└──────────────┬─────────────┘   └──────────────────────┘
               │
       专用 Rootless Docker Daemon
               │
┌──────────────┼──────────────┬───────────────┐
│              │              │               │
▼              ▼              ▼               ▼
预处理容器      静态扫描容器    AI 只读分析环境  构建/动态验证环境
```

### 5.1 控制面组件

#### Audit API

- 使用 FastAPI 和 Pydantic。
- API 前缀统一为 `/api/v1`。
- 负责身份认证、授权、输入校验、状态读取、人工复核和报告下载。
- 不直接运行扫描器、构建命令或目标代码。
- 业务写入通过 PostgreSQL 事务完成。

#### Audit Orchestrator

- 复用现有 Dispatcher 核心思想。
- 读取 AuditRun 状态并生成固定类型 AuditTask。
- 依据 Worker 能力而不是单纯模型优先级分配任务。
- 维护任务租约、心跳、超时、重试和取消。
- 检查阶段门槛和最终完成条件。
- 是任务协议和内部探索图的唯一写入者。

#### PostgreSQL

- MVP 即使用 PostgreSQL，不使用 SQLite 作为正式数据库。
- 保存业务实体、任务状态、Finding、Review、Coverage 和操作日志。
- 数据库不保存源码文件、扫描原始大文件或 PoC 日志正文。

#### Artifact Store

- MVP 使用内容寻址的本地持久卷后端。
- 生产阶段增加 MinIO/S3 后端。
- 业务层只依赖统一的 `put/get/delete` 接口和 Artifact 元数据。
- 每个 Artifact 保存 SHA-256、大小、媒体类型、创建任务和访问级别。

#### LLM Gateway

- Worker 不持有外部模型长期密钥。
- 提供模型路由、短期运行令牌、请求大小限制、预算、脱敏、超时和熔断。
- 记录模型、版本、Token 和费用，但不在普通日志中保存完整源码 Prompt。

### 5.2 执行面组件

#### Source Ingestion

- 拉取受支持 Git 地址。
- 安全解压 ZIP 和浏览器目录归档。
- 生成不可变 Snapshot。
- 在完成拉取后清除 Git 凭据。
- 不执行任何仓库构建脚本。

#### Java Preprocessor

- 识别 Maven、Gradle、多模块和 Java/JDK 版本。
- 建立包、类、方法、注解、入口点、权限和 Sink 索引。
- 形成模块依赖图和构建计划。

#### Deterministic Scanner

- 运行 CodeQL、Semgrep、FindSecBugs、Dependency-Check、Trivy、gitleaks 和配置规则。
- 将不同格式转换为统一 Candidate Finding。

#### Semantic Reviewer

- 按模块、入口点、敏感 Sink 和漏洞类别分析业务语义。
- 通过只读 Audit Tool Broker 查询代码和索引。
- 没有任意 Shell、宿主机文件和通用网络权限。

#### Dynamic Verifier

- 在一次性沙箱中构建、运行测试、启动目标模块和依赖服务。
- 生成最小验证用例、HTTP 请求或 PoC。
- 收集请求、响应、日志、异常栈和退出状态。
- 不能访问控制面和宿主机网络。

#### Finding Pipeline

- 校验候选漏洞数据契约。
- 生成 fingerprint 并去重。
- 合并不同工具、模型和动态验证证据。
- 驱动独立机器复核和高危人工复核。

---

## 6. 领域模型

### 6.1 Repository

```text
Repository
- id: UUID
- name: string
- source_type: git | zip | local_upload
- remote_url: string | null
- credential_ref: string | null
- default_branch: string | null
- created_by: user_id
- created_at: timestamp
- updated_at: timestamp
```

- `credential_ref` 指向 SecretStore，不保存明文 Token、密码或私钥。
- ZIP 和目录上传不设置 `remote_url`。

### 6.2 SourceSnapshot

```text
SourceSnapshot
- id: UUID
- repository_id: UUID
- commit_sha: string | null
- content_sha256: string
- branch_or_tag: string | null
- artifact_id: UUID
- file_count: integer
- total_bytes: integer
- java_file_count: integer
- java_version: string | null
- build_system: maven | gradle | mixed | unknown
- status: creating | ready | rejected | failed
- failure_code: string | null
- created_at: timestamp
```

- Snapshot 一旦进入 `ready` 就不可修改。
- Git Snapshot 同时保存 Commit SHA 和内容 SHA-256。
- `content_sha256` 是规范化源码树哈希，不是 ZIP 文件本身的哈希：按规范化相对路径排序，对每个普通文件计算内容哈希，再对“路径、文件类型、可执行位、内容哈希”序列计算总哈希；忽略 ZIP 时间戳和归档顺序。
- ZIP、目录上传依赖规范化源码树哈希作为稳定版本标识，因此相同目录使用不同归档时间重新上传仍得到相同 `content_sha256`。

### 6.3 AuditPolicy

```text
AuditPolicy
- id: UUID
- name: string
- version: integer
- include_paths: string[]
- exclude_paths: string[]
- enabled_scanners: string[]
- dynamic_verification: required | preferred | disabled
- severity_thresholds: json
- resource_budget: json
- active: boolean
- created_at: timestamp
```

- 综合审计默认策略启用全部首期扫描器，动态验证为 `required`。
- `disabled` 只允许 admin 创建的策略使用；此类运行完成时必须包含覆盖警告。
- AuditRun 固定记录策略版本，后续修改不影响历史结果。

### 6.4 AuditRun

```text
AuditRun
- id: UUID
- repository_id: UUID
- source_request: json
- snapshot_id: UUID | null
- policy_id: UUID
- policy_version: integer
- status: AuditRunStatus
- current_stage: AuditStage | null
- progress: decimal
- warning_count: integer
- failure_code: string | null
- failure_reason: string | null
- created_by: user_id
- created_at: timestamp
- started_at: timestamp | null
- completed_at: timestamp | null
```

`AuditStage` 取值固定为 `ingesting | preprocessing | static_scanning |
semantic_auditing | dynamic_verifying | machine_review | human_review | reporting`。
AuditRun 处于 `created` 且尚未开始时 `current_stage` 为 `null`；取消、失败或完成后保留最后进入的阶段，便于审计和故障定位。

状态机：

```text
created
→ ingesting
→ preprocessing
→ static_scanning
→ semantic_auditing
→ dynamic_verifying
→ machine_review
→ human_review
→ reporting
→ completed | completed_with_warnings

任意运行态 → cancelling → cancelled
任意运行态 → failed
```

- 状态转换由服务端状态机校验。
- `source_request` 只允许三种结构：引用已有 ready Snapshot、指定 Git ref 创建新 Snapshot、引用已完成的 ZIP/目录上传；不得包含服务器本地路径或明文凭据。
- 引用已有 Snapshot 时仍进入一次短暂的 `ingesting` 校验步骤，用于确认 Snapshot 状态、Artifact 哈希和访问权限，然后立即进入 `preprocessing`。
- `created` 和 `ingesting` 阶段允许 `snapshot_id` 为空；进入 `preprocessing` 的前置条件是生成状态为 `ready` 的不可变 Snapshot 并写入 `snapshot_id`。
- `snapshot_id` 一旦写入就不能变更；重新拉取分支、重新上传源码或选择其他 Commit 必须创建新的 AuditRun。
- `progress` 根据各阶段权重和完成任务数量计算，不接受模型输出。

### 6.5 AuditTask

```text
AuditTask
- id: UUID
- audit_run_id: UUID
- parent_task_id: UUID | null
- type: AuditTaskType
- scope: json
- required_capabilities: string[]
- status: queued | claimed | running | succeeded | failed | cancelled | skipped
- worker_name: string | null
- attempt: integer
- max_attempts: integer
- timeout_seconds: integer
- input_artifact_ids: UUID[]
- output_artifact_ids: UUID[]
- error_code: string | null
- error_detail: string | null
- lease_expires_at: timestamp | null
- created_at: timestamp
- started_at: timestamp | null
- finished_at: timestamp | null
```

允许的任务类型：

```text
inventory
build
sast
dependency_scan
secret_scan
config_scan
semantic_review
dynamic_verify
independent_verify
coverage_check
report
```

AI 可以在 `semantic_review` 内建议细粒度 AuditIntent，但只能由 Orchestrator 转换为受支持的 AuditTask。

### 6.6 Finding

```text
Finding
- id: UUID
- audit_run_id: UUID
- fingerprint: string
- title: string
- description: string
- category: string
- cwe_id: string
- owasp_category: string | null
- severity: critical | high | medium | low | info
- confidence: confirmed | high | medium | low
- status: FindingStatus
- attack_preconditions: string
- impact: string
- remediation: string
- runtime_verification: verified | unverified | not_applicable
- discovered_by: string
- first_seen_at: timestamp
- updated_at: timestamp
```

状态机：

```text
candidate
→ validating
→ machine_confirmed
→ awaiting_human_review
→ confirmed

candidate | validating → rejected
awaiting_human_review → confirmed | rejected | accepted_risk
confirmed → accepted_risk
```

- 严重和高危从 `machine_confirmed` 进入 `awaiting_human_review`。
- 中危及以下可从 `machine_confirmed` 进入最终报告，状态保持 `machine_confirmed`。
- 人工选择 `reverify` 时，Finding 从 `awaiting_human_review` 回到 `validating`，并创建新的 `independent_verify` 或 `dynamic_verify` 任务；新验证完成后再次进入人工队列。

### 6.7 FindingLocation

```text
FindingLocation
- id: UUID
- finding_id: UUID
- role: entrypoint | source | propagation | sink | related
- file_path: string
- start_line: integer
- end_line: integer
- symbol: string | null
- code_snippet: string
- snapshot_sha: string
- ordinal: integer
```

- 一条 Finding 可以跨越多个文件和方法。
- 所有位置必须绑定 Snapshot SHA，防止报告定位到错误版本。

### 6.8 Artifact

```text
Artifact
- id: UUID
- audit_run_id: UUID
- kind: source_snapshot | scan_result | build_log | runtime_log | poc | report | other
- storage_key: string
- sha256: string
- size_bytes: integer
- media_type: string
- access_level: normal | sensitive
- produced_by_task_id: UUID | null
- created_at: timestamp
- expires_at: timestamp | null
```

### 6.9 Evidence

```text
Evidence
- id: UUID
- finding_id: UUID
- type: code_snippet | call_trace | tool_result | build_log | unit_test | poc_output | http_exchange | runtime_log
- artifact_id: UUID | null
- summary: string
- sha256: string | null
- produced_by_task_id: UUID
- created_at: timestamp
```

### 6.10 Verification

```text
Verification
- id: UUID
- finding_id: UUID
- method: static_corroboration | independent_agent | build_test | dynamic_poc
- verdict: confirmed | rejected | inconclusive
- verifier: string
- evidence_ids: UUID[]
- reasoning: string
- created_at: timestamp
```

- 原发现 Worker 不能作为同一 Finding 的独立复核 Worker。
- 超时和环境不可用只能生成 `inconclusive`。

### 6.11 AuditCoverage

```text
AuditCoverage
- audit_run_id: UUID
- modules_total: integer
- modules_analyzed: integer
- java_files_total: integer
- java_files_analyzed: integer
- entrypoints_total: integer
- entrypoints_analyzed: integer
- sensitive_sinks_total: integer
- sensitive_sinks_analyzed: integer
- build_status: success | partial | failed
- static_tools_completed: json
- skipped_paths: json
- unsupported_components: json
- coverage_warnings: json
- updated_at: timestamp
```

### 6.12 HumanReview

```text
HumanReview
- id: UUID
- finding_id: UUID
- verdict: confirmed | rejected | accepted_risk | reverify
- original_severity: FindingSeverity
- final_severity: FindingSeverity
- reviewer_id: user_id
- comment: string
- reviewed_at: timestamp
```

### 6.13 Report

```text
Report
- id: UUID
- audit_run_id: UUID
- version: integer
- summary_json: json
- html_artifact_id: UUID
- json_artifact_id: UUID
- sarif_artifact_id: UUID
- generated_at: timestamp
```

### 6.14 内部 AuditFact 与 AuditIntent

内部探索图不直接作为漏洞库：

```text
AuditFact
- id
- audit_run_id
- kind: architecture | entrypoint | trust_boundary | source | sink | candidate_finding | verification_result
- structured_payload
- evidence_ids
- created_by_task_id
- created_at

AuditIntent
- id
- audit_run_id
- category
- scope
- required_capabilities
- source_fact_ids
- status: pending | claimed | concluded | cancelled
- created_by_task_id
- claimed_by_task_id
- created_at
- concluded_at
```

`candidate_finding` 只有通过 Finding Pipeline 的数据契约、位置校验和去重后，才创建正式 Finding。

---

## 7. 完整审计工作流

### 7.1 源码接入

1. 用户选择 Git、ZIP 或浏览器目录上传。
2. Git 拉取后解析并固定 Commit SHA。
3. ZIP 和目录上传计算规范化源码树 SHA-256。
4. 检查路径穿越、符号链接逃逸、解压体积、文件数量、单文件大小、嵌套仓库和子模块。
5. 生成只读 Snapshot Artifact。
6. 清理接入容器和 Git 凭据。

接入失败时 AuditRun 进入 `failed`，不进入分析阶段。

MVP 不自动初始化 Git submodule 或 Git LFS：平台记录对应路径并生成 Coverage 警告；若缺失内容导致无法构建，按构建失败策略继续源码级审计。后续支持这些来源时仍必须经过 Git 主机允许列表和独立 Snapshot 固化流程。

### 7.2 Java 项目预处理

识别并索引：

- Maven、Gradle、Wrapper 和多模块结构。
- Java/JDK 版本。
- Spring Boot、Spring MVC、Spring Security、MyBatis、Hibernate、Struts 等框架。
- Controller、Filter、Interceptor、Servlet、RPC、MQ Consumer 和定时任务。
- 数据库、HTTP、文件、命令、反序列化、表达式和模板等敏感 Sink。
- 身份认证、权限注解和安全配置。
- 配置文件、Dockerfile、Kubernetes YAML 和 Terraform。
- 测试、生成代码、第三方源码和默认排除目录。

输出模块依赖图、符号索引、入口清单、权限清单、Source/Sink 清单、构建计划和初始 Coverage。

### 7.3 隔离构建

构建顺序：

```text
Maven Wrapper
→ 系统 Maven
→ Gradle Wrapper
→ 系统 Gradle
```

只执行与识别到的构建系统匹配的路径，不在 Maven 项目上无条件尝试 Gradle。

产物：

- 编译日志和退出状态。
- 依赖树。
- 字节码和测试结果。
- CodeQL Database。
- SpotBugs/FindSecBugs 输入。

构建失败时：

- Semgrep、源码语义、密钥和配置扫描继续。
- 尝试直接解析 POM、Gradle 文件和依赖锁文件。
- 字节码分析和动态验证标记不可用。
- AuditRun 最终至少为 `completed_with_warnings`，除非后续出现致命控制面错误。

### 7.4 确定性工具扫描

并行运行：

| 审计类型 | 工具或能力 |
| --- | --- |
| SAST | CodeQL、Semgrep、FindSecBugs |
| 依赖漏洞 | OWASP Dependency-Check、Trivy、OSV 数据 |
| 密钥泄露 | gitleaks |
| 配置审计 | Spring、Docker、Kubernetes、Terraform 规则 |
| 自定义规则 | 平台内置 Java 安全规则库 |

所有结果先转换成 Candidate Finding，不直接进入最终报告。

### 7.5 AI 语义审计

Orchestrator 按“模块 + 攻击面 + 漏洞类别”拆分任务，例如：

```text
模块：user-service
攻击面：REST Controller
类别：水平越权与垂直越权
范围：Controller → Service → Repository 调用链
```

重点检查：

- 身份认证与会话管理。
- 水平和垂直越权。
- SQL、NoSQL、LDAP、表达式和模板注入。
- SSRF。
- 任意文件读写和路径穿越。
- 命令执行。
- 不安全反序列化。
- SpEL、OGNL、XXE。
- 不安全上传和下载。
- URL 跳转。
- 密码学和敏感数据。
- Spring Security 配置错误。
- 被审计系统自身的业务数据隔离问题。
- 竞态、金额、订单和业务状态机漏洞。

模型输出必须包含：

- 文件和行号。
- 入口到 Sink 的调用链。
- 外部输入如何可控。
- 已有防护以及为何有效或可绕过。
- 攻击前提和影响。
- 推荐验证方式。

缺少代码位置、调用链或可控性说明的输出不会创建 Finding。

### 7.6 归一化与去重

默认 fingerprint：

```text
SHA-256(
  snapshot_sha
  + normalized_cwe
  + normalized_sink_symbol
  + normalized_source_symbol
  + normalized_file_path
)
```

多工具和多 Agent 命中同一根因时合并 Evidence、调用链、验证建议和严重性判断。结论冲突时进入验证，不直接采用最高严重性。

### 7.7 动态验证

1. 从只读 Snapshot 创建任务独占工作副本。
2. 构建并启动目标模块。
3. 按构建计划启动允许的临时 PostgreSQL、MySQL、Redis 或 HTTP 回显服务。
4. 生成测试、HTTP 请求或最小 PoC。
5. 保存请求、响应、日志、异常栈、测试结果和退出状态。
6. 销毁应用、依赖容器、网络和临时卷。

结果只能是：

```text
confirmed
rejected
inconclusive
```

环境缺失、构建失败和超时产生 `inconclusive`，不能产生 `rejected`。

### 7.8 独立机器复核

- 严重和高危 Candidate 必须进入独立复核。
- 独立 Worker 不读取原发现者的自由推理过程。
- 独立 Worker 只获得候选类别、源码位置和必要上下文，并自行重建调用链。
- 可动态验证时必须检查动态证据或重新复现。

确认路径：

```text
原始发现 + 独立 Worker 确认 + 动态验证成功
```

动态环境客观不可构建时允许：

```text
原始发现 + 两个独立静态结论 + runtime_verification=unverified
```

### 7.9 人工复核

严重和高危 Finding 进入人工队列。复核人可以：

- 确认。
- 驳回并填写理由。
- 接受风险。
- 调整严重性。
- 发起重新验证。
- 查看调用链、PoC、请求响应和完整运行证据。

中危及以下不强制人工确认，但必须显示机器验证方式和置信度。

### 7.10 完成门槛

AuditRun 只有满足以下条件才能进入报告阶段：

- 所有范围内文件已完成清点。
- 所有入口点和敏感 Sink 已分配审计任务或记录排除理由。
- 必选静态工具已成功完成或记录失败原因。
- 不存在运行中、已认领但失联或未处置的任务。
- 所有严重和高危候选已验证或明确标记运行时无法验证。
- 人工复核队列已清空。
- 所有跳过路径、未支持组件和覆盖缺口已记录。

模型输出不能跳过这些检查。

---

## 8. 错误处理、重试与恢复

| 场景 | 行为 |
| --- | --- |
| Git/上传接入失败 | AuditRun 失败，不创建 ready Snapshot |
| 构建失败 | 继续源码级扫描，禁用依赖字节码的任务，记录 Coverage 警告 |
| 工具瞬时失败 | 最多重试两次，仍失败则记录工具失败 |
| Agent 输出非法 | 不落库，更换 Worker 重试 |
| Worker 心跳丢失 | 终止进程、释放租约、重新排队 |
| 动态验证超时 | 结果为 inconclusive |
| Artifact 写入失败 | 暂停运行，不允许丢失证据后继续 |
| 数据库写入失败 | 事务回滚，任务不标记成功 |
| 用户取消 | 停止新任务，取消运行任务，销毁沙箱，保留已有证据 |
| Dispatcher 重启 | MVP 恢复过期租约；生产阶段增加完整任务恢复审计 |
| 重复 Finding | 合并证据，不创建重复记录 |

错误响应使用稳定结构：

```json
{
  "error_code": "SNAPSHOT_ARCHIVE_PATH_ESCAPE",
  "message": "Archive contains a path outside the extraction root",
  "request_id": "..."
}
```

日志不得包含 Git Token、LLM Key、Cookie、完整源码正文或敏感 PoC 数据。

---

## 9. 安全隔离设计

### 9.1 四个安全域

```text
控制域：Web / API / PostgreSQL / Artifact Metadata
源码接入域：Git Clone / ZIP 解压 / Snapshot 生成
分析域：静态工具 / AI 语义审计
执行域：Maven/Gradle 构建 / 测试 / 应用启动 / PoC
```

四个安全域使用独立网络和身份。源码和执行容器不能直接访问数据库或控制 API。

### 9.2 Sandbox Manager

Dispatcher 不直接访问 Docker。内部协议：

```text
SandboxBackend
- create(template, snapshot, limits)
- start(sandbox_id)
- wait(sandbox_id, timeout)
- cancel(sandbox_id)
- collect_artifacts(sandbox_id)
- destroy(sandbox_id)
```

MVP 实现 `RootlessDockerBackend`；生产阶段增加 `KubernetesJobBackend`。

Sandbox Manager 仅接受平台内置模板，不接受 Agent 提交的镜像名、宿主机路径、Capability、网络模式或特权参数。

### 9.3 容器安全基线

所有分析、构建和验证容器：

- 非 root 用户。
- 只读根文件系统。
- `cap_drop: ALL`。
- `no-new-privileges`。
- 禁止 privileged。
- 禁止 host PID、IPC 和 network。
- 禁止 Docker Socket。
- 限制 CPU、内存、磁盘、PID 和执行时长。
- 任务结束强制销毁。

目录：

```text
/work/source   只读 Snapshot
/work/scratch  当前任务独占可写目录
/work/output   只写审计证据
/tmp           限额 tmpfs
```

### 9.4 网络设计

```text
control-net
  Web、API、PostgreSQL、Artifact Store

ingestion-net
  只允许访问配置过的 Git 主机

build-net
  只允许访问配置过的 Maven/Nexus 镜像

analysis-net
  只允许访问 LLM Gateway 和受限 Artifact API

validation-net-<run-id>
  目标应用、临时数据库和回显服务互通
  默认禁止互联网、控制域、宿主机和云元数据地址
```

Maven 和 Gradle 依赖必须通过配置的 Nexus/代理；动态验证 SSRF 使用隔离网络内的回显服务。

### 9.5 凭据设计

#### Git 凭据

- MVP SecretStore 使用 AES-256-GCM 加密，主密钥通过 Docker Secret 挂载。
- 数据库保存密文和 credential reference，不保存明文。
- 只有 Source Ingestion 服务能够解密。
- Clone 完成后不将凭据写入 Snapshot、构建环境或 Agent 环境。
- 生产阶段可以增加 Vault SecretStore 适配器。

#### LLM 凭据

- 外部模型 Key 只存在于 LLM Gateway。
- Worker 使用绑定 AuditRun、Worker 和过期时间的短期内部 Token。
- Gateway 执行模型允许列表、费用限制、日志脱敏和数据外发策略。

### 9.6 Prompt Injection 防护

以下全部作为不可信数据：

- README。
- AGENTS.md、CLAUDE.md 及类似文件。
- 代码注释。
- 测试数据。
- 构建日志。
- 扫描器输出。

约束：

- Agent 从平台控制目录启动，不从源码根目录加载上下文文件。
- 禁止 CLI 自动加载仓库内的 Agent 指令。
- 系统指令和源码内容分通道传递。
- Semantic Reviewer 只能使用只读 Tool Broker。
- 构建和验证只能通过受控 Sandbox API。
- 输出必须通过严格 JSON Schema。
- 外部上传、凭据读取、关闭安全策略和任意联网请求不会被工具层执行。

### 9.7 Worker 权限

| Worker | 权限 |
| --- | --- |
| Inventory | 只读文件、AST 和构建文件解析 |
| SAST/SCA | 只读源码，写扫描结果 |
| Semantic Reviewer | 只读索引及有限源码片段，无任意 Shell |
| Build Worker | Maven/Gradle，仅限构建沙箱 |
| Dynamic Verifier | 启动目标程序及访问验证网络 |
| Independent Reviewer | 只读源码和验证证据 |
| Reporter | 只读结构化 Finding，不读取完整源码 |

### 9.8 单租户权限模型

```text
admin
  系统配置、凭据、规则、策略和用户管理

auditor
  仓库管理、发起/取消审计、重新验证

reviewer
  严重/高危确认、驳回、接受风险和调整严重性

viewer
  只读结果和报告
```

MVP 使用本地账号、Argon2id 密码哈希、HttpOnly/Secure/SameSite Cookie 和 CSRF 防护；生产阶段增加 OIDC。

关键操作写入操作审计日志：

- 创建和删除仓库。
- 发起、取消和重试 AuditRun。
- 修改规则和策略。
- 查看敏感 Artifact。
- 人工确认、驳回和调整漏洞。
- 导出报告。
- 修改凭据和用户。

---

## 10. 产品界面

### 10.1 导航

```text
仪表盘
仓库
审计任务
漏洞
人工复核
规则与策略
系统设置
审计日志
```

删除通用搜索图首页、Goal 创建和 Hint 操作。

### 10.2 仪表盘

显示：

- 最近 AuditRun。
- 运行中、等待复核、失败和警告数量。
- 各严重性 Finding 数量。
- 构建失败和 Coverage 警告。
- Worker、扫描器、LLM Gateway 和 Sandbox Manager 健康状态。

### 10.3 仓库页面

支持：

1. Git URL + Branch/Tag/Commit。
2. ZIP 上传。
3. 浏览器目录选择，客户端归档后上传。

不允许输入任意服务器路径。

详情显示源码来源、Snapshot、Commit、模块、Java/框架版本、历史审计和凭据状态。

### 10.4 发起审计

用户选择：

- Repository 和 Snapshot。
- include/exclude 路径。
- JDK 自动识别或显式覆盖。
- 受限构建参数覆盖：只允许选择 Maven/Gradle 任务、Profile、测试开关和平台允许列表中的系统属性，不接受任意 Shell 字符串。
- AuditPolicy。
- 资源和时间预算。

综合策略默认启用动态验证。只有 admin 创建的静态策略可以禁用，且报告必须显示警告。

### 10.5 AuditRun 详情

固定展示：

```text
源码接入
项目预处理
隔离构建
静态扫描
AI 语义审计
动态验证
机器复核
人工复核
覆盖检查
生成报告
```

每个阶段显示状态、耗时、任务数、Worker、重试、日志、Artifact 和覆盖警告。状态通过 SSE 推送。

### 10.6 Finding 详情

显示：

- 标题、CWE、严重性、置信度和状态。
- 攻击前提和影响。
- 入口、传播路径和 Sink 调用链。
- 文件、行号、符号和代码片段。
- 静态工具证据。
- AI 语义分析。
- 动态 PoC 和运行日志。
- 独立机器复核。
- 人工复核记录。
- 修复建议。

使用 Monaco Editor 展示只读代码并定位 Snapshot 中的行号。

### 10.7 人工复核队列

只包含严重和高危漏洞。支持确认、驳回、接受风险、调整严重性、填写意见和重新验证。

批量确认仅允许同一规则、同一根因且证据一致的 Finding。

### 10.8 内部探索图

Fact–Intent 图移动到管理员和 auditor 可见的“高级诊断”，仅用于解释 Agent 方向、任务生成、Worker 重试和候选漏洞来源。

### 10.9 前端技术

使用：

- Vue 3。
- TypeScript。
- Vite。
- Pinia。
- Vue Router。
- Monaco Editor。
- ECharts。

构建产物仍由 FastAPI 托管，不单独运行 Node 服务。

---

## 11. API 设计

### 11.1 Repository 与 Snapshot

```text
POST   /api/v1/repositories
GET    /api/v1/repositories
GET    /api/v1/repositories/{id}
DELETE /api/v1/repositories/{id}

POST   /api/v1/uploads
POST   /api/v1/repositories/{id}/snapshots
GET    /api/v1/snapshots/{id}
```

### 11.2 AuditRun

```text
POST   /api/v1/audit-runs
GET    /api/v1/audit-runs
GET    /api/v1/audit-runs/{id}
POST   /api/v1/audit-runs/{id}/cancel
POST   /api/v1/audit-runs/{id}/retry
GET    /api/v1/audit-runs/{id}/events
```

### 11.3 Finding 与复核

```text
GET    /api/v1/findings
GET    /api/v1/findings/{id}
POST   /api/v1/findings/{id}/review
POST   /api/v1/findings/{id}/reverify
```

### 11.4 Artifact 与报告

```text
GET    /api/v1/artifacts/{id}
GET    /api/v1/reports/{id}
POST   /api/v1/audit-runs/{id}/reports
```

### 11.5 API 约束

- 所有列表分页。
- 支持按 Repository、AuditRun、CWE、严重性和状态过滤。
- Pydantic 模型禁止未声明字段。
- 所有错误提供稳定 `error_code` 和 `request_id`。
- Artifact 下载检查角色并写审计日志。
- 删除 Repository 前检查关联运行、Snapshot 和报告。
- 不提供通用 Intent/Fact 外部写接口。
- 不提供 Webhook 或 CI 触发接口。

---

## 12. 报告设计

### 12.1 管理摘要

- 仓库、Snapshot、Commit 和策略版本。
- 总体风险评级。
- 各严重性漏洞数量。
- 最重要风险。
- 构建和 Coverage 状态。
- 未审计范围和运行警告。

### 12.2 技术报告

每个 Finding 包括：

- 稳定编号和 fingerprint。
- CWE、OWASP、严重性和置信度。
- 文件和行号。
- 完整调用链。
- 可控性和利用条件。
- 动态验证证据或运行时未验证标记。
- 修复建议。
- 人工复核结论。

### 12.3 输出格式

- HTML：主要交互报告。
- JSON：完整机器可读结果。
- SARIF 2.1.0：保留后续代码平台集成能力。

首期不生成 PDF。

---

## 13. 分阶段实施路线

整体拆分为七个独立可验收子项目。每个子项目完成后保持主分支可运行，不进行一次性大爆炸重写。

### 13.1 子项目一：领域模型重置

交付：

- 新领域实体和 PostgreSQL Schema。
- `/api/v1` 基础接口。
- AuditRun 和 Finding 状态机。
- 数据库迁移框架。
- 删除通用任务创建入口。

验收：

- 平台无法创建渗透测试、CTF 或通用问题。
- AuditRun 绑定不可变 Snapshot。
- 状态转换经过服务端校验。
- 自由文本不能直接创建 confirmed Finding。

### 13.2 子项目二：源码与 Artifact 管理

交付：

- Git、ZIP 和目录上传。
- Commit 和内容哈希。
- 只读 Snapshot。
- SecretStore。
- 本地 Artifact 后端。
- 上传和解压安全限制。

验收：

- 三种来源进入统一 Snapshot。
- 相同源码产生相同内容哈希。
- ZIP Slip、符号链接逃逸和压缩炸弹被拒绝。
- Agent 无法获取 Git 凭据。
- ready Snapshot 不可修改。

### 13.3 子项目三：Sandbox Manager

交付：

- 独立 Sandbox Manager。
- 专用 Rootless Docker daemon。
- 预定义分析、构建和验证模板。
- 资源、网络、超时、取消和清理。

验收：

- Dispatcher 不挂载宿主机 Docker Socket。
- Maven 插件无法访问控制面和宿主机。
- 不允许 privileged、host network 和任意宿主机挂载。
- 超时和取消后无残留沙箱资源。
- Artifact 在沙箱销毁后仍可读取。

### 13.4 子项目四：Java 确定性分析

交付：

- Maven/Gradle、多模块和 JDK 检测。
- 构建、依赖树、符号、入口、权限和 Sink 索引。
- CodeQL、Semgrep、FindSecBugs、Dependency-Check、Trivy、gitleaks 和配置规则。
- 工具结果统一转换。

验收：

- Maven 和 Gradle 示例项目均能完成分析。
- 构建失败时源码扫描继续。
- 工具结果包含规则、CWE、位置和原始 Artifact。
- 同根因结果能够合并。
- 每个工具状态进入 Coverage。

### 13.5 子项目五：AI 语义审计

交付：

- 固定 Java 审计 Prompt。
- 语义任务拆分。
- 只读 Tool Broker。
- JSON Schema。
- 调用链与可控性检查。
- fingerprint、去重和 LLM Gateway。

验收：

- AI 无权直接确认 Finding。
- 缺少位置、调用链或可控性说明的输出被拒绝。
- 仓库 Agent 指令文件不能改变平台任务。
- fingerprint 对相同 Snapshot 稳定。
- Agent 无法访问长期凭据和任意互联网。

### 13.6 子项目六：动态验证与机器复核

交付：

- 临时构建和验证环境。
- 受支持的数据库、Redis 和 HTTP 回显依赖。
- 应用启动探测。
- 测试、请求和最小 PoC。
- Evidence 收集。
- 独立 Worker 盲审。

验收：

- 超时产生 inconclusive。
- 动态证据保存请求、响应、日志和退出状态。
- 原发现者不能承担独立复核。
- 严重和高危未机器复核前不能进入人工队列。
- 沙箱销毁后目标服务不可继续访问。

### 13.7 子项目七：审计工作台与报告

交付：

- Vue 3 + TypeScript 前端。
- Repository、AuditRun、Finding、Coverage 和 Review 页面。
- SSE。
- HTML、JSON 和 SARIF 报告。
- 角色权限和操作日志。

验收：

- 用户可以完全通过页面导入源码并发起审计。
- 构建失败和覆盖缺口同时显示在运行页和报告。
- 严重和高危必须人工处置。
- 代码位置可追溯到 Snapshot。
- viewer 无法修改结果或访问受限制 Artifact。

---

## 14. MVP 总体验收标准

MVP 必须满足：

1. 导入 Git、ZIP 和目录形式的 Java 项目。
2. 固定并展示源码 Commit 或内容哈希。
3. 完成静态、依赖、密钥、配置和 AI 语义分析。
4. 在隔离环境构建并启动可运行项目。
5. 动态验证适用的 Candidate Finding。
6. 对严重和高危执行独立机器复核。
7. 由人工处置所有严重和高危 Finding。
8. 输出带 Coverage 和未审计范围的完整报告。
9. 在恶意 Maven/Gradle 项目下保护宿主机和控制面。
10. 全流程不包含渗透测试、CTF、通用 Goal 或本地 Agent 执行。
11. 不生成代码补丁，不写回源码仓库。
12. 所有关键操作和敏感 Artifact 访问可审计。

---

## 15. 生产级升级

MVP 稳定后，在不引入多租户的前提下完成以下升级。

### 15.1 可靠性

- Dispatcher 重启后的任务恢复。
- 数据库租约、幂等键和状态转换审计。
- Sandbox Manager 崩溃后的孤儿资源清理。
- Artifact 从本地卷迁移至 MinIO/S3。
- PostgreSQL 备份、恢复和保留策略。
- 失败任务死信视图和人工重试。

### 15.2 性能

- Maven/Gradle 只读依赖缓存。
- 按 Snapshot 哈希复用 CodeQL Database 和源码索引。
- 大型多模块工程按模块并行。
- 模型上下文按符号和调用链检索。
- 限制全仓库内容直接进入模型。
- 分离扫描器、模型和动态沙箱并发额度。

### 15.3 安全

- OIDC。
- LLM 数据外发策略和模型供应商策略。
- 镜像 digest 固定。
- SBOM、镜像签名和构建来源记录。
- seccomp 和 AppArmor 策略。
- Nexus、Git 和模型出口白名单。
- Artifact 加密和更完整的敏感数据脱敏。
- 可选 gVisor 或 Kata Containers 后端。

### 15.4 Kubernetes

- 实现 `KubernetesJobBackend`。
- 每个 AuditTask 使用独立 Job、NetworkPolicy、ResourceQuota 和临时卷。
- 业务层和 Orchestrator 继续依赖统一 SandboxBackend。
- 不建设租户 Namespace、租户配额或跨租户权限。

---

## 16. 测试策略

### 16.1 单元测试

覆盖：

- AuditRun 和 Finding 状态机。
- fingerprint 稳定性。
- 严重性规则。
- JSON Schema。
- Finding 去重与证据合并。
- 权限矩阵。
- 完成门槛。
- Coverage 计算。
- 错误码。

### 16.2 集成测试

覆盖：

- Git、ZIP 和目录导入。
- PostgreSQL 事务和迁移。
- Artifact 生命周期。
- Sandbox 创建、运行、取消和销毁。
- Maven/Gradle 构建。
- 扫描器输出转换。
- LLM Gateway 请求和预算。
- 动态验证 Evidence 回写。
- SSE 状态推送。

### 16.3 安全回归测试

构造恶意仓库验证：

- ZIP Slip。
- 符号链接逃逸。
- 压缩炸弹。
- Maven 插件命令执行。
- Gradle 初始化和构建脚本执行。
- 仓库 Prompt Injection。
- 云元数据 SSRF。
- 控制网络探测。
- Fork Bomb。
- 磁盘填满。
- 超大日志。
- 密钥诱导外传。
- 容器退出后残留进程和网络。

### 16.4 审计效果基准

基准集合：

- OWASP BenchmarkJava。
- WebGoat。
- 自建 Spring Boot 鉴权、越权、SSRF、文件、注入和业务状态漏洞集。
- 每个漏洞的已修复与未修复成对样本。

持续记录：

- 严重和高危召回率。
- 人工复核前精确率。
- 错误文件和行号率。
- 动态复现成功率。
- 重复 Finding 比例。
- 每万行 Java 代码耗时。
- 每次 AuditRun Token 和费用。
- 构建成功率和 Coverage 缺口。

### 16.5 CI 基线

- 正式 CI 仅运行在 Linux。
- Windows 开发使用 WSL2。
- 每次合并执行单元、API、数据库和容器集成测试。
- 每日运行 Java 漏洞基准。
- 每周运行完整恶意仓库隔离测试。
- CI 同时执行 lint、类型检查、依赖扫描、SAST 和镜像扫描。

---

## 17. 可观测性与预算

每次 AuditRun 记录：

- 各阶段等待和执行时间。
- 每种 AuditTask 成功、失败、重试和取消数量。
- Worker 健康和租约丢失。
- 每个扫描器版本和规则版本。
- 模型名称、版本、Token 和费用。
- 构建与动态沙箱 CPU、内存、磁盘和时长。
- Artifact 数量和总大小。
- Coverage 和未审计范围。

预算限制：

- 单次上传大小。
- 解压后总大小和文件数量。
- 单任务 CPU、内存、PID、磁盘和时长。
- 单 AuditRun 最大并行构建和验证环境。
- 单 AuditRun LLM Token 和费用。
- Artifact 保留期限。

预算处理规则固定如下：

- 上传大小、解压体积、文件数量、单任务 PID、磁盘或内存超过硬限制时立即终止相关阶段；接入阶段超限使 AuditRun 进入 `failed`，运行任务超限按任务失败处理并触发既定重试策略。
- 单次 AuditRun 总时长、LLM Token 或费用达到软上限时停止派发新的语义扩展任务，保留已完成结果；若所有严重/高危候选已处置且完成门槛仍满足，则进入 `completed_with_warnings`，否则进入 `failed` 并使用错误码 `AUDIT_BUDGET_EXHAUSTED`。
- 并行构建和验证数量达到上限时任务保持 `queued`，不视为失败。
- Artifact 达到保留期限后由后台清理；SourceSnapshot、最终报告及被 Finding 引用的 Evidence 在关联 Repository/AuditRun 存续期间不按普通临时 Artifact 期限清理。

---

## 18. 数据与产品迁移

现有通用 Cairn 数据不迁移到新领域表，因为 Fact/Intent 无法可靠映射为 Finding、Evidence 和 Verification。

迁移步骤：

1. 提供旧项目 YAML 和 Timeline 导出命令。
2. 新版本使用独立 PostgreSQL Schema。
3. 移除旧 UI 和旧项目写接口。
4. 只读旧数据归档工具保留一个正式版本周期。
5. 删除渗透测试 Prompt、Kali Worker 镜像和相关文档。
6. 更新 README，只描述 Java 代码审计平台。
7. 删除或归档与通用问题求解和渗透测试有关的示例配置。

不提供旧 Fact 自动生成 Finding 的转换器，以免把未经验证的自由文本当作正式漏洞。

---

## 19. 关键决策记录

| 决策 | 结果 |
| --- | --- |
| 产品定位 | 只做 Java 综合代码审计 |
| 架构路线 | 保留 Cairn 调度内核，重建代码审计领域层 |
| 租户 | 单租户，不建设 tenant_id 和租户隔离 |
| 源码来源 | Git、ZIP、浏览器目录上传 |
| 触发方式 | 仅页面手动发起 |
| 动态能力 | 支持深度构建、启动和 PoC 验证 |
| 高危处置 | 独立机器复核后人工确认 |
| 修复能力 | 只给修复建议，不生成或写回补丁 |
| MVP 部署 | Linux + Docker Compose + Rootless Docker Sandbox |
| 数据库 | MVP 起使用 PostgreSQL |
| Artifact | MVP 本地内容寻址存储，生产迁移 MinIO/S3 |
| 前端 | Vue 3 + TypeScript，构建产物由 FastAPI 托管 |
| 正式报告 | HTML、JSON、SARIF；首期无 PDF |
| 生产演进 | 增强可靠性、安全、性能并增加 Kubernetes 后端，不增加多租户 |

---

## 20. 设计完成定义

本设计实现后的平台必须满足以下不可协商条件：

- 用户无法通过公开功能创建非代码审计任务。
- 平台不包含渗透测试和 CTF 运行能力。
- 不可信源码永不在宿主机或控制面直接执行。
- 每个 Finding 可追溯至不可变 Snapshot、代码位置、发现任务和验证证据。
- 严重和高危 Finding 未经独立机器复核及人工处置不能进入最终确认状态。
- 模型不能绕过状态机、Coverage 和完成门槛。
- 构建或工具失败必须显式进入 Coverage 和报告。
- 平台不自动修改或写回用户源码。
- 单租户部署仍执行身份认证、角色授权和操作审计。
- MVP 架构能够在不改动业务模型的前提下增加 Kubernetes Sandbox 后端。
