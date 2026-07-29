# Cairn

**面向 Java 源码的单租户代码审计平台。**

> 当前分支已经完成七个主路线子项目。Audit Orchestrator 可以把一次运行从源码接入、构建与扫描、语义审计、正式 Finding、动态验证和独立机器复核推进到人工复核、Coverage 完成闸门与 HTML/JSON/SARIF 报告；Vue 工作台、本地账户、四角色 RBAC、CSRF 和操作审计日志已经接入同一交付链路。模型调用的最后一跳仍需运维方自备密钥，本仓库未验证。闭源平台 CP0 的合成 fixture、版本化契约和确定性 benchmark 已完成，但真实用友/泛微资格验证仍缺合法样本和人工仲裁金标，不能据此宣称厂商支持。

## 产品边界

Cairn 只服务于 Java 代码审计，固定围绕以下领域对象工作：

- `Repository`：待审计代码仓库或上传源；
- `SourceSnapshot`：与内容哈希绑定的不可变源码快照；
- `AuditPolicy`：版本化审计策略；
- `AuditRun` / `AuditTask`：审计运行及阶段任务；
- `Finding`：结构化漏洞、位置、证据、验证和复核结果；
- `Artifact` / `AuditCoverage` / `Report`：产物、覆盖率和报告元数据。

平台为**单租户部署**，不包含租户字段或多租户隔离逻辑。公开 API 不提供通用项目搜索、渗透测试编排、CTF、通用 Agent、Fact/Intent/Hint 或本地 Worker 执行能力。

## 当前已实现

- PostgreSQL 16 正式运行时，基于 SQLAlchemy 2、Alembic 和 psycopg 3；
- 21 张 Java 审计领域表、版本化迁移、约束和索引；
- 本地账户、Argon2id 密码哈希、服务端 Session、双提交 CSRF，以及 `admin`、`auditor`、`reviewer`、`viewer` 四角色显式 RBAC；
- 登录、权限拒绝、账户管理和业务写操作的持久化审计日志；业务变更与对应日志在同一数据库事务中提交；
- `AuditRun` 与 `Finding` 的受控状态转换规则；
- `ready` 状态的 `SourceSnapshot` 在 ORM 和数据库层均禁止更新；
- Repository 创建、查询和删除 API，以及 Repository 下 Snapshot 的持久化列表；
- AuditPolicy 创建版本和查询 API；
- AuditRun 创建、查询、任务时间线、Coverage、SSE 事件流、取消、重试和报告生成 API；
- Finding 查询、人工复核和重新验证 API；确定性阶段仍只写候选 AuditFact，由 Finding Pipeline 校验后提升为正式 Finding；
- Git、ZIP 和浏览器目录归档接入，以及统一的不可变 SourceSnapshot；
- 规范化源码树 SHA-256 和确定性只读 Snapshot TAR；
- ZIP Slip、符号链接、特殊文件、压缩比、文件数和解压体积防护；
- 本地内容寻址 Artifact 后端和下载完整性校验；
- AES-256-GCM Git SecretStore、Git 主机允许列表和凭据隔离；
- 独立的内部 Sandbox Manager、Bearer Secret 鉴权和原子生命周期记录；
- 固定的 `analysis`、`build`、`validation` 模板，调用方不能指定镜像、命令、挂载、Capability、端口、特权参数或网络；
- 专用 rootless Docker 后端检查、Manager 重启孤儿回收，以及创建、启动、等待、取消、超时、收集和销毁协议；
- 非 root、只读根文件系统、`cap_drop: ALL`、`no-new-privileges`、无 host PID/IPC/network 和无 Docker Socket 的工作负载基线；
- CPU、内存、PID、文件大小、临时文件系统、工作目录总量和时长限制；
- Snapshot 的二次哈希校验与安全 TAR 展开，以及不可信输出的确定性归档；
- 工作负载停止并销毁后、受控工作目录删除前写入内容寻址 Artifact，之后仍可通过内部服务读取；
- Maven/Gradle Wrapper、多模块、JDK、框架和模块依赖探测，以及 Java 符号、入口、权限、Source/Sink 和配置路径索引；
- 构建前将只读 Snapshot 安全复制到 scratch，按固定参数执行 Maven 或 Gradle，构建失败不阻断源码级扫描；
- CodeQL、Semgrep、FindSecBugs、Dependency-Check、Trivy、gitleaks 和内置配置规则的固定适配器；
- SARIF、Semgrep JSON、SpotBugs XML、Dependency-Check JSON、Trivy JSON 和 gitleaks JSON 的有界归一化、位置校验、平台指纹与跨工具根因合并；
- 闭集 `inventory`、`build`、`codeql`、`semgrep`、`findsecbugs`、`dependency-check`、`trivy`、`gitleaks` 和 `config-rules` 执行 Profile，模板/Profile 配对由服务端固定；
- 默认模板镜像内置 JDK 17、Maven 3.9.11、Gradle 8.14.3、Semgrep 1.130.0 和本地 Java 安全规则；
- 独立 Audit Orchestrator、受鉴权的 Sandbox HTTP 客户端、幂等 AuditTask、暂态重试和尝试产物保留；
- 每个沙箱输出在任务成功前登记为 task-owned Artifact，并把工具状态、版本、原因、候选数量和 Artifact 写入 `AuditCoverage`；
- 确定性候选结果以 `candidate_finding` AuditFact 保存，同根因的多工具证据合并但不提前创建正式 Finding；
- 严格请求模型、稳定错误响应、存活与就绪检查；
- 独立 LLM Gateway：唯一允许使用长期模型密钥执行推理的组件；可信 Admin API 仅在保存配置或枚举模型时解密密钥。Gateway 校验绑定 AuditRun/Worker/模型/有效期的短期 Grant，强制模型白名单、请求与输出预算、熔断，并只允许自定义工具通过（服务端托管的 `web_search`/`web_fetch`/MCP/容器一律拒绝，否则模型侧即可绕过内部网络访问公网）；
- 证据驱动的语义任务拆分：只在索引确实发现对应攻击面与 Sink 的模块上创建（模块 × 攻击面 × 类别）任务，例如没有 XML 解析 Sink 的模块不会产生 XXE 审计任务；任务量由 `AuditPolicy.semantic_budget` 封顶，截断会写入 Coverage 警告；
- 专用 `semantic` 沙箱模板与镜像：不含 JDK/Maven/Gradle/Semgrep/git/curl 等构建与网络工具，Grant 与审计范围通过唯一的闭合类型化通道注入，Grant 不写入 SandboxRecord、日志或任务行；
- 语义候选与扫描器候选按同一 `root_cause_key` 合并，调用链与可控性说明得以保留；每个范围生成一条 `AuditIntent` 交给后续动态验证认领；模型拒答记为 Coverage 缺口而非静默通过；
- 多工具严重级冲突不再取最高值，而是保留无争议的最低级别并记录各方主张，交由验证阶段裁决（§7.6）；
- 只读 Tool Broker 与固定 Java 审计 Prompt：系统指令与源码内容分通道传递，仓库内的 `AGENTS.md`、README 与代码注释只作为待审计数据出现在 `tool_result` 中；
- 语义输出契约：缺少代码位置、入口到 Sink 调用链或可控性说明的模型输出一律拒绝并记录，AI 无权直接确认 Finding；
- Finding Pipeline：候选事实经数据契约、位置校验与去重后才创建正式 `Finding`；每个位置对快照重新解析并绑定 `snapshot_sha`、附带真实代码片段，越界行号或快照中不存在的路径整条候选拒绝；没有 CWE 的候选不满足契约，记为 rejection 而非硬塞一个 CWE；`remediation` 与 OWASP 分类来自代码内的确定性映射表，不含模型主张；
- 独立 Agent 盲审（§7.8）：严重与高危候选交由独立 Worker 复核，其线上契约只能携带类别、CWE、Sink 与代码位置，物理上无字段承载原发现者的推理、调用链或可控性说明，因此盲审的“盲”由通道强制而非靠调用方自觉；复核必须自行重建入口到 Sink 调用链，确认而无链、驳回而未指明防护措施都会降级为 `inconclusive`；
- 验证阶段永不因故障而驳回：模型拒答、传输失败、预算耗尽、输出不可解析、沙箱未启动一律产生 `inconclusive`（§7.7），无法完成工作的复核者不能删除候选；
- 一次性动态验证环境：从只读 Snapshot 起隔离网络（`internal: true`）、目标应用与受支持依赖服务（PostgreSQL / MySQL / Redis / HTTP 回显），依赖服务按闭集 `ServiceKind` 由服务端固定镜像、端口、用户与 tmpfs，调用方只能报 kind；目标应用作为 runner 子进程启动，销毁沙箱即销毁应用；创建中途失败整组回滚，销毁后校验无残留容器与网络；
- 确定性差分探针：SQL 注入与路径穿越看响应差异，SSRF 与 XXE 靠带 nonce 的带外命中（发请求的是应用本身，无需解读响应），命令注入用时延盲测——注入的命令跑在刻意不含 HTTP 客户端的验证容器里，回连不出去；**只有真正跑过且没发现差异的探针才会 `rejected`**，路由未知、类别不支持、应用未就绪、传输失败一律 `inconclusive`（§7.7）；
- 构建计划探测只读应用自身的 Spring 配置决定启动哪些依赖，**不解析仓库内的 docker-compose**——那等于让仓库决定平台跑什么容器；也只在 Spring 自己查找的位置读取，测试夹具里的 `application.yml` 不算；
- 运行时证据：请求、响应、耗时、应用日志与退出状态按 §7.7 保存为 `Evidence` 与 `RUNTIME_LOG` / `POC` Artifact；
- 模型编写的 PoC（增量 6c）：对没有确定性探针的严重/高危 Finding，模型只写「一个请求模板 + 一个注入点」，平台用良性值与攻击值各代入一次、两次请求可证只差那一个值；成功判据取自闭集（`contains_text` / `status_code_is` / `status_code_differs` / `elapsed_exceeds_ms` / `echo_nonce_observed`），且**必须命中攻击而不命中基准**才算证据——命中基准也命中攻击的判据被判为无区分度而非确认；带外回连的 nonce 由平台生成并在 echo 侧校验，模型看不到也无字段声称命中；PoC 作者跑在无目标网络的 semantic 沙箱、执行跑在无 Gateway 的 validation 沙箱，单一容器无法既写 PoC 又裁决其成败；反序列化、模板注入、表达式注入、未认证访问可覆盖，属主越权（IDOR）因平台无目标应用凭据仍为 `inconclusive` 并写明原因；
- §7.8 确认规则：一次盲审确认加一个独立确定性工具的佐证即可确认（`runtime_verification=unverified`）；盲审驳回但有工具佐证、或运行时与静态结论相左，一律升给人工裁决而非自行了断；严重与高危 Finding 未经机器复核不得进入人工队列（§13.6），该闸门以 `independent_agent` Verification 行的存在为准；原发现 Worker 不能复核自己的 Finding，该检查落在服务层；
- 人工复核可确认、驳回、接受风险或请求重新验证；重新验证创建可执行任务并把结果带回人工队列，严重/高危 Finding 即使被机器驳回也必须取得最终人工处置；
- 完成闸门要求成功的 Inventory、与数值缺口逐类匹配的 Coverage 原因，以及所有当前或历史严重/高危 Finding 的最终非 reverify 人工处置；通过后先落一条成功的 `coverage_check` 任务再生成报告。普通构建警告不能掩盖入口等无关缺口；
- 版本化 HTML、JSON 与 SARIF 报告，包含攻击前提、置信度与运行时状态、调用链位置与代码片段、证据、机器验证、人工复核、静态工具、警告、跳过路径和不支持组件；
- 带 `Last-Event-ID` 恢复、心跳、Session 复查和终态退出的 AuditRun SSE；
- Vue 3 + TypeScript 工作台，覆盖登录、Dashboard、Git/ZIP/浏览器目录接入、Snapshot、运行详情、任务时间线、Coverage、Finding/源码、人工复核与 reverify、报告、策略、用户和审计日志；
- FastAPI 可直接提供 Vite 构建产物和 SPA 深链接，Dockerfile 使用 Node 22 阶段构建前端并复制到运行镜像；API、健康检查和 OpenAPI 路径不会落入 SPA fallback；
- 包含 API、PostgreSQL、Orchestrator、Sandbox Manager、LLM Gateway 与持久化状态/Artifact 卷的 Docker Compose 运行环境；
- `cairn serve`、`cairn sandbox-serve`、`cairn gateway-serve` 和 `cairn orchestrate` 四个服务入口，外加账户管理 CLI、`cairn benchmarks` 和 `cairn semantic-smoke`。

创建 AuditRun 后，独立 Orchestrator 会异步领取并生成确定性任务。构建或可选扫描器不可用会形成明确 Coverage 警告，而不会伪装成功；完成全部启用工具后进入语义审计阶段，按索引证据拆分并执行语义任务；随后候选事实提升为正式 Finding，严重与高危 Finding 经独立盲审、动态验证和人工复核后进入完成闸门。人工要求重新验证时，任务实际执行并回到人工队列；所有门槛满足后才生成报告并进入 `completed` 或 `completed_with_warnings`。语义、验证和完成检查中的每一次失败、拒答、降级或计划截断都会记录为 Coverage 警告。

动态验证支持确定性探针和模型编写、平台裁决的 PoC。环境缺失、类别不支持、应用未就绪或传输失败仍按 §7.7 记录 `inconclusive` 与 `runtime_verification=unverified`，不能伪装为已经执行并驳回。

## 尚未实现

以下能力仍不在当前交付范围内，不应从现有代码推断为可用：

1. 目标应用的执行期凭据代理和需要两个真实身份的属主越权（IDOR）动态验证；
2. 内核级目录配额、Nexus 出口策略、seccomp/AppArmor、备份恢复、MinIO/S3、OIDC 和 Kubernetes 执行后端等生产加固；
3. CP1 及后续的纯二进制接入、字节码索引和用友/泛微版本化适配器。

### 闭源平台 CP0 状态

CP0 已交付严格的 `closed-platform-gold-v1`、`audit-run-export-v1`、`benchmark-result-v1` 契约与 JSON Schema、确定性的 `cairn benchmarks`、项目自行编写的 Java/XML/JSP 合成 fixture、临时 JAR/WAR/EAR 构建器，以及可从零复算的合成 gold/export/result 基线。合成基线只验证契约、指标和打包拓扑，不衡量当前分析器对任何商业产品的效果。

真实资格门槛仍为 **BLOCKED**：仓库没有合法授权的用友 NC/UAP/YonBIP 或泛微 Ecology 商业制品，也没有满足双人独立标注和单独仲裁的 `human-adjudicated` 金标。未知互联网下载、猜测的平台签名或伪造厂商二进制都不能替代这一门槛；在合法样本与人工金标到位前，只能称为“合成 fixture 验证”，不得宣称厂商或具体版本支持。契约、运行方法和缺失矩阵见 [Closed-platform CP0 benchmark contracts](docs/benchmarks/closed-platform-cp0.md)。

完整目标设计与实施记录见：

- [Java 代码审计平台设计](docs/superpowers/specs/2026-07-25-java-code-audit-platform-design.md)
- [审计领域基础实施计划](docs/superpowers/plans/2026-07-25-java-audit-domain-foundation.md)
- [源码与 Artifact 管理实施记录](docs/superpowers/plans/2026-07-26-java-audit-source-artifact-management.md)
- [Sandbox Manager 实施记录](docs/superpowers/plans/2026-07-26-java-audit-sandbox-manager.md)
- [Java 确定性分析实施记录](docs/superpowers/plans/2026-07-26-java-audit-deterministic-analysis.md)
- [LLM Gateway 与语义输出契约实施记录](docs/superpowers/plans/2026-07-26-java-audit-semantic-gateway.md)
- [语义审计执行实施记录](docs/superpowers/plans/2026-07-27-java-audit-semantic-execution.md)
- [Finding Pipeline 与独立机器复核实施记录](docs/superpowers/plans/2026-07-27-java-audit-finding-pipeline.md)
- [动态验证与确定性探针实施记录](docs/superpowers/plans/2026-07-28-java-audit-dynamic-verification.md)
- [模型编写的 PoC 实施记录](docs/superpowers/plans/2026-07-28-java-audit-authored-poc.md)
- [审计工作台、人工复核与报告实施记录](docs/superpowers/plans/2026-07-29-java-audit-workbench-reporting.md)
- [闭源企业平台审计能力增强计划](docs/superpowers/plans/2026-07-28-java-audit-closed-platform-capability.md)

## 运行要求

### Docker Compose（推荐）

- Linux，或 Windows 上的 WSL2；
- Docker Engine 及 Compose v2 插件。
- 一个专用于 Cairn 工作负载、由非 root 用户运行且启用 cgroup v2
  内存/PID 控制的 rootless Docker daemon。
- rootless 主机需安装 `newuidmap`/`newgidmap`，并为 daemon 用户配置
  `/etc/subuid` 与 `/etc/subgid`。

### 手动运行

- Python 3.12；
- [uv](https://docs.astral.sh/uv/)；
- PostgreSQL 16；
- 一个可由 Cairn 创建表和执行迁移的 PostgreSQL 数据库账户。
- 运行 CP0 fixture/baseline 测试时需要 JDK 21；构建器固定使用
  `javac --release 17`，当前基线验证版本为 `javac 21.0.11`；
- 手动构建工作台时需要 Node.js 22 和 npm；
- 启动 Sandbox Manager 时，还需要可访问的专用 rootless Docker socket、32 字节以上内部令牌文件和独占工作目录。

正式运行数据库仅支持 PostgreSQL。SQLite 只用于快速单元测试和迁移兼容性检查。

## 使用 Docker Compose 启动

动态验证的依赖容器（PostgreSQL / MySQL / Redis / HTTP 回显）**不在 Compose 里**：它们由 Sandbox Manager 在自己的 rootless daemon 上按需创建、随沙箱销毁。运维方需要在该 daemon 上预拉取 `postgres:16-alpine`、`mysql:8`、`redis:7-alpine`，并构建 `cairn-sandbox-validation` 镜像；缺失时动态验证以 `inconclusive` 降级而不是失败。

默认配置会启动 `cairn-postgres`、`cairn-server`、`cairn-orchestrator`、`cairn-sandbox-manager` 和 `cairn-llm-gateway`。镜像的 Node 22 构建阶段会编译 Vue 工作台，API 自动执行 Alembic 迁移并在 `127.0.0.1:8000` 同源提供工作台和 API。Sandbox Manager 使用独立镜像和内部网络，没有宿主机端口，也不包含 API 镜像中的 Git/SSH 客户端。只有 Orchestrator 同时连接数据库网络和 Sandbox API 网络并持有内部 Bearer Token，Audit API 无法直接调用 Manager。LLM Gateway 同样不发布宿主机端口，只接入内部 `cairn-analysis-net` 和专用出口网络 `cairn-llm-egress`。API 以读写方式挂载加密的模型配置目录，Gateway 只读挂载该目录和主密钥，Orchestrator 只读挂载其中不含明文密钥的元数据文件且不持有主密钥。

仓库内 Compose 只把服务发布到 localhost 的明文 HTTP，因此对 `cairn-server` 显式设置 `CAIRN_SESSION_COOKIE_SECURE=false`。这只是本地 profile 的例外；生产部署必须使用 HTTPS，并保留 `CAIRN_SESSION_COOKIE_SECURE=true` 的安全默认值，否则会把可登录的工作台暴露在不受保护的传输层上。

Sandbox Manager 不连接普通宿主机 Docker，也不在 Compose 内启动 privileged DinD。完整启动前必须先按 Docker 官方 rootless 模式为 Cairn 配置一个专用 daemon，并确保其 socket、工作目录和 Manager 容器内的 `cairn` 用户使用兼容的 UID/GID 或 ACL。然后设置实际路径：

MVP 中一个 Manager、一个状态卷和一个 rootless daemon 必须一一对应，不要把本地 Manager 横向扩容到多个副本。

```bash
export CAIRN_ROOTLESS_DOCKER_SOCKET=/run/user/999/docker.sock
export CAIRN_SANDBOX_HOST_WORK_ROOT=/var/lib/cairn/sandbox-work
export CAIRN_SANDBOX_AUTH_TOKEN_HOST_FILE=/var/lib/cairn/secrets/sandbox-token
export CAIRN_LLM_GRANT_KEY_HOST_FILE=/var/lib/cairn/secrets/llm-grant-key
export CAIRN_SECRET_KEY_HOST_FILE=/var/lib/cairn/secrets/master-key
export CAIRN_LLM_CONFIG_HOST_DIR=/var/lib/cairn/llm
```

内部令牌必须是 32 到 512 字节的可打印 ASCII；本地环境可使用：

```bash
umask 077
mkdir -p /var/lib/cairn/secrets /var/lib/cairn/sandbox-work /var/lib/cairn/llm
openssl rand -hex 32 > /var/lib/cairn/secrets/sandbox-token
openssl rand -hex 32 > /var/lib/cairn/secrets/llm-grant-key
openssl rand -out /var/lib/cairn/secrets/master-key 32
chmod 600 /var/lib/cairn/secrets/sandbox-token \
  /var/lib/cairn/secrets/llm-grant-key \
  /var/lib/cairn/secrets/master-key
```

通过专用 rootless daemon 构建并登记模板与 helper 镜像标签：

```bash
export DOCKER_HOST="unix://${CAIRN_ROOTLESS_DOCKER_SOCKET}"
docker build -f sandbox-images/Dockerfile \
  -t cairn-sandbox-analysis:local .
docker tag cairn-sandbox-analysis:local cairn-sandbox-build:local
docker tag cairn-sandbox-analysis:local cairn-sandbox-helper:local
# semantic 模板承载 AI 语义审计、独立盲审与 PoC 作者，包含 cairn.poc 与 anthropic SDK。
docker build -f sandbox-images/Dockerfile.semantic \
  -t cairn-sandbox-semantic:local .
# validation 模板承载动态验证与 PoC 执行，是独立镜像（JRE 而非 JDK，含 Pydantic，
# 不含 Maven/Gradle/pip/curl），不能从 analysis 镜像 tag 而来。
docker build -f sandbox-images/Dockerfile.validation \
  -t cairn-sandbox-validation:local .
unset DOCKER_HOST
```

默认模板镜像包含 JDK 17、Maven 3.9.11、Gradle 8.14.3、Semgrep 1.130.0、Java 安全规则和 Cairn 固定 runner。版本及下载校验值记录在 `sandbox-images/toolchain.json`。Maven/Gradle 只在 `build` Profile 中对 scratch 副本执行；Snapshot 挂载始终只读。

CodeQL、FindSecBugs/SpotBugs、Dependency-Check、Trivy 和 gitleaks 的适配器已经实现，但其二进制、许可规则或离线漏洞库不随默认镜像分发。管理员应构建派生镜像并按 `toolchain.json` 的固定路径预置、固定版本；审计运行期禁止下载规则包或数据库。缺少二进制或资产时，该工具在 Coverage 中记录为 `unavailable`，其余工具继续。

Profile 与模板配对为服务端闭集：

| 模板 | 允许的确定性 Profile | 默认镜像能力 |
| --- | --- | --- |
| `analysis` | `inventory`、`semgrep`、`dependency-check`、`trivy`、`gitleaks`、`config-rules` | Inventory、Semgrep、配置规则可直接使用；其余需要离线资产 |
| `build` | `build`、`codeql`、`findsecbugs` | Maven/Gradle 构建可直接使用；CodeQL、FindSecBugs 需要离线资产 |
| `validation` | `default` | 一次性启动目标应用和依赖服务，执行确定性探针与已校验 PoC；需要单独构建 `cairn-sandbox-validation:local` |
| `semantic` | `semantic` | 需单独构建 `cairn-sandbox-semantic:local`，并由运维方配置到 LLM Gateway 的受限网络 |

```bash
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8000/health/ready
```

首次启动后创建首位管理员。命令会在终端中安全提示输入并确认密码，密码不会进入 shell 历史或进程参数：

```bash
docker compose exec cairn-server uv run cairn create-user --username admin --role admin
```

随后访问 <http://127.0.0.1:8000/> 登录工作台。管理员应进入“系统配置”，选择 OpenAI 或 Anthropic 协议、填写 Base URL 与 API Key，点击“获取模型”后选择模型并保存；不支持模型枚举的兼容服务也可手工填写模型 ID。API Key 不会在后续响应中回显，保存后以 AES-256-GCM 加密落盘。模型配置保存前 Gateway 的 readiness 返回 503 是预期状态；保存后新审计任务会把所选模型绑定进短期 Grant。业务 API 不接受匿名请求；自动化客户端应先调用 `/api/v1/auth/login` 保存 Session Cookie，并在所有写请求中回送登录响应的 CSRF Token。

如果尚未配置 rootless daemon，可以只启动控制面：

```bash
docker compose up -d --build cairn-postgres cairn-server
```

交互式 API 文档位于：

- Swagger UI：<http://127.0.0.1:8000/docs>
- OpenAPI：<http://127.0.0.1:8000/openapi.json>

查看日志或停止服务：

```bash
docker compose logs -f cairn-server
docker compose logs -f cairn-orchestrator
docker compose logs -f cairn-sandbox-manager
docker compose down
```

PostgreSQL、Artifact 和 Sandbox 生命周期记录分别保存在命名卷 `cairn-postgres-data`、`cairn-artifact-data` 与 `cairn-sandbox-state` 中；普通的 `docker compose down` 不会删除这些卷。沙箱工作目录使用显式宿主机路径，便于部署时放置到独立配额文件系统。

默认数据库账户仅适合本机开发。可以在启动前设置以下变量：

```bash
export CAIRN_POSTGRES_USER=cairn
export CAIRN_POSTGRES_PASSWORD='replace-with-a-local-secret'
export CAIRN_POSTGRES_DB=cairn
docker compose up -d --build
```

## 手动构建工作台

从源码手动运行时，先构建 Vue 静态文件，并把 FastAPI 的静态根目录指向构建结果：

```bash
cd cairn/web
npm ci
npm run build
cd ../..
export CAIRN_STATIC_ROOT=$PWD/cairn/web/dist
```

未提供有效 `index.html` 时，API 仍可单独运行，但不会注册静态资源和 SPA 深链接。

## 手动启动 API

先创建 PostgreSQL 数据库，然后在仓库根目录安装依赖：

```bash
uv sync --project cairn --group dev
export CAIRN_DATABASE_URL='postgresql+psycopg://cairn:cairn@127.0.0.1:5432/cairn'
uv run --project cairn alembic -c cairn/alembic.ini upgrade head
# 只适用于绑定 127.0.0.1 的本地明文 HTTP；生产 HTTPS 不要关闭 Secure Cookie。
export CAIRN_SESSION_COOKIE_SECURE=false
uv run --project cairn cairn serve --host 127.0.0.1 --port 8000
```

PowerShell 设置连接串的方式为：

```powershell
$env:CAIRN_DATABASE_URL = 'postgresql+psycopg://cairn:cairn@127.0.0.1:5432/cairn'
```

可用配置项：

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CAIRN_DATABASE_URL` | 是 | 无 | SQLAlchemy PostgreSQL 连接串 |
| `CAIRN_API_PREFIX` | 否 | `/api/v1` | 审计 API 前缀 |
| `CAIRN_SQL_ECHO` | 否 | `false` | 是否输出 SQLAlchemy SQL 日志 |
| `CAIRN_ARTIFACT_ROOT` | 否 | `/tmp/cairn-artifacts` | 本地内容寻址 Artifact 根目录；Compose 固定为持久卷路径 |
| `CAIRN_INGESTION_WORK_ROOT` | 否 | `/tmp/cairn-ingestion` | 上传、解压和 Git 固化的独占临时工作区 |
| `CAIRN_STATIC_ROOT` | 否 | 包内 `server/static` | Vite `dist` 目录；目录中无 `index.html` 时不注册工作台路由 |
| `CAIRN_SESSION_TTL_MINUTES` | 否 | `720` | 服务端 Session 有效期 |
| `CAIRN_SESSION_COOKIE_SECURE` | 否 | `true` | 是否只通过 HTTPS 发送 Session 与 CSRF Cookie；仅本地 HTTP 可显式关闭 |
| `CAIRN_SESSION_COOKIE_SAMESITE` | 否 | `strict` | Cookie SameSite 策略，可选 `strict` 或 `lax` |
| `CAIRN_GIT_ALLOWED_HOSTS` | 否 | 空 | 逗号分隔 Git 主机允许列表，支持 `*.example.com`；空值拒绝全部 Git 拉取 |
| `CAIRN_SECRET_KEY_FILE` | 否 | 无 | 保存 32 字节原始值或 Base64 值的 Git 凭据主密钥文件 |
| `CAIRN_GIT_CLONE_TIMEOUT_SECONDS` | 否 | `300` | Git 接入超时 |
| `CAIRN_UPLOAD_MAX_BYTES` | 否 | `104857600` | 上传归档最大字节数 |
| `CAIRN_SNAPSHOT_MAX_FILES` | 否 | `100000` | Snapshot 最大普通文件数 |
| `CAIRN_SNAPSHOT_MAX_TOTAL_BYTES` | 否 | `2147483648` | Snapshot 最大展开字节数 |
| `CAIRN_SNAPSHOT_MAX_FILE_BYTES` | 否 | `104857600` | Snapshot 单文件最大字节数 |
| `CAIRN_SNAPSHOT_MAX_COMPRESSION_RATIO` | 否 | `200` | ZIP 单成员最大压缩比 |

迁移必须先于 API 启动执行。`/health/live` 只表示进程存活，`/health/ready` 还会检查数据库连接。

## 手动启动 Sandbox Manager

Sandbox Manager 与 Audit API 使用不同配置，不需要数据库连接。它必须以专用 rootless Docker daemon 的拥有者身份运行：

```bash
export CAIRN_SANDBOX_DOCKER_HOST='unix:///run/user/999/docker.sock'
export CAIRN_SANDBOX_AUTH_TOKEN_FILE='/var/lib/cairn/secrets/sandbox-token'
export CAIRN_SANDBOX_ARTIFACT_ROOT='/var/lib/cairn/artifacts'
export CAIRN_SANDBOX_STATE_ROOT='/var/lib/cairn/sandbox-state'
export CAIRN_SANDBOX_WORK_ROOT='/var/lib/cairn/sandbox-work'
uv run --project cairn cairn sandbox-serve \
  --host 127.0.0.1 --port 8001 --no-access-log
```

关键配置：

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CAIRN_SANDBOX_AUTH_TOKEN_FILE` | 是 | 无 | 内部 Bearer Token 文件 |
| `CAIRN_SANDBOX_DOCKER_HOST` | 否 | `unix:///run/cairn-rootless-docker.sock` | 专用 rootless Docker endpoint |
| `CAIRN_SANDBOX_REQUIRE_ROOTLESS` | 否 | `true` | 非 rootless daemon 是否直接拒绝 |
| `CAIRN_SANDBOX_ARTIFACT_ROOT` | 否 | `/var/lib/cairn/artifacts` | Snapshot 输入与沙箱输出的内容寻址存储 |
| `CAIRN_SANDBOX_STATE_ROOT` | 否 | `/var/lib/cairn/sandbox-state` | 原子生命周期记录 |
| `CAIRN_SANDBOX_WORK_ROOT` | 否 | `/var/lib/cairn/sandbox-work` | Manager 独占的受控挂载根目录 |
| `CAIRN_SANDBOX_REAP_INTERVAL_SECONDS` | 否 | `1` | 超时、磁盘预算和孤儿检查间隔 |
| `CAIRN_SANDBOX_CREATED_TTL_SECONDS` | 否 | `60` | 已创建但未启动的资源保留时间 |
| `CAIRN_SANDBOX_MAX_ACTIVE_SANDBOXES` | 否 | `4` | Manager 同时保留的 created/running 沙箱上限 |
| `CAIRN_SANDBOX_BUILD_NETWORK` | 否 | 空 | 管理员预建的受限依赖代理网络；空值表示构建模板无网络 |
| `CAIRN_SANDBOX_ANALYSIS_IMAGE` | 否 | `cairn-sandbox-analysis:local` | analysis 模板镜像 |
| `CAIRN_SANDBOX_BUILD_IMAGE` | 否 | `cairn-sandbox-build:local` | build 模板镜像 |
| `CAIRN_SANDBOX_VALIDATION_IMAGE` | 否 | `cairn-sandbox-validation:local` | validation 模板镜像 |
| `CAIRN_SANDBOX_HELPER_IMAGE` | 否 | `cairn-sandbox-helper:local` | 仅用于停止后权限归一化的 Manager helper 镜像 |

CPU、内存、PID 和 tmpfs 由 Docker/cgroup 强制执行，单文件大小由 `RLIMIT_FSIZE` 限制；工作目录总量由 Manager 周期核算并终止超限任务。每个模板还由固定的 `timeout` 包装器提供纵深防护，Manager 重启时则依据持久状态和 Docker 标签执行权威的孤儿回收。生产环境仍应把 `CAIRN_SANDBOX_WORK_ROOT` 放在有宿主机硬配额的独立文件系统上，以消除检查间隔内的磁盘突发。

内部协议位于 `/internal/v1`，不生成公开 OpenAPI：

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `POST` | `/internal/v1/sandboxes` | 由固定模板和 Snapshot 创建沙箱 |
| `GET` | `/internal/v1/sandboxes/{id}` | 查询生命周期 |
| `POST` | `/internal/v1/sandboxes/{id}/start` | 启动 |
| `POST` | `/internal/v1/sandboxes/{id}/wait` | 最长 30 秒等待状态 |
| `POST` | `/internal/v1/sandboxes/{id}/cancel` | 停止、收集并销毁 |
| `POST` | `/internal/v1/sandboxes/{id}/artifacts` | 幂等收集输出 |
| `DELETE` | `/internal/v1/sandboxes/{id}` | 幂等销毁 |
| `GET` | `/internal/v1/sandbox-artifacts/{sha256}` | 读取已登记的沙箱输出 |

创建请求除 Snapshot、Task ID 和资源上限外只能选择上述固定 Profile 枚举；镜像、命令、参数、环境、挂载和网络均不能由调用者提交。`operation` 会原样进入生命周期响应和持久状态，便于 Orchestrator 校验任务与产物的一致性。

## 手动启动 Audit Orchestrator

Orchestrator 使用与 API 相同的 PostgreSQL 和 Artifact Store，并通过内部令牌访问 Sandbox Manager。先完成数据库迁移并启动 Manager，再运行：

```bash
export CAIRN_DATABASE_URL='postgresql+psycopg://cairn:cairn@127.0.0.1:5432/cairn'
export CAIRN_ARTIFACT_ROOT='/var/lib/cairn/artifacts'
export CAIRN_INGESTION_WORK_ROOT='/var/lib/cairn/ingestion'
export CAIRN_SANDBOX_API_URL='http://127.0.0.1:8001'
export CAIRN_SANDBOX_AUTH_TOKEN_FILE='/var/lib/cairn/secrets/sandbox-token'
uv run --project cairn cairn orchestrate
```

`cairn orchestrate --once` 最多处理一个可领取的 AuditRun 后退出，适合开发和运维探测。常驻模式的专用配置为：

| 环境变量 | 必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `CAIRN_SANDBOX_API_URL` | 否 | `http://cairn-sandbox-manager:8001` | Sandbox Manager HTTP(S) 服务 origin，不允许凭据、路径、查询或 fragment |
| `CAIRN_SANDBOX_AUTH_TOKEN_FILE` | 是 | 无 | 与 Manager 相同的内部 Bearer Token 文件 |
| `CAIRN_ORCHESTRATOR_POLL_INTERVAL_SECONDS` | 否 | `1` | 无任务时的轮询间隔 |
| `CAIRN_ORCHESTRATOR_WAIT_SECONDS` | 否 | `5` | 单次等待沙箱状态的秒数，最大 30 秒 |
| `CAIRN_ORCHESTRATOR_WORKER_NAME` | 否 | `deterministic-orchestrator` | 写入 AuditTask 的固定工作进程名称 |

源码解析期间也会使用 API 的 Git allowlist、SecretStore、接入限制和临时工作目录配置。MVP 仅支持单副本 Orchestrator；多副本租约和故障接管属于后续生产加固。

## API 范围

除健康检查、OpenAPI 文档和登录外，公开业务 API 都要求有效 Session；所有非 `GET`/`HEAD`/`OPTIONS` 请求还必须携带匹配的 `X-CSRF-Token`。`admin` 管理用户与策略并拥有全部操作权限，`auditor` 管理审计输入、运行、重新验证和报告，`reviewer` 执行人工裁决，`viewer` 只读结果与报告；敏感 Artifact 和源码不向 `viewer` 开放。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/`、`/{frontend-route}` | 工作台入口与 SPA 深链接；没有前端构建时 `/` 返回服务描述 |
| `GET` | `/health/live` | 存活检查 |
| `GET` | `/health/ready` | 数据库就绪检查 |
| `POST` | `/api/v1/auth/login` | 登录并签发 Session/CSRF Cookie |
| `POST` | `/api/v1/auth/logout` | 撤销当前 Session |
| `GET` | `/api/v1/auth/me` | 查询当前用户 |
| `POST` | `/api/v1/auth/password` | 修改自己的密码并撤销已有 Session |
| `POST` / `GET` | `/api/v1/users` | 管理员创建或分页查询用户 |
| `GET` / `PATCH` | `/api/v1/users/{id}` | 管理员查询、改角色或启停用户 |
| `POST` | `/api/v1/users/{id}/password` | 管理员重置密码并撤销该用户 Session |
| `GET` | `/api/v1/audit-logs` | 管理员筛选只追加的操作审计日志 |
| `POST` | `/api/v1/repositories` | 创建 Repository |
| `GET` | `/api/v1/repositories` | 分页查询 Repository |
| `GET` | `/api/v1/repositories/{id}` | 查询 Repository |
| `DELETE` | `/api/v1/repositories/{id}` | 删除未被引用的 Repository |
| `POST` | `/api/v1/git-credentials` | 加密保存 HTTPS Token 或 SSH Key |
| `DELETE` | `/api/v1/git-credentials/{reference}` | 删除未被 Repository 引用的凭据 |
| `POST` | `/api/v1/uploads` | 流式上传 ZIP 或浏览器目录传输归档 |
| `POST` | `/api/v1/repositories/{id}/snapshots` | 从上传或 Git ref 生成不可变 Snapshot |
| `GET` | `/api/v1/repositories/{id}/snapshots` | 分页查询 Repository 的 Snapshot |
| `GET` | `/api/v1/snapshots/{id}` | 查询 Snapshot |
| `GET` | `/api/v1/snapshots/{id}/source` | 有界读取 Snapshot 中的源码片段 |
| `GET` | `/api/v1/artifacts/{id}` | 下载并校验 Artifact |
| `GET` | `/api/v1/reports` | 按 AuditRun 分页查询持久化报告 |
| `GET` | `/api/v1/reports/{id}?format=html\|json\|sarif` | 下载指定格式报告 |
| `POST` | `/api/v1/audit-policies` | 创建新的策略版本 |
| `GET` | `/api/v1/audit-policies` | 分页查询策略版本 |
| `GET` | `/api/v1/audit-policies/{id}` | 查询策略版本 |
| `POST` | `/api/v1/audit-runs` | 创建 AuditRun |
| `GET` | `/api/v1/audit-runs` | 分页查询 AuditRun |
| `GET` | `/api/v1/audit-runs/{id}` | 查询 AuditRun |
| `GET` | `/api/v1/audit-runs/{id}/tasks` | 分页查询持久化任务时间线 |
| `GET` | `/api/v1/audit-runs/{id}/coverage` | 查询 Coverage 指标、工具状态和缺口 |
| `GET` | `/api/v1/audit-runs/{id}/events` | 订阅可恢复的 SSE 运行事件 |
| `POST` | `/api/v1/audit-runs/{id}/cancel` | 请求取消 AuditRun |
| `POST` | `/api/v1/audit-runs/{id}/retry` | 从失败或取消的运行创建重试运行 |
| `POST` | `/api/v1/audit-runs/{id}/reports` | 通过完成闸门并生成三种报告 |
| `GET` | `/api/v1/findings` | 分页、筛选 Finding |
| `GET` | `/api/v1/findings/{id}` | 查询 Finding 详情 |
| `POST` | `/api/v1/findings/{id}/review` | 记录确认、驳回或接受风险的人工裁决 |
| `POST` | `/api/v1/findings/{id}/reverify` | 创建指定方法的重新验证任务 |

示例：登记一个 Git Repository。

```bash
curl -X POST http://127.0.0.1:8000/api/v1/repositories \
  -b cairn-cookies.txt \
  -H 'X-CSRF-Token: LOGIN_RESPONSE_CSRF_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "demo-java-service",
    "source_type": "git",
    "remote_url": "https://github.com/example/demo-java-service.git",
    "default_branch": "main"
  }'
```

API 请求模型禁止未知字段。分页接口默认 `limit=50&offset=0`，单次最多返回 100 条记录。

示例：上传 ZIP 并生成 Snapshot。

```bash
curl -X POST \
  'http://127.0.0.1:8000/api/v1/uploads?source_type=zip' \
  -b cairn-cookies.txt \
  -H 'X-CSRF-Token: LOGIN_RESPONSE_CSRF_TOKEN' \
  -H 'Content-Type: application/zip' \
  -H 'X-Filename: demo.zip' \
  --data-binary @demo.zip

curl -X POST \
  http://127.0.0.1:8000/api/v1/repositories/REPOSITORY_ID/snapshots \
  -b cairn-cookies.txt \
  -H 'X-CSRF-Token: LOGIN_RESPONSE_CSRF_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"type":"upload","upload_id":"UPLOAD_ID"}'
```

浏览器目录上传使用相同接口：前端先把相对路径和文件打成 ZIP 传输归档，再使用 `source_type=local_upload`。ZIP 与目录归档经过完全相同的安全限制。

私有 Git 凭据需要 32 字节主密钥。手动运行时可生成仅供本机开发使用的密钥并设置：

```bash
umask 077
openssl rand -out /tmp/cairn-master-key 32
export CAIRN_SECRET_KEY_FILE=/tmp/cairn-master-key
export CAIRN_GIT_ALLOWED_HOSTS='github.com,gitlab.com'
```

Compose 部署应通过只读 Docker Secret 或 Compose override 将密钥挂载到默认路径 `/run/secrets/cairn_master_key`。未挂载密钥时服务仍可启动，但 Git 凭据创建和私有仓库拉取返回 `secret_store_unavailable`。

## 安全边界

当前版本已经实现单租户本地认证与授权，但这不等同于完成互联网暴露所需的全部生产加固：

- Docker Compose 只绑定 `127.0.0.1`；
- 手动启动也应保持 `--host 127.0.0.1`；
- 生产环境必须通过受控的 HTTPS 反向代理提供服务并保留 Secure Cookie；不要把明文 HTTP API 直接发布到局域网或公网；
- 密码只保存参数化 Argon2id 哈希；账户管理 CLI 交互式读取密码，不接受会进入 shell 历史或 `ps` 的密码参数；
- `cairn_session` 为 HttpOnly，服务端只保存令牌摘要；`cairn_csrf` 供同源工作台回送 `X-CSRF-Token`，两者默认 `Secure`、`SameSite=Strict`；
- RBAC 对每个端点使用显式角色集合，不依赖可被新角色意外继承的权限排序；角色变更、停用和密码重置会撤销已有 Session；
- 登录成功/失败、权限拒绝、账户与业务写操作、Artifact/报告下载均写入不可由 API 修改或删除的操作审计日志；密码、Session 和 Git 凭据不会复制到日志；
- 敏感 Artifact 在解析底层字节路径前先检查角色，`viewer` 无法读取源码、运行日志、PoC 流量和扫描器原始输出；
- Git 凭据使用 AES-256-GCM 加密，公开 API 没有凭据读取操作；
- Git 拉取默认拒绝所有主机，必须显式设置主机允许列表；
- 上传和 Git Snapshot 固化过程不执行仓库 Hook、构建脚本、测试或应用代码；后续构建只发生在受限沙箱的 scratch 副本中；
- Audit API 和 Orchestrator 都不挂载任何 Docker Socket；
- 只有独立 Sandbox Manager 连接专用 rootless daemon，且其内部端口不发布；
- 只有 Orchestrator 持有 Sandbox Bearer Token；Audit API 不连接 Sandbox API 内部网络；
- 调用方不能提交镜像、命令、环境变量、宿主机路径、挂载、设备、Capability、端口或网络模式；
- analysis 模板无网络；build 默认无网络且只能由管理员绑定固定依赖代理网络；validation 使用 Manager 创建的隔离网络；
- 扫描器只能使用镜像内置规则和离线数据库，缺失资产显式标记为 `unavailable`；
- 长期模型 API Key 由管理员页面提交，API 使用 AES-256-GCM 加密后写入独立配置文件；可信 Admin API 仅在更新/枚举模型时解密，Gateway 仅在推理出口解密。Worker 只持有绑定 AuditRun/Worker/模型/有效期的短期 Grant，日志不记录 Prompt 正文、响应内容或密钥；
- Gateway 同时接入内部 `cairn-analysis-net` 与专用出口网络 `cairn-llm-egress`，但不接入 `cairn-control`，因此既不可达 PostgreSQL 也不可达 Artifact Store；上游 origin 在非 loopback 情况下强制 HTTPS，且出口不跟随重定向；
- 语义审计代理与独立复核代理都只能使用只读 Tool Broker 提供的闭集工具，没有 Shell、写权限和通用网络；仓库内的代理指令文件、代码注释、测试数据和构建日志一律按不可信数据处理；
- 独立复核代理拿不到原发现者的推理：其线上契约（`VerifyCandidateSpec`）只声明类别、CWE、Sink、模块与代码位置五类字段并禁止额外字段，因此任何携带 `message`/`call_chain`/`controllability` 的请求都是校验错误；原发现 Worker 不得复核同一 Finding，严重与高危 Finding 未经机器复核不得进入人工队列；
- `semantic` 镜像不含 JDK、Maven、Gradle、Semgrep、git、curl、wget、uv 和 pip；Grant 与审计范围只能经由唯一的闭合类型化请求块进入容器，容器内的 runner 在构造客户端后立即从环境中删除 Grant；
- Sandbox Manager 不持有长期模型密钥；Orchestrator 只持有 Grant 签名密钥，不持有模型 API Key；
- 语义沙箱所在网络由运维方在沙箱专用 daemon 上创建；未配置时该模板没有出口，任务失败并记录 Coverage 警告，而不会在无审计的情况下继续；
- 动态验证网络为 `internal: true`：组内目标应用与依赖服务互通，组外不可达互联网、控制面、宿主机与云元数据地址（169.254.169.254），该属性由跑在真实 Docker daemon 上的集成测试双向验证；
- 依赖服务镜像声明的每个 `VOLUME` 必须被 spec 里的 tmpfs 覆盖，否则拒绝创建——未覆盖的卷会生成 Manager 生命周期之外的匿名卷，数据会比沙箱活得久；
- 取消、超时、磁盘超限和 Manager 重启都会执行输出收集与受管资源回收。

OIDC、可信代理清单、证书终止、限流、备份恢复和外部网络暴露仍属于部署方的生产加固责任；本地账户与四角色 RBAC 不能替代这些控制。

## 测试

运行不依赖 PostgreSQL 或 Docker 的后端测试：

```bash
uv run --project cairn --group dev \
  pytest cairn/tests -m "not postgres and not docker and not docker_local" -q
```

运行 CP0 契约、fixture 与 benchmark 基线测试：

```bash
uv run --project cairn --group dev \
  pytest cairn/tests/closed_platform -q -p no:cacheprovider
```

运行工作台单元测试、类型检查和生产构建：

```bash
cd cairn/web
npm test
npm run typecheck
npm run build
```

运行 PostgreSQL 迁移测试：

```bash
export TEST_DATABASE_URL='postgresql+psycopg://cairn:cairn@127.0.0.1:55432/cairn_test'
uv run --project cairn --group dev pytest cairn/tests -m postgres -v
```

使用显式 disposable Docker daemon 运行沙箱容器集成测试：

```bash
export TEST_SANDBOX_DOCKER_HOST='unix:///run/user/999/docker.sock'
export TEST_SANDBOX_IMAGE='cairn-sandbox-analysis:local'
export TEST_SANDBOX_REQUIRE_ROOTLESS=1
uv run --project cairn --group dev \
  pytest cairn/tests/sandbox/test_docker_integration.py -v
```

沙箱与 Orchestrator 测试依赖 POSIX 进程与信号语义；完整测试套件应在 Linux 或 WSL2 中运行。

## License

项目采用 [GNU Affero General Public License v3.0](LICENSE)。
