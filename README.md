# Cairn

**面向 Java 源码的单租户代码审计平台。**

> 当前分支已经完成“审计领域基础”“源码与 Artifact 管理”“Sandbox Manager”和“Java 确定性分析”四个阶段：Audit Orchestrator 可以把一次运行从源码解析推进到 `semantic_auditing`，并保留构建、扫描、Coverage 和候选事实。AI 语义审计、动态验证、机器复核、认证、Web 工作台和报告仍未实现，因此尚不能完成端到端审计交付。

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
- 18 张 Java 审计领域表、版本化迁移、约束和索引；
- `AuditRun` 与 `Finding` 的受控状态转换规则；
- `ready` 状态的 `SourceSnapshot` 在 ORM 和数据库层均禁止更新；
- Repository 创建、查询和删除 API；
- AuditPolicy 创建版本和查询 API；
- AuditRun 创建、查询和取消 API；
- Finding 只读 API；确定性阶段只写候选 AuditFact，不直接创建正式 Finding；
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
- 包含 API、PostgreSQL、Orchestrator、Sandbox Manager 与持久化状态/Artifact 卷的 Docker Compose 运行环境；
- `cairn serve`、`cairn sandbox-serve` 和 `cairn orchestrate` 三个服务入口。

创建 AuditRun 后，独立 Orchestrator 会异步领取并生成确定性任务。构建或可选扫描器不可用会形成明确 Coverage 警告，而不会伪装成功；完成全部启用工具后，运行停在由下一阶段接管的 `semantic_auditing`。

## 尚未实现

以下能力属于后续独立实施阶段，不应从当前版本中推断为可用：

1. AI 语义审计、审计意图生成与跨模块数据流推理；
2. 候选事实到正式 Finding 的机器复核、状态推进和误报处理；
3. 动态验证服务栈、执行期密钥代理与独立验证复核；
4. 本地认证、Vue 审计工作台、人工复核和报告导出；
5. 内核级目录配额、Nexus 出口策略、seccomp/AppArmor、备份恢复、MinIO/S3、OIDC 和 Kubernetes 执行后端等生产加固。

完整目标设计与实施记录见：

- [Java 代码审计平台设计](docs/superpowers/specs/2026-07-25-java-code-audit-platform-design.md)
- [审计领域基础实施计划](docs/superpowers/plans/2026-07-25-java-audit-domain-foundation.md)
- [源码与 Artifact 管理实施记录](docs/superpowers/plans/2026-07-26-java-audit-source-artifact-management.md)
- [Sandbox Manager 实施记录](docs/superpowers/plans/2026-07-26-java-audit-sandbox-manager.md)
- [Java 确定性分析实施记录](docs/superpowers/plans/2026-07-26-java-audit-deterministic-analysis.md)

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
- 启动 Sandbox Manager 时，还需要可访问的专用 rootless Docker socket、32 字节以上内部令牌文件和独占工作目录。

正式运行数据库仅支持 PostgreSQL。SQLite 只用于快速单元测试和迁移兼容性检查。

## 使用 Docker Compose 启动

默认配置会启动 `cairn-postgres`、`cairn-server`、`cairn-orchestrator` 和 `cairn-sandbox-manager`。API 自动执行 Alembic 迁移且只暴露到宿主机 `127.0.0.1:8000`；Sandbox Manager 使用独立镜像和内部网络，没有宿主机端口，也不包含 API 镜像中的 Git/SSH 客户端。只有 Orchestrator 同时连接数据库网络和 Sandbox API 网络并持有内部 Bearer Token，Audit API 无法直接调用 Manager。

Sandbox Manager 不连接普通宿主机 Docker，也不在 Compose 内启动 privileged DinD。完整启动前必须先按 Docker 官方 rootless 模式为 Cairn 配置一个专用 daemon，并确保其 socket、工作目录和 Manager 容器内的 `cairn` 用户使用兼容的 UID/GID 或 ACL。然后设置实际路径：

MVP 中一个 Manager、一个状态卷和一个 rootless daemon 必须一一对应，不要把本地 Manager 横向扩容到多个副本。

```bash
export CAIRN_ROOTLESS_DOCKER_SOCKET=/run/user/999/docker.sock
export CAIRN_SANDBOX_HOST_WORK_ROOT=/var/lib/cairn/sandbox-work
export CAIRN_SANDBOX_AUTH_TOKEN_HOST_FILE=/var/lib/cairn/secrets/sandbox-token
```

内部令牌必须是 32 到 512 字节的可打印 ASCII；本地环境可使用：

```bash
umask 077
mkdir -p /var/lib/cairn/secrets /var/lib/cairn/sandbox-work
openssl rand -hex 32 > /var/lib/cairn/secrets/sandbox-token
```

通过专用 rootless daemon 构建并登记模板与 helper 镜像标签：

```bash
export DOCKER_HOST="unix://${CAIRN_ROOTLESS_DOCKER_SOCKET}"
docker build -f sandbox-images/Dockerfile \
  -t cairn-sandbox-analysis:local .
docker tag cairn-sandbox-analysis:local cairn-sandbox-build:local
docker tag cairn-sandbox-analysis:local cairn-sandbox-validation:local
docker tag cairn-sandbox-analysis:local cairn-sandbox-helper:local
unset DOCKER_HOST
```

默认模板镜像包含 JDK 17、Maven 3.9.11、Gradle 8.14.3、Semgrep 1.130.0、Java 安全规则和 Cairn 固定 runner。版本及下载校验值记录在 `sandbox-images/toolchain.json`。Maven/Gradle 只在 `build` Profile 中对 scratch 副本执行；Snapshot 挂载始终只读。

CodeQL、FindSecBugs/SpotBugs、Dependency-Check、Trivy 和 gitleaks 的适配器已经实现，但其二进制、许可规则或离线漏洞库不随默认镜像分发。管理员应构建派生镜像并按 `toolchain.json` 的固定路径预置、固定版本；审计运行期禁止下载规则包或数据库。缺少二进制或资产时，该工具在 Coverage 中记录为 `unavailable`，其余工具继续。

Profile 与模板配对为服务端闭集：

| 模板 | 允许的确定性 Profile | 默认镜像能力 |
| --- | --- | --- |
| `analysis` | `inventory`、`semgrep`、`dependency-check`、`trivy`、`gitleaks`、`config-rules` | Inventory、Semgrep、配置规则可直接使用；其余需要离线资产 |
| `build` | `build`、`codeql`、`findsecbugs` | Maven/Gradle 构建可直接使用；CodeQL、FindSecBugs 需要离线资产 |
| `validation` | `default` | 当前只保留模板契约探针，动态验证属于后续阶段 |

```bash
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:8000/api/v1/repositories
```

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

## 手动启动 API

先创建 PostgreSQL 数据库，然后在仓库根目录安装依赖：

```bash
uv sync --project cairn --group dev
export CAIRN_DATABASE_URL='postgresql+psycopg://cairn:cairn@127.0.0.1:5432/cairn'
uv run --project cairn alembic -c cairn/alembic.ini upgrade head
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

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| `GET` | `/` | 服务描述 |
| `GET` | `/health/live` | 存活检查 |
| `GET` | `/health/ready` | 数据库就绪检查 |
| `POST` | `/api/v1/repositories` | 创建 Repository |
| `GET` | `/api/v1/repositories` | 分页查询 Repository |
| `GET` | `/api/v1/repositories/{id}` | 查询 Repository |
| `DELETE` | `/api/v1/repositories/{id}` | 删除未被引用的 Repository |
| `POST` | `/api/v1/git-credentials` | 加密保存 HTTPS Token 或 SSH Key |
| `DELETE` | `/api/v1/git-credentials/{reference}` | 删除未被 Repository 引用的凭据 |
| `POST` | `/api/v1/uploads` | 流式上传 ZIP 或浏览器目录传输归档 |
| `POST` | `/api/v1/repositories/{id}/snapshots` | 从上传或 Git ref 生成不可变 Snapshot |
| `GET` | `/api/v1/snapshots/{id}` | 查询 Snapshot |
| `GET` | `/api/v1/artifacts/{id}` | 下载并校验 Artifact |
| `POST` | `/api/v1/audit-policies` | 创建新的策略版本 |
| `GET` | `/api/v1/audit-policies` | 分页查询策略版本 |
| `GET` | `/api/v1/audit-policies/{id}` | 查询策略版本 |
| `POST` | `/api/v1/audit-runs` | 创建 AuditRun |
| `GET` | `/api/v1/audit-runs` | 分页查询 AuditRun |
| `GET` | `/api/v1/audit-runs/{id}` | 查询 AuditRun |
| `POST` | `/api/v1/audit-runs/{id}/cancel` | 请求取消 AuditRun |
| `GET` | `/api/v1/findings` | 分页、筛选 Finding |
| `GET` | `/api/v1/findings/{id}` | 查询 Finding 详情 |

示例：登记一个 Git Repository。

```bash
curl -X POST http://127.0.0.1:8000/api/v1/repositories \
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
  -H 'Content-Type: application/zip' \
  -H 'X-Filename: demo.zip' \
  --data-binary @demo.zip

curl -X POST \
  http://127.0.0.1:8000/api/v1/repositories/REPOSITORY_ID/snapshots \
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

当前版本尚未实现身份认证和授权：

- Docker Compose 只绑定 `127.0.0.1`；
- 手动启动也应保持 `--host 127.0.0.1`；
- 不要将当前 API 直接发布到局域网或公网；
- Git 凭据使用 AES-256-GCM 加密，公开 API 没有凭据读取操作；
- Git 拉取默认拒绝所有主机，必须显式设置主机允许列表；
- 上传和 Git Snapshot 固化过程不执行仓库 Hook、构建脚本、测试或应用代码；后续构建只发生在受限沙箱的 scratch 副本中；
- Audit API 和 Orchestrator 都不挂载任何 Docker Socket；
- 只有独立 Sandbox Manager 连接专用 rootless daemon，且其内部端口不发布；
- 只有 Orchestrator 持有 Sandbox Bearer Token；Audit API 不连接 Sandbox API 内部网络；
- 调用方不能提交镜像、命令、环境变量、宿主机路径、挂载、设备、Capability、端口或网络模式；
- analysis 模板无网络；build 默认无网络且只能由管理员绑定固定依赖代理网络；validation 使用 Manager 创建的隔离网络；
- 扫描器只能使用镜像内置规则和离线数据库，缺失资产显式标记为 `unavailable`；
- 取消、超时、磁盘超限和 Manager 重启都会执行输出收集与受管资源回收。

认证、权限控制和外部网络暴露必须在后续加固阶段完成后再启用。

## 测试

运行不依赖 PostgreSQL 的测试：

```bash
uv run --project cairn --group dev pytest cairn/tests -m "not postgres" -q
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
