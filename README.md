# Cairn

**面向 Java 源码的单租户代码审计平台。**

> 当前分支处于“审计领域基础”阶段：已经提供 PostgreSQL 数据模型、状态机和审计 API，尚未接入源码拉取、扫描器、执行沙箱、动态验证、认证、Web 工作台和报告生成。因此，它还不能独立完成一次真实的 Java 代码审计。

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
- 16 张 Java 审计领域表、完整初始迁移、约束和索引；
- `AuditRun` 与 `Finding` 的受控状态转换规则；
- `ready` 状态的 `SourceSnapshot` 在 ORM 和数据库层均禁止更新；
- Repository 创建、查询和删除 API；
- AuditPolicy 创建版本和查询 API；
- AuditRun 创建、查询和取消 API；
- Finding 只读 API，候选 Finding 只能由内部服务创建；
- 严格请求模型、稳定错误响应、存活与就绪检查；
- 仅包含 API 与 PostgreSQL 的 Docker Compose 基础运行环境；
- CLI 仅保留 `cairn serve`。

创建 AuditRun 目前只会写入领域状态，不会自动拉取代码或启动扫描任务。

## 尚未实现

以下能力属于后续独立实施阶段，不应从当前版本中推断为可用：

1. Git、ZIP 和目录上传接入，以及 Artifact 对象存储；
2. rootless 执行沙箱、网络策略、资源配额和密钥代理；
3. Maven/Gradle 预处理、Java 索引，以及 CodeQL、Semgrep、FindSecBugs 等确定性扫描；
4. AI 语义审计、候选 Finding 归一化和去重；
5. 动态验证与独立机器复核；
6. 本地认证、Vue 审计工作台、人工复核和报告导出；
7. 备份恢复、MinIO/S3、OIDC 和 Kubernetes 执行后端等生产加固。

完整目标设计与实施记录见：

- [Java 代码审计平台设计](docs/superpowers/specs/2026-07-25-java-code-audit-platform-design.md)
- [审计领域基础实施计划](docs/superpowers/plans/2026-07-25-java-audit-domain-foundation.md)

## 运行要求

### Docker Compose（推荐）

- Linux，或 Windows 上的 WSL2；
- Docker Engine 及 Compose v2 插件。

### 手动运行

- Python 3.12；
- [uv](https://docs.astral.sh/uv/)；
- PostgreSQL 16；
- 一个可由 Cairn 创建表和执行迁移的 PostgreSQL 数据库账户。

正式运行数据库仅支持 PostgreSQL。SQLite 只用于快速单元测试和迁移兼容性检查。

## 使用 Docker Compose 启动

默认配置会启动 `cairn-postgres` 和 `cairn-server`，自动执行 Alembic 迁移，并仅将 API 暴露到宿主机 `127.0.0.1:8000`。

```bash
docker compose up -d --build
docker compose ps
curl --fail http://127.0.0.1:8000/health/ready
curl --fail http://127.0.0.1:8000/api/v1/repositories
```

交互式 API 文档位于：

- Swagger UI：<http://127.0.0.1:8000/docs>
- OpenAPI：<http://127.0.0.1:8000/openapi.json>

查看日志或停止服务：

```bash
docker compose logs -f cairn-server
docker compose down
```

PostgreSQL 数据保存在命名卷 `cairn-postgres-data` 中，普通的 `docker compose down` 不会删除该卷。

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

迁移必须先于 API 启动执行。`/health/live` 只表示进程存活，`/health/ready` 还会检查数据库连接。

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

## 安全边界

当前版本尚未实现身份认证和授权：

- Docker Compose 只绑定 `127.0.0.1`；
- 手动启动也应保持 `--host 127.0.0.1`；
- 不要将当前 API 直接发布到局域网或公网；
- `credential_ref` 目前只是外部 SecretStore 引用，平台不会接收或保存明文 Git 密码；
- 当前 API 不运行仓库代码，也不挂载 Docker Socket。

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

保留的旧 Dispatcher 内部测试依赖 POSIX 进程与信号语义；完整测试套件应在 Linux 或 WSL2 中运行。

## License

项目采用 [GNU Affero General Public License v3.0](LICENSE)。
