# Java 闭源企业平台审计能力增强计划

**状态：** Proposed

**日期：** 2026-07-28

**适用对象：** 用友 NC/UAP/YonBIP、泛微 Ecology 等以 JAR、WAR、EAR、class、
JSP/XML 配置和闭源运行时交付的 Java 企业平台，以及这些平台上的二次开发代码。

**与现有路线的关系：** 本计划是现有七个子项目之上的专项增量，使用 `CP0` 到
`CP7` 编号，避免与主路线阶段混淆。现有源码审计能力继续保留，所有新增能力必须
同时支持纯二进制和源码/二进制混合输入。

---

## 1. 结论与目标

当前 Cairn 不能把纯 JAR、WAR、EAR 或 class 作为有效审计输入，也没有用友、
泛微的平台专项解析、规则和验证基准。现有能力适合标准 Java/Spring 源码，不能据此
宣称对闭源企业平台有良好审计效果。

本计划的最终目标不是“能够上传归档”，而是建立以下完整链路：

```text
授权二进制/源码接入
→ 安全递归展开与组件清单
→ 字节码、配置、JSP 和反编译视图索引
→ 平台及版本画像
→ 入口、输入、权限、调用图和 Sink 建模
→ 确定性规则与 AI 语义审计
→ 隔离运行、运行时追踪和授权矩阵验证
→ 带覆盖缺口和证据等级的 Finding/报告
```

达到本计划的 GA 门槛后，平台才可以对限定的平台版本宣称“具备较好的专项审计
能力”。在此之前，对外口径应是“通用 Java 二进制分析”或“实验性平台适配”。

## 2. 当前代码基线与缺口

以下结论来自当前实现，不以路线文档中的目标描述代替代码事实。

| 能力 | 当前代码事实 | 缺口 |
| --- | --- | --- |
| 纯二进制接入 | `server/ingestion/tree.py` 在 `.java` 数量为零时返回 `NO_JAVA_SOURCE` | 纯 JAR/WAR/EAR/class 无法创建可运行的审计快照 |
| 构建产物 | `analysis/execution.py` 只收集从源码构建出来的 JAR/WAR，供动态验证启动 | 不能分析用户直接提交的部署包 |
| 项目识别 | `analysis/project.py` 只识别 Spring、MyBatis、Hibernate、Struts、gRPC 等通用依赖 | 无用友/泛微产品、版本和模块画像 |
| 程序索引 | `analysis/indexer.py` 以源码正则建立类、方法、注解、入口和 Sink | 无 classfile、归档内资源、字节码调用图和反射边 |
| 入口与权限 | 主要识别 Spring/Jakarta 标准注解 | 漏掉 JSP、`web.xml`、平台 XML、Action/Event 和平台权限 API |
| 语义任务 | `orchestrator/semantic_tasks.py` 只围绕已识别入口生成主要任务 | 自定义入口漏识别后，后续 AI 审计也可能完全漏掉 |
| Finding 位置 | `analysis/contracts.py` 和 Finding Pipeline 强制源码路径与正行号 | 不能表达归档、类、方法、描述符和字节码偏移 |
| AI 工具 | `semantic/broker.py` 只能读源码文件、源码符号和源码索引 | 不能查询反编译方法、调用者、配置绑定和边置信度 |
| 动态验证 | 只有 SQL 注入、路径穿越、SSRF、XXE、命令执行五类固定探针 | 缺少平台认证态、角色、组织和租户边界验证 |
| 专项规则与样本 | 内置 Java Semgrep 规则文件约 73 行，测试仅有通用 Maven/Gradle/Spring fixture | 无用友/泛微规则包、真实样本和召回率基线 |

## 3. 范围与边界

### 3.1 首期支持的输入模式

| 模式 | 例子 | 目标能力 |
| --- | --- | --- |
| 混合输入 | 二开源码 + 平台 SDK/JAR | 源码和字节码跨边界调用链 |
| 纯二进制 | JAR、WAR、EAR、class 目录 | 离线组件、配置、字节码和反编译审计 |
| 可运行部署包 | WAR 或可执行 JAR + 授权运行时 | 静态结论、运行追踪和动态验证 |
| 不完整部署包 | 缺少部分平台依赖 | 尽力分析，并显式披露未解析调用边和覆盖缺口 |

### 3.2 明确不做

- 不扫描未经授权的生产系统，不把本计划扩展为外部渗透测试。
- 不在仓库或官方镜像中分发用友、泛微的商业二进制、密钥或安装介质。
- 不把反编译文本当作原始源码，也不伪造不存在的源码行号。
- 不因版本命中直接确认漏洞。版本、类名或文件哈希只能形成候选，仍需代码路径、
  补丁差异或运行证据佐证。
- 不承诺还原被加密、重度混淆、JNI/native 或服务端未提供的代码。
- 不允许模型、规则或待审计归档决定宿主机命令、镜像、挂载、网络和运行参数。

### 3.3 数据和授权要求

- 用户必须确认对上传、解包、反编译和运行目标制品具有授权。
- 原始二进制、反编译视图和动态证据均按敏感 Artifact 处理。
- 闭源输入默认 `semantic_data_policy=local_only`。只有管理员显式允许后，才可把受限
  代码片段发送到外部模型；长期模型密钥仍只存在于 LLM Gateway。
- 私有真实样本不得进入公开仓库。公开测试使用无厂商代码的合成兼容桩；私有基准
  只保存授权样本、加密制品和可审计的标签清单。

## 4. 目标架构与关键契约

### 4.1 审计快照

为避免一次性重命名大量领域对象，第一版保留现有 `SourceSnapshot` 表和内部类名，
但新增 `input_kind=source|bytecode|hybrid`，产品界面统一显示为“审计快照”。

接入成功条件调整为：快照至少包含一个有效 `.java`、`.class`、JAR、WAR 或 EAR。
纯二进制不再触发 `NO_JAVA_SOURCE`。原始上传和规范化快照都保留内容哈希，派生的
展开树、组件清单、字节码索引和反编译视图各自成为不可变 Artifact。

### 4.2 归档内位置

新增位置契约 `CodeLocationV2`：

```text
origin_kind: source | bytecode | config | decompiled
container_path: app.war
entry_path: WEB-INF/lib/workflow.jar!/com/vendor/Action.class
class_name: com.vendor.Action
method_name: execute
method_descriptor: (L.../RequestInfo;)Ljava/lang/String;
bytecode_offset: 184 | null
source_path: src/.../Action.java | null
start_line/end_line: int | null
decompiled_artifact_id: UUID | null
decompiled_start_line/decompiled_end_line: int | null
```

规则：

- `container_path + entry_path + class_name + method_descriptor` 是二进制证据的稳定身份。
- classfile 的 `LineNumberTable` 存在时可以记录原始源码行号；不存在时行号必须为空。
- 反编译行号只能定位反编译 Artifact，不能写入原始源码行号字段。
- Finding 页面必须明确显示“源码”“字节码”“配置”或“反编译视图”。
- fingerprint 使用快照哈希、归档内稳定路径、类/方法描述符、CWE 和 Sink，不使用
  可能随反编译器版本变化的反编译行号。

### 4.3 Program Index v2

现有源码 inventory 升级为可合并的 `ProgramIndexV2`：

```text
Component       归档、嵌套依赖、版本、哈希、签名和来源
Class/Method    类名、描述符、访问标志、继承、接口、注解和行号表
Resource        web.xml、JSP、Spring/Struts/平台 XML、properties/yaml
Entrypoint      路由、Action、事件、任务、RPC、JSP 和配置来源
InputSource     HTTP、Request/Session、消息、文件、平台请求对象
SecurityGuard   登录、角色、组织、数据权限和租户边界检查
SensitiveSink   SQL、命令、文件、HTTP、反序列化、表达式、模板和平台 API
CallEdge        调用者、被调者、边类型、来源和置信度
ConfigEdge      XML/JSP/注册项到类或方法的绑定
CoverageGap     缺失依赖、反射、动态类、混淆、无行号和不支持格式
```

调用边必须标记 `exact|resolved|inferred|runtime`，报告不能把推断边展示为确定事实。

### 4.4 平台适配器

新增闭集 `PlatformAdapter`，适配器只能返回结构化画像和索引扩展，不能执行任意代码：

```text
detect(components, resources) -> PlatformProfile[]
entrypoints(index, resources) -> Entrypoint[]
sources(index) -> InputSource[]
guards(index, resources) -> SecurityGuard[]
sinks(index) -> SensitiveSink[]
config_edges(resources) -> ConfigEdge[]
runtime_hints(profile) -> ClosedRuntimeHint
```

每次运行记录适配器名称、版本、规则包哈希、命中证据和适用产品版本。用友必须按
NC/UAP、YonBIP 等产品族拆分，不能用一个笼统的 `yonyou=true` 代替版本化适配。

## 5. 分阶段实施

### CP0：授权样本、威胁模型和基准体系

**目标：** 先建立可以重复测量的基线，防止以规则数量、文档数量或演示截图代替
真实审计效果。

**代码交付：**

- 新增 `cairn/benchmarks` 命令，输入金标清单和 AuditRun 导出，计算入口召回率、
  高危漏洞召回率、精确率、证据完整率、动态复现率和覆盖缺口率。
- 定义版本化 `closed-platform-gold-v1`、`benchmark-result-v1` JSON Schema。
- 在 `cairn/tests/closed_platform/fixtures` 建立无厂商代码的合成 fixture：嵌套 JAR、
  WAR、EAR、独立 class、JSP、`web.xml`、XML Action、平台请求对象、平台 SQL API、
  权限和租户守卫。
- 私有基准执行器只接受内容哈希和密钥引用，测试日志不得输出二进制或反编译正文。

**样本矩阵：**

- 用友至少选择两个产品族，每个产品族覆盖两个仍有实际使用量的版本线。
- 泛微至少选择两个 Ecology 版本线。
- 每条版本线至少包含一个纯部署包、一个二开模块和一组已人工确认的漏洞/安全样本。
- 金标由两名审计人员独立标注入口、权限边界、Sink 和漏洞，冲突需人工仲裁。

**退出门槛：**

- 当前版本的基线报告可以从零开始重复生成。
- 每个金标结论都能追溯到样本哈希和人工证据。
- 没有合法真实样本时，本阶段不得以互联网下载的未知制品代替；后续只能标记为
  “合成 fixture 验证”，不能宣称厂商平台支持。

### CP1：二进制接入与安全归档清单

**目标：** 纯 JAR/WAR/EAR/class 可以形成不可变审计快照，但此阶段不声称已经完成
深度代码审计。

**代码交付：**

- `SourceType` 增加二进制上传类型，上传端通过魔数和结构校验识别格式，不信任后缀
  或客户端 MIME。
- `collect_snapshot_tree` 接受 `source|bytecode|hybrid`，移除纯二进制的
  `NO_JAVA_SOURCE` 拒绝；无任何 Java 源码或有效 JVM 制品时使用新错误码
  `NO_SUPPORTED_JVM_INPUT`。
- 新增只在分析沙箱执行的 `binary-inventory` Profile，安全递归枚举 JAR/WAR/EAR；
  不在 API 进程中反编译或加载类。
- 对每层归档限制展开字节数、文件数、深度、单项大小、压缩比和总 CPU/时长；拒绝
  Zip Slip、重复规范化路径、符号链接、特殊文件和路径碰撞。
- 建立稳定逻辑路径，例如
  `app.war!/WEB-INF/lib/workflow.jar!/com/acme/Action.class`，保留每层哈希。
- 读取 `MANIFEST.MF`、Maven `pom.properties`、包实现版本、签名元数据和服务注册项，
  生成组件清单与 CycloneDX SBOM；不得执行静态初始化器。
- 多版本 JAR 按目标 JDK 选择有效 class，同时在 Coverage 中记录被遮蔽版本。

**测试与验收：**

- 纯 JAR、WAR、EAR、class 目录和混合源码/二进制均能创建 AuditRun。
- 同一输入重复接入产生相同快照哈希、组件身份和逻辑路径。
- 至少覆盖两层嵌套归档、压缩炸弹、重复项、畸形 central directory、超限 class、
  签名 JAR 和 multi-release JAR。
- 接入和清单过程不得启动 JVM 目标类，不得访问互联网，沙箱销毁后无展开目录残留。

### CP2：字节码 Program Index 与反编译视图

**目标：** 在没有源码和构建脚本时，仍能获得可靠的类、方法、注解、引用和调用图；
反编译只服务于阅读和语义分析，classfile 才是确定性事实源。

**技术选型：**

- 使用 ASM 解析 classfile、描述符、注解、指令、常量池和行号表。
- 使用 SootUp 构建 CHA/RTA 调用图和中间表示，不自行实现 JVM 字节码语义。
- 使用固定版本 CFR 生成只读反编译视图，并把工具版本写入 Artifact。
- 在 CP0 做一次兼容性尖峰；如果 SootUp 对金标版本的 classfile 兼容率低于 95%，
  形成 ADR 后改用 WALA，不能并行维护两套主调用图。

**代码交付：**

- 新增 `bytecode-index` 受控 Profile 和独立分析镜像层，版本和校验值进入
  `sandbox-images/toolchain.json`。
- 产出 `ProgramIndexV2`，支持类继承、接口实现、虚调用候选、lambda/invokedynamic、
  注解、字段读写、常量传播基础信息和跨嵌套 JAR 引用。
- classpath 按 WAR/EAR 规则、manifest `Class-Path` 和管理员提供的只读依赖包解析；
  重复类、缺失类和版本冲突必须进入 Coverage。
- 反射、服务加载器、SPI、脚本引擎和动态类加载形成低置信度候选边，不静默忽略。
- 落地 `CodeLocationV2`，Finding Pipeline 同时兼容 v1 源码位置和 v2 二进制位置。
- 新增确定性反编译 Artifact 缓存，以“输入 class 哈希 + 反编译器版本”作为键；
  不跨租户/部署共享敏感明文。

**测试与验收：**

- 合法、未混淆 fixture 的 class 解析成功率不低于 99%，失败项逐项进入 Coverage。
- 能从 WAR 路由资源定位到 class 和方法，并从入口沿调用边到达测试 Sink。
- 无 `LineNumberTable` 的 class 仍能产生方法/偏移位置，不伪造源码行号。
- 反编译器升级不会改变 Finding fingerprint。
- 缺依赖、重复类和反射边不会使任务整体失败，也不能被报告成完整覆盖。

### CP3：通用企业 Web 与用友/泛微平台适配器

**目标：** 把平台自己的路由、请求对象、数据库 API 和权限模型纳入索引，而不是只看
Spring 注解。

**代码交付：**

- 先实现通用 `servlet-jsp`、`web-xml`、`struts-xml`、Spring XML、JAX-RS 和过滤器链
  适配器，作为厂商适配器共用基础。
- 实现 `weaver-ecology` 版本化规则包：覆盖 JSP/Servlet/Action/workflow 入口、
  `RequestInfo` 类请求数据、`RecordSet` 类数据库操作、会话身份和已知权限检查模式。
- 分别实现 `yonyou-nc-uap` 与 `yonyou-yonbip` 规则包：覆盖配置注册的
  Controller/Action/Event/Service、平台请求对象、ORM/数据库调用、用户/组织/数据权限
  和租户边界。实际类名和签名必须从授权样本生成，不凭产品名称猜测。
- 平台画像同时使用组件坐标、manifest、资源结构、类/方法签名和可选哈希；单一弱
  信号只能产生低置信度画像。
- 规则包带 `platform_id`、适用版本范围、规则版本、来源、测试 fixture 和变更记录。
- 对未知版本使用最近兼容的通用适配层并标记 `profile_confidence=low`，不得静默套用
  某个厂商版本规则。

**测试与验收：**

- 私有金标集的平台入口召回率不低于 90%，平台权限守卫召回率不低于 85%，关键
  SQL/命令/文件/HTTP/反序列化 Sink 召回率不低于 95%。
- 版本画像必须给出具体命中证据；未知版本和冲突版本进入 Coverage。
- 每条平台签名至少有一个正例、一个近似反例和一个不支持版本测试。
- 不含用友/泛微代码的普通 Java 项目不得被错误标记为对应平台。

### CP4：混合调用链、数据流与语义审计

**目标：** 从“发现危险调用”提升为“解释外部输入如何经过平台调用链到达 Sink，
以及权限检查是否有效”。

**代码交付：**

- 建立源码 AST/现有 inventory 与 `ProgramIndexV2` 的统一符号键，实现源码到闭源
  JAR、闭源 JAR 回调二开代码的跨边界调用链。
- 基于中间表示实现按类别的过程间污点分析，首批覆盖 SQL 注入、命令执行、路径
  穿越、SSRF、XXE、危险反序列化、表达式和模板注入。
- 权限分析单独建模身份、角色、组织、数据权限和租户 Guard，不能把“调用过任意
  权限函数”直接等同于安全。
- 语义任务同时采用入口前向、Sink 反向和未知入口兜底三种策略。即使平台入口未被
  识别，高危 Sink 仍必须生成反向审计任务并记录入口未知。
- Tool Broker 新增只读工具：`read_decompiled_method`、`list_callers`、
  `list_callees`、`trace_to_sink`、`show_route_binding`、`show_security_guards`。
- 模型输出必须逐边引用 `CallEdge` 标识和置信度；仅凭反编译文本猜测的链不能获得
  `high` confidence。
- 为通用字节码、用友和泛微建立独立规则命名空间；规则命中经过现有 Candidate、
  去重、机器复核和证据管道，适配器不得直接创建 confirmed Finding。

**测试与验收：**

- 合成 fixture 中的源码/字节码双向调用链均可重建。
- 删除一个入口适配规则后，Sink 反向任务仍能发现对应候选并明确“入口未知”。
- 高危候选必须包含真实归档路径、类、方法描述符、入口或未知入口原因、Sink 和边
  置信度；缺任一项不得提升为正式 Finding。
- 私有金标集的严重/高危静态召回率达到 80% 以上，精确率达到 65% 以上后才进入
  平台静态审计试点。

### CP5：版本、补丁和历史漏洞知识

**目标：** 识别组件和补丁差异，把 CVE/CNVD/厂商公告转化为可验证候选，而不是做
只按版本号报警的漏洞库匹配。

**代码交付：**

- 建立离线、版本化、带 SHA-256 清单的 `platform-intel` 规则包，记录公告标识、
  CWE、受影响版本、修复版本、类/方法/资源特征、补丁差异和验证策略。
- 组件版本按“强签名、弱签名、冲突”分类；强签名可以来自厂商签名、精确制品哈希
  或稳定方法指纹，文件名只能作为弱证据。
- 对授权的脆弱版/修复版制品生成语义方法指纹和差异特征，不把商业二进制写入规则
  仓库。
- 将“组件存在”“版本可能受影响”“危险代码存在”“调用可达”“动态确认”分成不同
  状态，只有最后两类可以提高 Finding 置信度。
- 规则更新走离线导入、签名校验、回滚和操作审计，审计运行固定规则包版本。

**测试与验收：**

- 每条历史漏洞规则至少同时通过脆弱版正例和修复版反例。
- 仅修改文件名或 manifest 版本不能把修复版误报为已确认漏洞。
- 报告可追溯到规则包版本、公告、命中特征和适用版本，且不泄露私有样本内容。

### CP6：授权运行时、Java Agent 与动态验证

**目标：** 对能够在隔离环境启动的部署包，用运行时事实补足反射、动态路由、权限
和租户边界等静态盲区。

**代码交付：**

- 增加 `prebuilt-jar`、`generic-war` 两个服务端固定运行模板。商业应用服务器和平台
  运行时由管理员从授权安装介质注册为只读、哈希固定的私有模板，平台不自动下载。
- 通过 JVM 启动参数加载基于 Byte Buddy 的只读观测 Agent，记录请求关联的路由、
  Filter/Interceptor、方法边、反射目标、SQL、外连、文件、进程、反序列化、当前
  principal/role/org/tenant 标识；Agent 不修改业务返回值。
- 运行时调用边写回 `ProgramIndexV2`，标记为 `runtime`，并与具体请求和进程实例
  绑定，不能污染其他 Snapshot。
- 新增认证态测试资料契约：测试账户、角色、组织和租户均使用 Secret 引用，Finding
  和日志不得保存密码、Cookie 或 Token 明文。
- 建立授权矩阵验证：同一业务对象分别以未登录、低权限、跨组织、跨租户和合法身份
  请求，对比状态码、响应语义、数据行和实际 Guard 轨迹。
- 为反序列化、表达式和模板注入增加受控验证器；模型生成 PoC 仍必须经过闭合契约、
  类别允许列表和沙箱限制，不能产生任意 Shell 或公网访问。
- 无合法运行时、许可证、测试账户或启动失败时只允许 `inconclusive`，绝不能因此
  `rejected` 静态候选。

**测试与验收：**

- 通用可执行 JAR 和 WAR 可以从纯二进制快照启动、探活、验证并完全销毁。
- Java Agent 能捕获反射路由和动态调用边，且关闭 Agent 后业务基线行为不变。
- 探针无法访问控制面、宿主机、云元数据和公网；凭据不进入 Artifact 和普通日志。
- 合成多角色/多租户 fixture 能确认越权、拒绝安全路径，并对环境缺失返回
  `inconclusive`。
- 沙箱销毁后不存在带本次 AuditRun 标签的容器、网络、进程和临时卷。

### CP7：覆盖率、试点和发布门槛

**目标：** 把“支持某平台”变成有版本边界、指标和证据的产品声明。

**代码交付：**

- Coverage 增加：输入类型、归档展开率、class 解析率、依赖解析率、调用边解析率、
  配置绑定率、入口/Sink/Guard 数、未知反射点、无行号类、混淆比例、适配器和规则包
  版本、静态/动态未覆盖原因。
- 报告按 Finding 展示源码、字节码、配置、反编译和运行时证据，不把它们混成一个
  “代码行号”。
- 平台能力矩阵按“产品族 + 版本线 + 输入模式 + 静态/动态”发布，不使用笼统的
  “支持用友”或“支持泛微”。
- 增加回归看板和 release gate；规则、反编译器、调用图工具或适配器升级后自动跑
  通用 Java 集、合成闭源集和私有金标集。

**发布等级：**

| 等级 | 必须满足的门槛 | 允许的产品口径 |
| --- | --- | --- |
| Experimental | CP1、CP2 完成；class 解析率 ≥99%；覆盖缺口完整披露 | 通用 Java 二进制实验性分析 |
| Preview | CP3、CP4 完成；金标高危召回率 ≥80%，精确率 ≥65% | 指定产品/版本的静态审计预览 |
| GA | CP5、CP6 完成；两轮独立金标评测中高危召回率 ≥85%，精确率 ≥70%，证据完整率 ≥95% | 指定产品/版本和输入模式的专项审计 |

附加发布门槛：

- 通用 Java 源码基准的高危召回率相对当前基线下降不得超过 2 个百分点。
- 所有未解析 class、调用边、配置和动态环境必须进入 Coverage，漏记覆盖缺口视为
  发布阻断问题。
- 每个平台至少完成两个不同客户/项目形态的授权试点，评测样本不得全部来自同一
  厂商版本或同一套合成 fixture。
- 指标必须由 `cairn benchmarks` 从 AuditRun Artifact 自动生成，人工编写的总结
  不能代替原始评测结果。

## 6. 实施顺序、依赖和人力估算

```text
CP0 基准 ─┬─> CP1 二进制接入 -> CP2 字节码索引 -> CP3 平台适配 ─┐
          │                                                       ├─> CP4 混合分析
          └──────────────────────────────> CP5 漏洞知识 ──────────┤
                                                                  └─> CP6 动态验证 -> CP7 发布
```

建议顺序工期约为 30 到 34 个工程师周，不包含商业样本、许可证和运行时环境的授权
获取时间。由 3 到 4 人组成的团队可按“接入/字节码”“规则/平台”“动态/基准”三条线
并行，预估 4 到 5 个月达到首个 GA 候选。没有真实授权样本时，应停止在 Preview，
不能用增加人力绕过验收依据缺失的问题。

## 7. 风险与降级策略

| 风险 | 处理方式 | 对结论的影响 |
| --- | --- | --- |
| 重度混淆或加密 class | 记录混淆指标、未知符号和不可解析项；必要时只做运行追踪 | Coverage 降级，不声称完整静态审计 |
| 缺少平台依赖 | 管理员提供只读依赖包；调用图保留 phantom/unknown edge | 对相关 Finding 降低置信度 |
| 反射和动态脚本 | 静态候选边 + Java Agent 运行边 | 无运行证据时保持 inferred |
| 商业运行时无法授权 | 只发布静态支持等级 | 动态结论全部为 unverified/inconclusive |
| 反编译器产生误导 | classfile/IR 为事实源，反编译仅是版本化视图 | 禁止用反编译行号作稳定身份 |
| 外部模型数据合规 | 默认 local-only，管理员显式授权外发 | 无合规模型时语义阶段记 Coverage 缺口 |
| 超大 EAR/WAR | 分层预算、按组件增量索引、哈希缓存 | 超限项逐项披露，不静默截断 |
| 历史漏洞情报误报 | 脆弱/修复双样本、可达性和动态证据分层 | 版本命中只能产生候选 |

## 8. 完成度评估规则

后续评估本计划时，每个阶段按以下证据计分：

| 证据 | 权重 |
| --- | ---: |
| 对应生产代码和数据库迁移已合入 | 30% |
| 单元、契约、安全和回归测试通过 | 25% |
| 真实沙箱/归档/运行时集成测试通过 | 20% |
| 合成和私有金标指标达到阶段门槛 | 20% |
| 运维说明、能力矩阵和限制文档准确 | 5% |

硬性规则：

- 只有设计或计划文档，没有对应代码，阶段完成度最多为 5%。
- 只有代码和 mock 测试，没有真实 JAR/WAR/class 或真实沙箱集成，阶段完成度最多为
  55%。
- 没有用友/泛微授权金标集，CP3 及以后最多只能评为 Preview，不得评为 GA。
- 任一阶段隐瞒解析失败、缺依赖、未知入口或动态环境缺失，阶段验收直接失败。
- 每份阶段实施记录必须列出代码路径、迁移、测试命令、测试结果、样本哈希、指标和
  尚未验证项；`Status: Implemented` 本身不构成完成证据。

## 9. 第一批可执行任务

按风险和价值，首个迭代只做以下工作：

1. 建立 CP0 合成 JAR/WAR/class fixture 和基准结果契约。
2. 修改接入契约，让纯二进制生成 `input_kind=bytecode` 的不可变快照。
3. 实现有界嵌套归档清单和稳定 `archive!/<entry>` 逻辑路径。
4. 引入 ASM，完成 class/方法/注解/调用指令索引和 `CodeLocationV2` 最小闭环。
5. 让 Finding Pipeline 能保存一个没有源码行号、但有 class/方法/offset 和反编译
   Artifact 的候选。
6. 使用一个纯 WAR fixture 跑通“上传 → 索引 → Sink 候选 → Finding → Coverage”。

该迭代完成后只能称为“二进制审计骨架可用”。平台专项能力必须继续通过 CP3、CP4
和私有金标验收，不能提前宣称完成。
