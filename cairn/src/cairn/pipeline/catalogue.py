"""Deterministic remediation and OWASP mapping for promoted Findings.

``Finding.remediation`` is NOT NULL and ``Finding.cwe_id`` is mandatory, but a
candidate carries neither: the Semantic Reviewer produces
``recommended_verification`` (how to settle the question), not
``remediation`` (how to fix it), and scanners produce neither.

Both tables here are code constants. That is the point: a remediation
paragraph reaching a security reviewer should be a statement the platform
stands behind, reproducible across runs and reviewable in a diff — not text a
model generated once and nobody can re-derive. The trade is breadth for
trustworthiness, and a human reviewer can always refine a specific case.

Keyed on CWE rather than on category, because ``category`` is open vocabulary
— :func:`cairn.analysis.normalizers._category` slugifies whatever a scanner
emitted — while CWE is closed and is the field the Finding contract actually
requires.

The prose is Simplified Chinese because the reviewers who act on it read
Chinese; Java and Spring API names, configuration keys and code stay verbatim,
because those are what a reader has to search the codebase for.
:data:`CATEGORY_LABELS` is the display side of the same rule: the stored
``category`` remains an ASCII slug — it keys probe selection, scope keys and
budget filters — and the Chinese label is only ever rendered.
"""

from __future__ import annotations

# CWE -> OWASP Top 10 2021 category. Only mappings the OWASP 2021 CWE lists
# actually make; a CWE outside this table yields no OWASP category rather than
# a guess, and `Finding.owasp_category` is nullable for exactly that reason.
OWASP_BY_CWE: dict[str, str] = {
    "CWE-16": "A05:2021 Security Misconfiguration",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-77": "A03:2021 Injection",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-90": "A03:2021 Injection",
    "CWE-91": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-200": "A01:2021 Broken Access Control",
    "CWE-209": "A05:2021 Security Misconfiguration",
    "CWE-284": "A01:2021 Broken Access Control",
    "CWE-285": "A01:2021 Broken Access Control",
    "CWE-287": "A07:2021 Identification and Authentication Failures",
    "CWE-306": "A07:2021 Identification and Authentication Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-328": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-362": "A04:2021 Insecure Design",
    "CWE-400": "A04:2021 Insecure Design",
    "CWE-434": "A04:2021 Insecure Design",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-522": "A07:2021 Identification and Authentication Failures",
    "CWE-601": "A01:2021 Broken Access Control",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-639": "A01:2021 Broken Access Control",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-829": "A08:2021 Software and Data Integrity Failures",
    "CWE-863": "A01:2021 Broken Access Control",
    "CWE-915": "A08:2021 Software and Data Integrity Failures",
    "CWE-917": "A03:2021 Injection",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
    "CWE-1104": "A06:2021 Vulnerable and Outdated Components",
}

# Java- and Spring-specific where that adds something a reader could act on.
REMEDIATION_BY_CWE: dict[str, str] = {
    "CWE-16": (
        "修正框架配置本身，而不是在调用点补一道补偿性校验。逐项确认该模块实际生效的 "
        "Spring Security 过滤器链、Servlet 与 actuator 暴露面、CORS 允许来源和错误页设置，"
        "并把预期取值固化在随构建一起发布的配置里，而不是放在某个环境专属的覆盖文件中。"
    ),
    "CWE-22": (
        "不要用请求输入拼接文件系统路径。把用户提供的名称解析到一个固定的基准目录之下，"
        "用 `Path.normalize().toRealPath()` 规范化，并拒绝任何解析结果不以该基准目录开头的路径。"
        "更好的做法是让请求只携带一个不透明标识符，由服务端映射到真实路径，从根本上不接受路径参数。"
    ),
    "CWE-77": (
        "不要用请求输入拼接 shell 命令。改用 `ProcessBuilder` 并以参数列表方式传参，"
        "使得不存在任何 shell 去解析这个字符串；同时对每个参数做白名单校验。"
        "若确实必须经过 shell，则该参数只能取自一组固定常量。"
    ),
    "CWE-78": (
        "不要用请求输入拼接 shell 命令。改用 `ProcessBuilder` 并以参数列表方式传参，"
        "使得不存在任何 shell 去解析这个字符串；同时对每个参数做白名单校验。"
        "若确实必须经过 shell，则该参数只能取自一组固定常量。"
    ),
    "CWE-79": (
        "按值最终落地的上下文（HTML 正文、属性、JavaScript、URL）在输出时编码，"
        "而不是在输入时做净化。Thymeleaf 中优先使用 `th:text` 而非 `th:utext`；"
        "确实需要渲染富文本时，让内容先经过一个配置好白名单的净化器。"
    ),
    "CWE-89": (
        "使用参数化查询，让取值永远不会作为语法进入 SQL 解析器：`PreparedStatement` 占位符、"
        "JPA 具名参数，或 MyBatis 的 `#{}`。MyBatis 的 `${}` 是文本替换，不是参数。"
        "当列名、排序方向这类标识符必须可变时，把请求值经服务端白名单映射后再使用，而不是直接拼接。"
    ),
    "CWE-90": (
        "使用框架自带的编码器转义 LDAP 的 DN 与过滤器 —— Spring LDAP 的 `LdapEncoder`，"
        "或 `javax.naming` 的过滤器参数 —— 而不是把请求值拼进过滤器字符串。"
    ),
    "CWE-91": (
        "用文档 API 构造 XML，而不是字符串拼接，这样请求值会成为文本节点而不是标记。"
    ),
    "CWE-94": (
        "移除动态求值。若行为确实需要在运行期变化，改为通过一张固定的服务端实现映射表分发，"
        "由校验过的标识符作为键，而不是去执行外部传入的表达式或脚本。"
    ),
    "CWE-200": (
        "只返回调用方有权获得的字段。响应经由显式的 DTO 投影，而不是直接序列化持久化实体；"
        "并让每一条读取查询都按当前认证主体的租户、组织或属主收敛范围。"
    ),
    "CWE-209": (
        "对调用方返回不透明的错误信息，把堆栈、SQL 文本和内部标识符留在服务端日志里。"
        "显式配置错误处理器，确保框架默认的 whitelabel 或调试页面不会出现在生产响应中。"
    ),
    "CWE-284": (
        "在服务端对每一个入口执行访问决策，而不只是对 UI 会链接到的那些。"
        "优先采用默认拒绝的过滤器链加显式放行规则，而不是逐个方法加注解 —— "
        "这样新增的端点在有人想起来加注解之前就已经受保护。"
    ),
    "CWE-285": (
        "校验当前认证主体是否有权访问这个具体对象，而不只是「已登录」。"
        "把归属条件下推到查询里（在 `WHERE` 中按租户或属主过滤），"
        "这样漏掉一次判断也不会返回别的主体的数据行。"
    ),
    "CWE-287": (
        "把凭据校验交给框架的 authentication provider，而不是在处理器里直接比较取值，"
        "这样锁定策略、凭据编码和会话固定防护才会一并生效。"
        "同时确保登录成功后会重新生成会话标识。"
    ),
    "CWE-306": (
        "把该端点纳入安全配置中需要认证的部分。若某个端点确实必须匿名访问，"
        "就在过滤器链中显式声明这一意图，而不是让它处于未被任何规则匹配的状态，"
        "使这条例外在评审时可见。"
    ),
    "CWE-327": (
        "替换为当前推荐的算法：对称加密用 AES-GCM，摘要用 SHA-256 或更强，"
        "口令用内存困难型函数（bcrypt、scrypt、Argon2）。同一个密钥下绝不重用 IV 或 nonce。"
    ),
    "CWE-328": (
        "不要再用这个摘要算法做安全决策。完整性校验改用 SHA-256 或更强；"
        "口令改用带每凭据独立盐的内存困难型哈希（bcrypt、scrypt、Argon2）。"
    ),
    "CWE-330": (
        "任何不允许被攻击者预测的取值 —— 令牌、会话标识、口令重置码、nonce —— "
        "都必须用 `java.security.SecureRandom` 生成。`java.util.Random` 和 `Math.random()` "
        "可以由已观测到的输出反推复现。"
    ),
    "CWE-352": (
        "对使用 Cookie 认证的写操作请求保持 CSRF 防护开启。"
        "若该端点确实是无状态、由非浏览器客户端以令牌认证访问，"
        "就在安全配置中把它记为一条范围明确的例外，而不是全局关闭防护。"
    ),
    "CWE-362": (
        "让检查与状态变更成为一个原子操作。把不变量下推到数据库 —— 带条件的 "
        "`UPDATE ... WHERE`、唯一约束，或事务内的 `SELECT ... FOR UPDATE` —— "
        "而不是依赖「先读后写」。仅有 `@Transactional` 边界在默认隔离级别下并不会串行化并发调用方。"
    ),
    "CWE-400": (
        "限定单个请求所能引发的工作量：限制分页大小、请求体大小和结果集规模，"
        "并为外部调用和数据库查询设置明确超时，使单个调用方无法长期占用资源。"
    ),
    "CWE-434": (
        "按内容而不是按客户端提供的文件名或 Content-Type 校验上传文件，"
        "以生成的名称存放在 Web 根目录之外，"
        "并且绝不从任何处理器会执行或解释的路径上对外提供该文件。"
    ),
    "CWE-502": (
        "不要把攻击者可控的字节反序列化成任意类型。使用不做类型解析的数据格式"
        "（普通 JSON 反序列化到固定 DTO）；若确实无法避免多态映射器，"
        "则将其限制到一份显式的许可类清单，而不是一个包名前缀。"
    ),
    "CWE-522": (
        "把凭据从随构建发布的代码与配置中移除，运行时从部署环境的密钥存储加载，"
        "并轮换已暴露的取值 —— 进入过版本库的凭据无论仓库是否公开都应视为已泄露。"
    ),
    "CWE-601": (
        "不要跳转到来自请求的地址。改为按经过校验的键选择服务端路径进行跳转，"
        "或在使用前用绝对 URL 白名单匹配请求提供的目标。"
    ),
    "CWE-611": (
        "在使用解析器工厂之前禁用外部实体与 DTD 处理：把 `disallow-doctype-decl` 设为 true，"
        "把 `external-general-entities` 和 `external-parameter-entities` 设为 false。"
        "每一个工厂实例都需要这样设置 —— 默认值是不安全的，"
        "在某个类里加固过的工厂并不能保护另一个类。"
    ),
    "CWE-639": (
        "按当前认证主体收敛查询范围，而不是信任请求里的标识符。"
        "在查询中按属主过滤才能让这道检查无法被遗忘；"
        "读取之后再单独断言归属，在后续新增的代码路径上很容易被跳过。"
    ),
    "CWE-798": (
        "移除硬编码凭据，改为从部署环境的密钥存储加载，并轮换已暴露的取值。"
        "把该模式加入密钥扫描规则，使得再次引入会直接让构建失败，而不是等到下一轮审计。"
    ),
    "CWE-829": (
        "只从配置好的内部镜像源解析依赖，固定版本并校验 checksum 或签名，"
        "使构建无法取到被替换过的制品。"
    ),
    "CWE-863": (
        "修正授权判定本身，而不是在旁边再加一道检查。"
        "用框架自身的语义去确认这条规则实际覆盖了什么 —— 某个 matcher 真正匹配哪些路径、"
        "代理在这条调用路径上是否会应用该注解 —— 并为修正后的规则补一个「去掉修复就会失败」的测试。"
    ),
    "CWE-915": (
        "把请求体绑定到只包含调用方允许设置的字段的显式 DTO，再在服务端映射到持久化实体。"
        "直接绑定到实体意味着调用方可以设置它声明的任何可写字段。"
    ),
    "CWE-917": (
        "不要对由请求输入构造的表达式求值。若确实需要 SpEL 或 OGNL 求值，"
        "使用不暴露任何类型引用的受限求值上下文进行解析，"
        "并把用户取值作为变量传入，而不是作为表达式文本。"
    ),
    "CWE-918": (
        "不要请求来自请求参数的 URL。若外发调用的目标确实必须可变，"
        "通过服务端主机白名单解析目标，在 DNS 解析之后再次校验以拒绝链路本地地址、"
        "回环地址和云元数据地址，并关闭重定向跟随，"
        "使一个被允许的主机无法把请求转发到别处。"
    ),
    "CWE-1104": (
        "将该组件升级到仍在维护的版本，或替换掉它。"
        "在尚无修复版本时，记录处置决定与下次复查时间，让这项暴露保持可见而不是悄悄老化。"
    ),
}

# Fallbacks for audit categories whose candidates may carry a CWE outside the
# table above. Keyed on the closed category vocabulary the semantic planner
# assigns (`cairn.orchestrator.semantic_tasks`).
REMEDIATION_BY_CATEGORY: dict[str, str] = {
    "authorization": REMEDIATION_BY_CWE["CWE-285"],
    "command-execution": REMEDIATION_BY_CWE["CWE-78"],
    "expression-injection": REMEDIATION_BY_CWE["CWE-917"],
    "path-traversal": REMEDIATION_BY_CWE["CWE-22"],
    "spring-security-misconfiguration": REMEDIATION_BY_CWE["CWE-16"],
    "sql-injection": REMEDIATION_BY_CWE["CWE-89"],
    "ssrf": REMEDIATION_BY_CWE["CWE-918"],
    "template-injection": REMEDIATION_BY_CWE["CWE-94"],
    "unsafe-deserialization": REMEDIATION_BY_CWE["CWE-502"],
    "xxe": REMEDIATION_BY_CWE["CWE-611"],
}

GENERIC_REMEDIATION = (
    "Cairn 对该弱点类别没有内置的修复建议。请以本 Finding 上的调用链与可控性说明为起点："
    "切断从外部输入到 Sink 的这条路径，并补一个「去掉修复就会失败」的测试。"
    "修复方案确定后，评审人应当用具体的变更说明替换本段文字。"
)

# Audit category slug -> Chinese display label.
#
# The stored `category` stays an ASCII slug: it keys probe selection
# (`cairn.dynamic.probes.PROBEABLE_CATEGORIES`), scope-key derivation and the
# policy's category filter, so translating the stored value would silently
# disable those. This table is display only, and covers what the platform
# itself emits — the semantic planner's closed vocabulary
# (`cairn.orchestrator.semantic_tasks.SINK_CATEGORIES` plus the two non-sink
# categories) and the slugs the scanner normalizers assign. Anything else is a
# scanner's own vocabulary and falls back to the humanised slug.
CATEGORY_LABELS: dict[str, str] = {
    "authorization": "越权访问",
    "command-execution": "命令执行",
    "command-injection": "命令注入",
    "config": "安全配置缺陷",
    "container-config": "容器配置缺陷",
    "deserialization": "不安全反序列化",
    "expression-injection": "表达式注入",
    "external-control-of-file-name": "文件名可被外部控制",
    "kubernetes": "Kubernetes 配置缺陷",
    "path-traversal": "路径穿越",
    "secret": "凭据泄露",
    "security": "安全弱点",
    "spring-config": "Spring 配置缺陷",
    "spring-security-misconfiguration": "Spring Security 配置缺陷",
    "sql-injection": "SQL 注入",
    "ssrf": "服务端请求伪造（SSRF）",
    "template-injection": "模板注入",
    "terraform": "Terraform 配置缺陷",
    "unsafe-deserialization": "不安全反序列化",
    "vulnerability": "已知组件漏洞",
    "xxe": "XML 外部实体注入（XXE）",
}


def owasp_for(cwe_id: str) -> str | None:
    """The OWASP Top 10 2021 category for a CWE, or ``None`` when unmapped."""

    return OWASP_BY_CWE.get(cwe_id.strip().upper())


def category_label(category: str, fallback: str) -> str:
    """The Chinese display label for a category slug.

    ``fallback`` is what the caller renders when the slug is not one the
    platform emits — a scanner's own vocabulary, which has no translation the
    platform can stand behind. Returning the humanised slug there is honest;
    guessing a Chinese name for it would not be.
    """

    return CATEGORY_LABELS.get(category.strip().lower(), fallback)


def remediation_for(cwe_id: str, category: str) -> str:
    """Remediation text for a promoted Finding.

    Falls back CWE -> category -> generic. The generic text says plainly that
    no specific guidance exists rather than inventing some, so a reader can
    tell the difference between advice the platform stands behind and a gap.
    """

    by_cwe = REMEDIATION_BY_CWE.get(cwe_id.strip().upper())
    if by_cwe is not None:
        return by_cwe
    by_category = REMEDIATION_BY_CATEGORY.get(category.strip().lower())
    if by_category is not None:
        return by_category
    return GENERIC_REMEDIATION
