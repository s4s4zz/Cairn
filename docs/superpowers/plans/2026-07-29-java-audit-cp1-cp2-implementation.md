# CP1/CP2 二进制审计骨架实施记录

**状态：** In Progress

**日期：** 2026-07-29

**对应计划：** `2026-07-28-java-audit-closed-platform-capability.md` 的第一批可执行任务

## 本次范围

本次只交付通用 Java 二进制审计骨架：

1. 原始 class、JAR、WAR、EAR 接入及 `source|bytecode|hybrid` 快照分类。
2. 在无网络 analysis Sandbox 中执行的有界嵌套归档清单。
3. 基于固定版本 ASM 的类、方法、注解和调用指令索引。
4. `CodeLocationV2` 以及无源码行号 Finding 的持久化兼容。
5. 合成纯 WAR 的“接入、清单、索引、Sink 候选、Finding、Coverage”回归闭环。

本次不实现厂商平台适配器、过程间污点分析、SootUp 主调用图、动态运行模板或厂商漏洞知识库。没有授权真实样本和双人仲裁金标时，不作任何用友、泛微产品支持声明。

## 决策

- `binary_upload` 表示上传体本身是部署制品，顶层容器作为 Snapshot 文件原样保留。
- `zip` 和 `local_upload` 仍是源码或混合目录的运输归档，保持现有 API 兼容。
- API 进程只做魔数和浅层结构校验，不递归展开、不反编译、不加载目标类。
- 嵌套归档逻辑路径使用 `outer.war!/WEB-INF/lib/dependency.jar!/pkg/Type.class`。
- classfile 是确定性事实源；反编译文本只作为敏感、版本化的阅读 Artifact。
- 原始源码行号、字节码偏移和反编译行号使用不同字段，缺失时保持 `null`。
- Finding fingerprint 不包含反编译行号。

## 数据迁移

- `20260729_0008`：`binary_upload`、快照 `input_kind` 与 JVM 制品计数。
- `20260729_0009`：`CodeLocationV2` 的可空源码位置和二进制位置字段。
- 历史快照通过列默认值回填为 `source`；历史 hybrid 快照必须重新接入才能获得正确覆盖数据。

## 验证记录

2026-07-29 的本地验证结果：

- 非 Docker、非 PostgreSQL 全量回归：`1206 passed, 10 skipped, 6 deselected`。
- CP0 合成 fixture、契约和 benchmark 基线：`23 passed`；合成样本
  SHA-256 为 `43621e45c98eff1812f52084ae3cda69ba8b6b85676dc2b1dbf82faacff58a71`，
  gold manifest SHA-256 为
  `a1dac7dd32687dcc575829c3fc5a2c85d4d979addb560ba4d98efc1f70871b42`。
- CP0/CP1/CP2 聚焦组：`82 passed, 1 skipped`；跳过项是未配置固定 ASM/CFR
  JAR 的真实工具集成测试，替身执行器的契约和失败路径已覆盖。
- CP1 API 聚焦回归：`39 passed`；覆盖错误后缀/MIME、顶层 WAR 原样保留、
  class 与 hybrid 分类、`NO_SUPPORTED_JVM_INPUT` 和二进制快照创建 AuditRun。
- 二进制清单、Program Index、Sink 候选、Orchestrator Artifact 水合、证据晋升和
  Finding 持久化聚焦回归：`69 passed, 1 skipped`。
- PostgreSQL 离线 DDL 与 ORM 聚焦回归：`8 passed`；迁移链只有一个 head
  `20260729_0009`。tree hash 仍使用 `cairn-source-tree-v1`。

仍未验证：真实 PostgreSQL 的 upgrade/downgrade、包含固定 ASM 9.8/CFR 0.152 的
Docker 镜像构建与无网络 Sandbox 集成，以及纯 WAR 从上传到 Coverage 的完整运行闭环。
因此本记录保持 `In Progress`；以上合成结果不能替代合法商业样本、双人标注和独立仲裁，
也不能作为任何厂商或版本支持声明。
