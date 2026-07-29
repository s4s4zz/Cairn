import type { AuditTask } from "@/types/api";

/**
 * Semantic review categories.
 *
 * These values match the `categoryLabel` table being added to `utils.ts` in
 * parallel work; this copy exists only so this module compiles on its own.
 * Collapse it onto `utils.categoryLabel` as soon as that table lands — two
 * tables for one enum is exactly the drift the rest of this file removes.
 */
const categoryNames: Record<string, string> = {
  authorization: "越权访问",
  "command-execution": "命令执行",
  "command-injection": "命令注入",
  "sql-injection": "SQL 注入",
  ssrf: "服务端请求伪造（SSRF）",
  xxe: "XML 外部实体注入（XXE）",
  "path-traversal": "路径穿越",
  "unsafe-deserialization": "不安全反序列化",
};

function categoryLabel(value: string): string {
  return categoryNames[value] ?? value;
}

/**
 * Human labels for tasks, scopes and error codes.
 *
 * Extracted from `StageTimeline` so the stage list and the waterfall name the
 * same task identically; two independent label tables would let one view call
 * a row "Semgrep Java 安全规则扫描" while the other calls it `sast`.
 */
const taskNames: Record<string, string> = {
  inventory: "Java 项目盘点",
  build: "隔离构建",
  sast: "代码安全扫描",
  dependency_scan: "依赖漏洞扫描",
  secret_scan: "敏感信息扫描",
  config_scan: "配置安全扫描",
  semantic_review: "AI 语义分析",
  dynamic_verify: "动态验证",
  independent_verify: "独立机器复核",
  coverage_check: "覆盖率检查",
  report: "报告生成",
};

const scopeNames: Record<string, string> = {
  inventory: "项目结构、模块、入口点与敏感调用盘点",
  build: "编译源码并收集字节码与可运行制品",
  codeql: "CodeQL 数据流扫描",
  semgrep: "Semgrep Java 安全规则扫描",
  findsecbugs: "FindSecBugs 字节码扫描",
  "dependency-check": "OWASP Dependency-Check 依赖扫描",
  trivy: "Trivy 依赖与配置扫描",
  gitleaks: "Gitleaks 密钥泄漏扫描",
  "config-rules": "Spring 与部署配置规则检查",
};

const errorDescriptions: Record<string, string> = {
  BYTECODE_UNAVAILABLE: "构建未产出可供该工具分析的 Java 字节码。",
  SCANNER_BINARY_UNAVAILABLE: "当前扫描镜像尚未配置该工具的可执行文件。",
  SANDBOX_PROCESS_FAILED:
    "隔离沙箱中的 Worker 异常退出；展开任务可核对范围、Worker 和尝试次数。",
  INVENTORY_FAILED: "项目结构与入口点清单没有成功生成。",
  SEMANTIC_BUDGET_EXHAUSTED: "模型请求或输出预算已耗尽，未生成最终结论。",
  SEMANTIC_MODEL_UNAVAILABLE: "当前模型服务不可用或拒绝了本次请求。",
};

/** Short reasons for the waterfall, where a full sentence would not fit. */
const shortReasons: Record<string, string> = {
  BYTECODE_UNAVAILABLE: "无字节码",
  SCANNER_BINARY_UNAVAILABLE: "工具缺失",
  SANDBOX_PROCESS_FAILED: "沙箱异常退出",
  INVENTORY_FAILED: "盘点失败",
  SEMANTIC_BUDGET_EXHAUSTED: "预算耗尽",
  SEMANTIC_MODEL_UNAVAILABLE: "模型不可用",
};

/** The trailing segment of a scope key: the tool or category the task ran for. */
export function taskScopeToken(task: AuditTask): string {
  return task.scope_key.split(":").at(-1) || task.type;
}

export function taskTitle(task: AuditTask): string {
  const token = taskScopeToken(task);
  if (task.type === "semantic_review") {
    return `${taskNames[task.type]}：${categoryLabel(token)}`;
  }
  return scopeNames[token] || taskNames[task.type] || task.type;
}

/** A compact label for the waterfall, where the stage name is already shown. */
export function taskShortTitle(task: AuditTask): string {
  const token = taskScopeToken(task);
  if (task.type === "semantic_review") return categoryLabel(token);
  return token === task.type ? taskNames[task.type] || task.type : token;
}

export function taskErrorDescription(task: AuditTask): string {
  return (
    task.error_detail ||
    (task.error_code ? errorDescriptions[task.error_code] : "") ||
    "任务没有返回更详细的错误信息。"
  );
}

export function shortReason(code: string | null): string | null {
  if (!code) return null;
  return shortReasons[code] || code;
}

export function scopeMetadata(task: AuditTask): string {
  const entrypointCount = Array.isArray(task.scope.entrypoint_paths)
    ? task.scope.entrypoint_paths.length
    : 0;
  const values = [
    typeof task.scope.module === "string" ? `模块 ${task.scope.module}` : "",
    typeof task.scope.attack_surface === "string" ? task.scope.attack_surface : "",
    typeof task.scope.category === "string" ? categoryLabel(task.scope.category) : "",
    entrypointCount ? `${entrypointCount} 个入口文件` : "",
  ].filter(Boolean);
  return values.join(" · ");
}

export function timeoutLabel(seconds: number): string {
  if (seconds >= 60 && seconds % 60 === 0) return `${seconds / 60} 分钟`;
  return `${seconds} 秒`;
}

/** Compact elapsed label for time bars: "18分40" rather than "18分 40秒". */
export function compactDuration(milliseconds: number): string {
  const totalSeconds = Math.max(0, Math.round(milliseconds / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours) return `${hours}时${minutes}分`;
  if (minutes) return `${minutes}分${String(seconds).padStart(2, "0")}`;
  return `${seconds}秒`;
}
