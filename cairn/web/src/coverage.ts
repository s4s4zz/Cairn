import { STAGES, hasPassedStage, stageForTaskType } from "@/stages";
import type { AuditCoverage, AuditRun, AuditStage, AuditTask } from "@/types/api";

/**
 * Coverage fields carry database defaults long before the stage that fills
 * them has run. A fresh `AuditCoverage` row is created on the first line of
 * preprocessing with `build_status = "failed"` and every `*_analyzed` at zero,
 * so rendering the raw row mid-run reports a failed build and zero coverage
 * for a run that is proceeding normally.
 *
 * Every reader here therefore answers three states rather than two: the value
 * is either not yet produced, in production, or final.
 */
export type MetricState = "unknown" | "counting" | "ready";

export interface CoverageMetric {
  key: string;
  label: string;
  value: number;
  total: number;
  state: MetricState;
  /** Percentage, only meaningful when `state === "ready"`. */
  ratio: number;
  /** The stage that produces the numerator. */
  producedBy: AuditStage;
}

export interface BuildStatusDisplay {
  label: string;
  tone: "success" | "warning" | "danger" | "neutral";
  known: boolean;
}

export interface CoverageGap {
  key: string;
  kind: "tool" | "path" | "component" | "warning";
  /** Drives the shared status glyph; skipped and failed are both gaps. */
  tone: "skipped" | "failed" | "warning";
  title: string;
  code: string | null;
  detail: string | null;
  stageLabel: string | null;
}

const REASON_SENTENCES: Record<string, string> = {
  BYTECODE_UNAVAILABLE: "构建未产出字节码，字节码层规则未运行。",
  SCANNER_BINARY_UNAVAILABLE: "扫描镜像未配置该工具，规则未运行。",
  SCANNER_EXECUTION_FAILED: "扫描器执行失败，该工具的结果不可用。",
  SANDBOX_PROCESS_FAILED: "隔离沙箱中的 Worker 异常退出，该范围未完成。",
  INVENTORY_FAILED: "项目结构与入口点清单未生成，后续范围推导不完整。",
  SEMANTIC_BUDGET_EXHAUSTED: "模型预算耗尽，该范围未得出结论。",
  SEMANTIC_MODEL_UNAVAILABLE: "模型服务不可用或拒绝请求，该范围未得出结论。",
  SEMANTIC_REVIEW_FAILED: "语义审计未完成，该范围未得出结论。",
  SEMANTIC_REVIEW_INCOMPLETE: "模型未给出完整结论，该范围按未覆盖处理。",
  SEMANTIC_PLAN_TRUNCATED: "语义审计计划超出上限被截断，尾部范围未审计。",
  DYNAMIC_BUDGET_EXHAUSTED: "动态验证预算耗尽，剩余候选未运行时验证。",
  VERIFICATION_BUDGET_EXHAUSTED: "机器复核预算耗尽，剩余候选未独立复核。",
  POC_BUDGET_EXHAUSTED: "PoC 编写预算耗尽，剩余候选未生成 PoC。",
};

/** Never invent an explanation for a code we do not know. */
function reasonSentence(code: string | null, tool: string | null): string {
  if (code && REASON_SENTENCES[code]) return REASON_SENTENCES[code];
  if (tool) return `${tool} 报告了未覆盖原因，详见原因码。`;
  return "该项被记录为未覆盖，详见原因码。";
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

export function coverageMetrics(
  run: Pick<AuditRun, "status" | "current_stage">,
  coverage: AuditCoverage,
): CoverageMetric[] {
  const inventoryDone = hasPassedStage(run, "preprocessing");
  const semanticDone = hasPassedStage(run, "semantic_auditing");

  const build = (
    key: string,
    label: string,
    value: number,
    total: number,
    ready: boolean,
    producedBy: AuditStage,
  ): CoverageMetric => ({
    key,
    label,
    value,
    total,
    state: ready ? "ready" : total > 0 ? "counting" : "unknown",
    ratio: total ? Math.round((value / total) * 100) : 0,
    producedBy,
  });

  return [
    build("modules", "模块", coverage.modules_analyzed, coverage.modules_total, inventoryDone, "preprocessing"),
    build("java_files", "Java 文件", coverage.java_files_analyzed, coverage.java_files_total, inventoryDone, "preprocessing"),
    build("entrypoints", "入口点", coverage.entrypoints_analyzed, coverage.entrypoints_total, semanticDone, "semantic_auditing"),
    build("sinks", "敏感 Sink", coverage.sensitive_sinks_analyzed, coverage.sensitive_sinks_total, semanticDone, "semantic_auditing"),
  ];
}

/**
 * `failed` is also the constructor default, so it is the one value that cannot
 * be trusted until the build stage has been passed. `success` and `partial`
 * are only ever written by a real build and are shown as soon as they appear.
 */
export function buildStatusDisplay(
  run: Pick<AuditRun, "status" | "current_stage">,
  coverage: AuditCoverage,
): BuildStatusDisplay {
  if (coverage.build_status === "success") {
    return { label: "构建成功", tone: "success", known: true };
  }
  if (coverage.build_status === "partial") {
    return { label: "部分构建", tone: "warning", known: true };
  }
  if (hasPassedStage(run, "building")) {
    return { label: "构建失败", tone: "danger", known: true };
  }
  return { label: "尚未构建", tone: "neutral", known: false };
}

function stageLabelForTool(tool: string | null, tasks: readonly AuditTask[]): string | null {
  if (!tool) return null;
  const owner = tasks.find((task) => task.scope_key.split(":").at(-1) === tool);
  if (owner) return stageForTaskType(owner.type)?.label ?? null;
  const named = STAGES.find((stage) => stage.key === tool);
  return named?.label ?? null;
}

/**
 * One table out of the four places a gap can hide: per-tool records, skipped
 * paths, unsupported components and coverage warnings. Split across four
 * panels they read as trivia; together they are the run's uncovered surface.
 */
export function collectGaps(
  coverage: AuditCoverage,
  tasks: readonly AuditTask[] = [],
): CoverageGap[] {
  const gaps: CoverageGap[] = [];

  for (const [tool, record] of Object.entries(coverage.static_tools_completed ?? {})) {
    if (!record || typeof record !== "object") continue;
    const status = text(record.status);
    if (!status || status === "completed") continue;
    const code = text(record.reason_code);
    gaps.push({
      key: `tool:${tool}`,
      kind: "tool",
      tone: status === "failed" ? "failed" : "skipped",
      title: `${tool} ${status === "failed" ? "执行失败" : "未执行"}`,
      code,
      detail: reasonSentence(code, tool),
      stageLabel: stageLabelForTool(tool, tasks),
    });
  }

  if (coverage.skipped_paths.length) {
    gaps.push({
      key: "paths",
      kind: "path",
      tone: "skipped",
      title: `${coverage.skipped_paths.length} 个路径未纳入分析`,
      code: null,
      detail: coverage.skipped_paths.slice(0, 8).join("  "),
      stageLabel: "项目盘点",
    });
  }

  coverage.unsupported_components.forEach((component, index) => {
    const name =
      text(component.name) ?? text(component.path) ?? text(component.component) ?? `组件 ${index + 1}`;
    gaps.push({
      key: `component:${index}`,
      kind: "component",
      tone: "warning",
      title: `${name} 不受支持`,
      code: text(component.reason_code) ?? text(component.code),
      detail: text(component.detail) ?? text(component.reason) ?? "该组件不在当前分析器的支持范围内。",
      stageLabel: "项目盘点",
    });
  });

  coverage.coverage_warnings.forEach((warning, index) => {
    const code = text(warning.reason_code) ?? text(warning.code);
    const tool = text(warning.tool);
    // Deduplicate against a per-tool record that already says the same thing.
    if (code && tool && gaps.some((gap) => gap.kind === "tool" && gap.code === code && gap.title.startsWith(tool))) {
      return;
    }
    gaps.push({
      key: `warning:${code ?? index}:${tool ?? index}`,
      kind: "warning",
      tone: "warning",
      title: tool ? `${tool} 报告覆盖缺口` : "覆盖缺口",
      code,
      detail: text(warning.message) ?? text(warning.detail) ?? reasonSentence(code, tool),
      stageLabel: stageLabelForTool(tool, tasks),
    });
  });

  return gaps;
}
