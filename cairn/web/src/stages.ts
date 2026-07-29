import type { AuditRun, AuditStage, AuditRunStatus } from "@/types/api";

/**
 * The one place that knows the audit stage order.
 *
 * `StageTimeline`, the waterfall, the process bar and the Coverage tri-state
 * all derive from this list. Keeping a second copy anywhere would let the
 * display drift from the orchestrator's own progression the first time a stage
 * is inserted (§9.3 of the process-visibility plan).
 */
export interface StageDefinition {
  key: AuditStage;
  /** Full label used in the stage list and the waterfall. */
  label: string;
  /** One or two characters for the dense stage cursor. */
  short: string;
  /** `AuditTask.type` values this stage owns. */
  tasks: readonly string[];
}

export const STAGES: readonly StageDefinition[] = [
  { key: "ingesting", label: "源码接入", short: "接", tasks: [] },
  { key: "preprocessing", label: "项目盘点", short: "盘", tasks: ["inventory"] },
  { key: "building", label: "隔离构建", short: "构", tasks: ["build"] },
  {
    key: "static_scanning",
    label: "静态扫描",
    short: "静",
    tasks: ["sast", "dependency_scan", "secret_scan", "config_scan"],
  },
  {
    key: "semantic_auditing",
    label: "AI 语义审计",
    short: "语",
    tasks: ["semantic_review"],
  },
  { key: "dynamic_verifying", label: "动态验证", short: "动", tasks: ["dynamic_verify"] },
  { key: "machine_review", label: "机器复核", short: "机", tasks: ["independent_verify"] },
  { key: "human_review", label: "人工复核", short: "人", tasks: [] },
  { key: "coverage_check", label: "覆盖检查", short: "覆", tasks: ["coverage_check"] },
  { key: "reporting", label: "生成报告", short: "报", tasks: ["report"] },
];

export const TERMINAL_SUCCESS_STATUSES: readonly AuditRunStatus[] = [
  "completed",
  "completed_with_warnings",
];

export const TERMINAL_STATUSES: readonly AuditRunStatus[] = [
  ...TERMINAL_SUCCESS_STATUSES,
  "cancelled",
  "failed",
];

export function stageIndex(stage: AuditStage | null): number {
  return STAGES.findIndex((definition) => definition.key === stage);
}

export function isTerminal(run: Pick<AuditRun, "status">): boolean {
  return TERMINAL_STATUSES.includes(run.status);
}

export function isTerminalSuccess(run: Pick<AuditRun, "status">): boolean {
  return TERMINAL_SUCCESS_STATUSES.includes(run.status);
}

/**
 * How far the run has moved relative to one stage.
 *
 * `passed` is the predicate the Coverage panel needs: a field whose producing
 * stage has not been passed must read as "not yet known" rather than as its
 * database default, which is how a fresh `AuditCoverage` row ends up claiming
 * the build failed before any build has run.
 */
export type StageProgress = "pending" | "active" | "passed";

export function stageProgress(
  run: Pick<AuditRun, "status" | "current_stage">,
  stage: AuditStage,
): StageProgress {
  const target = stageIndex(stage);
  if (target < 0) return "pending";
  if (isTerminalSuccess(run)) return "passed";
  const current = stageIndex(run.current_stage);
  if (current < 0) return "pending";
  if (current > target) return "passed";
  if (current === target) return "active";
  return "pending";
}

export function hasPassedStage(
  run: Pick<AuditRun, "status" | "current_stage">,
  stage: AuditStage,
): boolean {
  return stageProgress(run, stage) === "passed";
}

/** The stage that owns an `AuditTask.type`, or null for task types we do not map. */
export function stageForTaskType(type: string): StageDefinition | null {
  return STAGES.find((definition) => definition.tasks.includes(type)) ?? null;
}
