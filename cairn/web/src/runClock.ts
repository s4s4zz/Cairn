import { STAGES, isTerminal, isTerminalSuccess, stageIndex, type StageDefinition } from "@/stages";
import { shortReason, taskShortTitle } from "@/taskLabels";
import type {
  AuditRun,
  AuditRunStageEvent,
  AuditStage,
  AuditTask,
  ToolCoverageRecord,
} from "@/types/api";

export type BarStatus =
  | "pending"
  | "running"
  | "succeeded"
  | "partial"
  | "failed"
  | "skipped"
  | "cancelled";

export interface ClockBar {
  key: string;
  kind: "stage" | "task";
  stageKey: AuditStage;
  label: string;
  status: BarStatus;
  startMs: number | null;
  endMs: number | null;
  durationMs: number | null;
  /** Fractions of the run window, 0..1. Null when the row has no timing at all. */
  offset: number | null;
  extent: number | null;
  /** Share of total wall clock, 0..1. */
  share: number | null;
  timeoutSeconds: number | null;
  /** Seconds left before this task's own timeout, only when it ran close to it. */
  timeoutHeadroomSeconds: number | null;
  candidateCount: number | null;
  note: string | null;
  taskId: string | null;
}

export interface ClockTick {
  label: string;
  offset: number;
}

export interface RunClock {
  bars: ClockBar[];
  ticks: ClockTick[];
  startMs: number | null;
  endMs: number | null;
  totalMs: number;
  /** True when at least one row carries usable timing. */
  hasTiming: boolean;
}

/** Tasks a stage owns, in the order the API returned them (creation order). */
export function tasksForStage(
  tasks: readonly AuditTask[],
  definition: StageDefinition,
): AuditTask[] {
  return tasks.filter((task) => definition.tasks.includes(task.type));
}

/**
 * The displayed state of one stage.
 *
 * Shared by the stage list and the waterfall so a stage cannot read "部分完成"
 * in one and "完成" in the other.
 */
export function stageState(
  run: Pick<AuditRun, "status" | "current_stage">,
  tasks: readonly AuditTask[],
  index: number,
): BarStatus {
  const definition = STAGES[index];
  if (!definition) return "pending";
  const related = tasksForStage(tasks, definition);
  if (related.some((task) => ["running", "claimed"].includes(task.status))) {
    return "running";
  }
  if (related.some((task) => task.status === "failed")) {
    return related.some((task) => ["succeeded", "skipped"].includes(task.status))
      ? "partial"
      : "failed";
  }
  if (
    related.length &&
    related.every((task) => ["succeeded", "skipped", "cancelled"].includes(task.status))
  ) {
    return related.every((task) => task.status === "skipped") ? "skipped" : "succeeded";
  }
  if (isTerminalSuccess(run)) return "succeeded";
  const current = stageIndex(run.current_stage);
  if (index === current && !["failed", "cancelled"].includes(run.status)) {
    return "running";
  }
  if (current >= 0 && index < current) return "succeeded";
  if (run.status === "failed" && index === current) return "failed";
  return "pending";
}

function taskStatusToBar(status: AuditTask["status"]): BarStatus {
  if (status === "running" || status === "claimed") return "running";
  if (status === "succeeded") return "succeeded";
  if (status === "failed") return "failed";
  if (status === "skipped") return "skipped";
  if (status === "cancelled") return "cancelled";
  return "pending";
}

function epoch(value: string | null | undefined): number | null {
  if (!value) return null;
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : null;
}

function toolRecord(
  toolCoverage: Record<string, ToolCoverageRecord> | null | undefined,
  token: string,
): ToolCoverageRecord | null {
  const record = toolCoverage?.[token];
  return record && typeof record === "object" ? record : null;
}

interface TimedRow {
  startMs: number | null;
  endMs: number | null;
}

function taskTiming(task: AuditTask, nowMs: number): TimedRow {
  const startMs = epoch(task.started_at);
  const finished = epoch(task.finished_at);
  if (task.status === "running" || task.status === "claimed") {
    return { startMs, endMs: startMs === null ? null : nowMs };
  }
  return { startMs, endMs: finished };
}

const TICK_COUNT = 4;

/**
 * Recorded stage windows, collapsed to one span per stage.
 *
 * A stage that is re-entered keeps the earliest entry and the latest exit, so
 * the bar still reads as "the time this stage occupied".
 */
function stageWindows(
  events: readonly AuditRunStageEvent[] | null | undefined,
  run: Pick<AuditRun, "status" | "completed_at">,
  nowMs: number,
): Map<AuditStage, TimedRow> {
  const windows = new Map<AuditStage, TimedRow>();
  if (!events?.length) return windows;
  const runEnd = epoch(run.completed_at);
  for (const event of events) {
    const startMs = epoch(event.entered_at);
    if (startMs === null) continue;
    // An open window belongs to the stage the run is in: it closes at the run's
    // own completion, or keeps growing while the run is live.
    const endMs = epoch(event.exited_at) ?? (isTerminal(run) ? runEnd : nowMs);
    const existing = windows.get(event.stage);
    windows.set(event.stage, {
      startMs: existing?.startMs === undefined ? startMs : Math.min(existing.startMs ?? startMs, startMs),
      endMs:
        existing?.endMs === undefined || existing.endMs === null
          ? endMs
          : endMs === null
            ? existing.endMs
            : Math.max(existing.endMs, endMs),
    });
  }
  return windows;
}

export function buildRunClock(input: {
  run: Pick<AuditRun, "status" | "current_stage" | "started_at" | "completed_at">;
  tasks: readonly AuditTask[];
  toolCoverage?: Record<string, ToolCoverageRecord> | null;
  stageEvents?: readonly AuditRunStageEvent[] | null;
  nowMs: number;
  formatDuration: (milliseconds: number) => string;
}): RunClock {
  const { run, tasks, toolCoverage, stageEvents, nowMs, formatDuration } = input;
  const recorded = stageWindows(stageEvents, run, nowMs);

  const starts: number[] = [];
  const ends: number[] = [];
  const runStart = epoch(run.started_at);
  if (runStart !== null) starts.push(runStart);
  const runEnd = epoch(run.completed_at);
  if (runEnd !== null) ends.push(runEnd);

  const timings = new Map<string, TimedRow>();
  for (const task of tasks) {
    const timing = taskTiming(task, nowMs);
    timings.set(task.id, timing);
    if (timing.startMs !== null) starts.push(timing.startMs);
    if (timing.endMs !== null) ends.push(timing.endMs);
  }
  for (const window of recorded.values()) {
    if (window.startMs !== null) starts.push(window.startMs);
    if (window.endMs !== null) ends.push(window.endMs);
  }

  const startMs = starts.length ? Math.min(...starts) : null;
  const endMs = ends.length ? Math.max(...ends) : null;
  const totalMs = startMs !== null && endMs !== null ? Math.max(0, endMs - startMs) : 0;
  const span = totalMs || 1;

  const fraction = (value: number | null): number | null =>
    value === null || startMs === null ? null : Math.min(1, Math.max(0, (value - startMs) / span));

  const bars: ClockBar[] = [];

  STAGES.forEach((definition, index) => {
    const related = tasksForStage(tasks, definition);
    const stageStarts = related
      .map((task) => timings.get(task.id)?.startMs ?? null)
      .filter((value): value is number => value !== null);
    const stageEnds = related
      .map((task) => timings.get(task.id)?.endMs ?? null)
      .filter((value): value is number => value !== null);
    // A recorded window is authoritative: it covers the stages that own no
    // task at all, which task-derived timing can never reach.
    const window = recorded.get(definition.key);
    const stageStart = window?.startMs ?? (stageStarts.length ? Math.min(...stageStarts) : null);
    const stageEnd = window?.endMs ?? (stageEnds.length ? Math.max(...stageEnds) : null);
    const stageDuration =
      stageStart !== null && stageEnd !== null ? Math.max(0, stageEnd - stageStart) : null;

    bars.push({
      key: `stage:${definition.key}`,
      kind: "stage",
      stageKey: definition.key,
      label: definition.label,
      status: stageState(run, tasks, index),
      startMs: stageStart,
      endMs: stageEnd,
      durationMs: stageDuration,
      offset: fraction(stageStart),
      extent: stageDuration === null ? null : Math.min(1, stageDuration / span),
      share: stageDuration === null || !totalMs ? null : stageDuration / totalMs,
      timeoutSeconds: null,
      timeoutHeadroomSeconds: null,
      candidateCount: null,
      note: related.length || stageDuration !== null ? null : "无子任务，暂无时间数据",      taskId: null,
    });

    for (const task of related) {
      const timing = timings.get(task.id) ?? { startMs: null, endMs: null };
      const duration =
        timing.startMs !== null && timing.endMs !== null
          ? Math.max(0, timing.endMs - timing.startMs)
          : null;
      const token = task.scope_key.split(":").at(-1) || task.type;
      const record = toolRecord(toolCoverage, token);
      const candidateCount =
        typeof record?.candidate_count === "number" ? record.candidate_count : null;
      // A skipped task carries `finished_at` but never `started_at`; anchoring it
      // at its finish keeps the gap visible at the point in time it happened
      // instead of dropping it out of the picture entirely.
      const anchor = timing.startMs ?? (task.status === "skipped" ? timing.endMs : null);
      const headroom =
        duration !== null && task.timeout_seconds > 0
          ? task.timeout_seconds - duration / 1000
          : null;

      bars.push({
        key: `task:${task.id}`,
        kind: "task",
        stageKey: definition.key,
        label: taskShortTitle(task),
        status: taskStatusToBar(task.status),
        startMs: timing.startMs,
        endMs: timing.endMs,
        durationMs: duration,
        offset: fraction(anchor),
        extent: duration === null ? null : Math.min(1, duration / span),
        share: duration === null || !totalMs ? null : duration / totalMs,
        timeoutSeconds: task.timeout_seconds || null,
        timeoutHeadroomSeconds:
          headroom !== null && duration !== null && duration / 1000 >= task.timeout_seconds * 0.8
            ? Math.max(0, Math.round(headroom))
            : null,
        candidateCount,
        note:
          task.status === "skipped" || task.status === "failed"
            ? shortReason(task.error_code ?? record?.reason_code ?? null)
            : null,
        taskId: task.id,
      });
    }
  });

  const ticks: ClockTick[] = [];
  if (totalMs > 0) {
    for (let step = 0; step <= TICK_COUNT; step += 1) {
      const offset = step / TICK_COUNT;
      ticks.push({ label: formatDuration(totalMs * offset), offset });
    }
  }

  return {
    bars,
    ticks,
    startMs,
    endMs,
    totalMs,
    hasTiming: bars.some((bar) => bar.durationMs !== null),
  };
}
