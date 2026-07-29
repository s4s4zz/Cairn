import { onBeforeUnmount, ref, type Ref } from "vue";

import type { AuditRunEventSnapshot } from "@/types/api";

/**
 * A narrative rebuilt from the SSE snapshot stream.
 *
 * Two honest limits, both surfaced in the panel that renders these events:
 *
 * 1. The stream carries snapshots, not events. Two changes that land between
 *    consecutive snapshots collapse into one net difference, so this is a
 *    reconstruction rather than an authoritative event record — the operation
 *    audit log remains that.
 * 2. Timestamps are the moment the browser observed the change, not the moment
 *    the orchestrator made it. Opening the page mid-run therefore starts the
 *    narrative at the point of connection.
 */
export type RunEventTone = "neutral" | "info" | "success" | "warning" | "danger";

export interface RunEvent {
  id: string;
  at: string;
  tone: RunEventTone;
  text: string;
}

const STAGE_LABELS: Record<string, string> = {
  ingesting: "源码接入",
  preprocessing: "项目盘点",
  building: "隔离构建",
  static_scanning: "静态扫描",
  semantic_auditing: "AI 语义审计",
  dynamic_verifying: "动态验证",
  machine_review: "机器复核",
  human_review: "人工复核",
  coverage_check: "覆盖检查",
  reporting: "生成报告",
};

const TERMINAL_TEXT: Record<string, { text: string; tone: RunEventTone }> = {
  completed: { text: "运行完成", tone: "success" },
  completed_with_warnings: { text: "运行完成（带警告）", tone: "warning" },
  cancelled: { text: "运行已取消", tone: "neutral" },
  failed: { text: "运行失败", tone: "danger" },
};

const FINDING_TRANSITIONS: Array<{
  key: string;
  label: string;
  tone: RunEventTone;
}> = [
  { key: "validating", label: "进入验证", tone: "info" },
  { key: "machine_confirmed", label: "机器确认", tone: "info" },
  { key: "awaiting_human_review", label: "进入人工队列", tone: "warning" },
  { key: "confirmed", label: "确认为真实漏洞", tone: "danger" },
  { key: "rejected", label: "被驳回", tone: "neutral" },
  { key: "accepted_risk", label: "被接受风险", tone: "neutral" },
];

const TASK_TRANSITIONS: Array<{ key: string; label: string; tone: RunEventTone }> = [
  { key: "succeeded", label: "个任务完成", tone: "success" },
  { key: "failed", label: "个任务失败", tone: "danger" },
  { key: "skipped", label: "个任务被跳过", tone: "warning" },
];

function count(counts: Record<string, number> | undefined, key: string): number {
  return counts?.[key] ?? 0;
}

function total(counts: Record<string, number> | undefined): number {
  return Object.values(counts ?? {}).reduce((sum, value) => sum + value, 0);
}

/**
 * Net difference between two snapshots, as human-readable lines.
 *
 * Returns nothing for the first snapshot: it is a baseline, not a change.
 */
export function diffSnapshots(
  previous: AuditRunEventSnapshot | null,
  next: AuditRunEventSnapshot,
  at: string,
): Omit<RunEvent, "id">[] {
  if (!previous) return [];
  const events: Omit<RunEvent, "id">[] = [];

  if (previous.current_stage !== next.current_stage && next.current_stage) {
    events.push({
      at,
      tone: "info",
      text: `进入 ${STAGE_LABELS[next.current_stage] ?? next.current_stage}`,
    });
  }

  for (const transition of TASK_TRANSITIONS) {
    const delta = count(next.task_counts, transition.key) - count(previous.task_counts, transition.key);
    if (delta > 0) {
      events.push({ at, tone: transition.tone, text: `${delta} ${transition.label}` });
    }
  }

  const candidateDelta = total(next.finding_counts) - total(previous.finding_counts);
  if (candidateDelta > 0) {
    events.push({
      at,
      tone: "info",
      text: `新增 ${candidateDelta} 个候选（累计 ${total(next.finding_counts)}）`,
    });
  }

  for (const transition of FINDING_TRANSITIONS) {
    const delta = count(next.finding_counts, transition.key) - count(previous.finding_counts, transition.key);
    if (delta > 0) {
      events.push({ at, tone: transition.tone, text: `${delta} 个 Finding ${transition.label}` });
    }
  }

  const warningDelta = next.coverage_warning_count - previous.coverage_warning_count;
  if (warningDelta > 0) {
    events.push({
      at,
      tone: "warning",
      text: `新增 ${warningDelta} 条覆盖警告（累计 ${next.coverage_warning_count}）`,
    });
  }

  if (previous.status !== next.status && TERMINAL_TEXT[next.status]) {
    const terminal = TERMINAL_TEXT[next.status];
    events.push({
      at,
      tone: terminal.tone,
      text: next.failure_code ? `${terminal.text}：${next.failure_code}` : terminal.text,
    });
  }

  return events;
}

export function useRunNarrative(limit = 200): {
  events: Ref<RunEvent[]>;
  record: (snapshot: AuditRunEventSnapshot) => void;
  reset: () => void;
} {
  const events = ref<RunEvent[]>([]);
  let previous: AuditRunEventSnapshot | null = null;
  let sequence = 0;

  function record(snapshot: AuditRunEventSnapshot): void {
    const at = new Date().toISOString();
    const produced = diffSnapshots(previous, snapshot, at);
    previous = snapshot;
    if (!produced.length) return;
    const next = produced.map((event) => {
      sequence += 1;
      return { ...event, id: `event-${sequence}` };
    });
    // Newest first; the tail is dropped rather than growing without bound.
    events.value = [...next.reverse(), ...events.value].slice(0, limit);
  }

  function reset(): void {
    previous = null;
    events.value = [];
  }

  onBeforeUnmount(reset);
  return { events, record, reset };
}
