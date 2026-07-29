<script setup lang="ts">
import { computed } from "vue";

import { STAGES, isTerminal, stageIndex } from "@/stages";
import { tasksForStage } from "@/runClock";
import type { AuditRun, AuditTask } from "@/types/api";
import { duration } from "@/utils";

const props = defineProps<{
  run: AuditRun;
  tasks: AuditTask[];
  findingCounts: Record<string, number>;
  coverageWarnings: number;
}>();

const elapsed = computed(() => duration(props.run.started_at, props.run.completed_at));

const stageLabel = computed(() => {
  const index = stageIndex(props.run.current_stage);
  return index >= 0 ? STAGES[index].label : "准备";
});

/** "第 3/6 个范围" for the stage that is running, when it owns tasks. */
const stageDetail = computed(() => {
  const index = stageIndex(props.run.current_stage);
  if (index < 0) return "";
  const related = tasksForStage(props.tasks, STAGES[index]);
  if (!related.length) return "";
  const settled = related.filter((task) =>
    ["succeeded", "failed", "skipped", "cancelled"].includes(task.status),
  ).length;
  const unit = STAGES[index].key === "semantic_auditing" ? "个范围" : "个任务";
  return `第 ${Math.min(settled + 1, related.length)}/${related.length} ${unit}`;
});

const awaiting = computed(() => props.findingCounts.awaiting_human_review ?? 0);

const sentence = computed(() => {
  const run = props.run;
  if (run.status === "failed") {
    return `在${stageLabel.value}阶段失败：${run.failure_code || "未提供错误码"}`;
  }
  if (run.status === "cancelled") return `运行已取消 · 用时 ${elapsed.value}`;
  if (run.status === "completed") return `审计完成，无覆盖警告 · 用时 ${elapsed.value}`;
  if (run.status === "completed_with_warnings") {
    return `审计完成，带 ${props.coverageWarnings} 条覆盖警告 · 用时 ${elapsed.value}`;
  }
  if (run.status === "human_review") {
    return awaiting.value
      ? `等待人工处置 ${awaiting.value} 个 Finding`
      : "等待人工复核";
  }
  if (run.status === "created") return "等待编排器认领";
  if (run.status === "cancelling") return "正在取消，等待当前任务收尾";
  return [`正在${stageLabel.value}`, stageDetail.value, `已运行 ${elapsed.value}`]
    .filter(Boolean)
    .join(" · ");
});

const tone = computed(() => {
  if (props.run.status === "failed") return "danger";
  if (props.run.status === "human_review" && awaiting.value) return "action";
  if (props.run.status === "completed_with_warnings") return "warning";
  if (props.run.status === "completed") return "success";
  if (isTerminal(props.run)) return "neutral";
  return "info";
});
</script>

<template>
  <p class="narrative" :class="`narrative--${tone}`">{{ sentence }}</p>
</template>

<style scoped>
.narrative {
  margin: 8px 0 0;
  font-size: 13px;
  line-height: 1.5;
}
.narrative--info {
  color: var(--info);
}
.narrative--success {
  color: var(--success);
}
.narrative--warning {
  color: var(--warning);
}
.narrative--danger {
  color: var(--danger);
}
.narrative--neutral {
  color: var(--muted);
}
/* The only state that needs the reader to do something. */
.narrative--action {
  display: inline-block;
  padding: 6px 12px;
  color: var(--warning);
  font-weight: 700;
  background: var(--warning-soft);
  border-radius: 6px;
}
</style>
