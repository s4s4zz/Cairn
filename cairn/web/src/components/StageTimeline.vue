<script setup lang="ts">
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Circle,
  FileDown,
  LoaderCircle,
  Minus,
  RotateCcw,
} from "@lucide/vue";
import { computed, ref, watch } from "vue";

import { reportApi } from "@/api/resources";
import StatusBadge from "@/components/StatusBadge.vue";
import { buildRunClock, stageState, tasksForStage, type BarStatus } from "@/runClock";
import { STAGES } from "@/stages";
import {
  compactDuration,
  scopeMetadata,
  taskErrorDescription,
  taskScopeToken,
  taskTitle,
  timeoutLabel,
} from "@/taskLabels";
import type { AuditRun, AuditTask, ToolCoverageRecord } from "@/types/api";
import { duration, formatDate, shortId } from "@/utils";

const props = defineProps<{
  run: AuditRun;
  tasks: AuditTask[];
  toolCoverage?: Record<string, ToolCoverageRecord> | null;
}>();

const clock = computed(() =>
  buildRunClock({
    run: props.run,
    tasks: props.tasks,
    toolCoverage: props.toolCoverage,
    nowMs: Date.now(),
    formatDuration: compactDuration,
  }),
);

const stageBars = computed(() =>
  new Map(clock.value.bars.filter((bar) => bar.kind === "stage").map((bar) => [bar.stageKey, bar])),
);

function state(index: number): BarStatus {
  return stageState(props.run, props.tasks, index);
}

function stageTasks(index: number): AuditTask[] {
  return tasksForStage(props.tasks, STAGES[index]);
}

function stateLabel(value: BarStatus): string {
  return (
    {
      pending: "等待",
      running: "执行中",
      succeeded: "完成",
      partial: "部分完成",
      failed: "失败",
      skipped: "已跳过",
      cancelled: "已取消",
    }[value] ?? value
  );
}

function elapsed(index: number): string {
  const bar = stageBars.value.get(STAGES[index].key);
  return bar?.durationMs === null || bar === undefined ? "-" : compactDuration(bar.durationMs);
}

function share(index: number): number | null {
  return stageBars.value.get(STAGES[index].key)?.share ?? null;
}

function attempts(index: number): string {
  const related = stageTasks(index);
  if (!related.length) return "-";
  const retries = related.reduce((sum, task) => sum + Math.max(0, task.attempt - 1), 0);
  return retries ? `${retries} 次` : "无";
}

function toolRecord(task: AuditTask): ToolCoverageRecord | null {
  const record = props.toolCoverage?.[taskScopeToken(task)];
  return record && typeof record === "object" ? record : null;
}

function taskCandidates(task: AuditTask): number | null {
  const value = toolRecord(task)?.candidate_count;
  return typeof value === "number" ? value : null;
}

function toolVersion(task: AuditTask): string | null {
  const value = toolRecord(task)?.version;
  return typeof value === "string" && value ? value : null;
}

/** Candidates a stage produced, when its tools report one. */
function stageCandidates(index: number): number | null {
  const counts = stageTasks(index)
    .map(taskCandidates)
    .filter((value): value is number => value !== null);
  return counts.length ? counts.reduce((sum, value) => sum + value, 0) : null;
}

function taskDescription(task: AuditTask): string {
  if (task.status === "queued") return "等待 Worker 领取";
  if (task.status === "claimed") return "Worker 已领取，正在准备沙箱";
  if (task.status === "running") {
    return task.type === "semantic_review"
      ? "模型正在按需读取相关源码并分析入口到 Sink 的调用链"
      : "沙箱正在执行该工具";
  }
  if (task.status === "succeeded") {
    const candidates = taskCandidates(task);
    return candidates === null
      ? "任务成功完成并已收集结果"
      : `沙箱执行完成，产出 ${candidates} 个候选`;
  }
  if (task.status === "skipped") return "前置条件不满足，任务已跳过";
  if (task.status === "cancelled") return "任务已取消";
  return "任务未完成，请查看下方错误码";
}

function stageSummary(index: number): string {
  const related = stageTasks(index);
  const active = related.find((task) => ["running", "claimed"].includes(task.status));
  if (active) return `正在执行：${taskTitle(active)}`;
  if (!related.length) return "该阶段没有后台子任务";
  const succeeded = related.filter((task) => task.status === "succeeded").length;
  const failed = related.filter((task) => task.status === "failed").length;
  const skipped = related.filter((task) => task.status === "skipped").length;
  return [
    `${related.length} 个任务`,
    `${succeeded} 成功`,
    failed ? `${failed} 失败` : "",
    skipped ? `${skipped} 跳过` : "",
  ]
    .filter(Boolean)
    .join(" · ");
}

function needsAttention(index: number): boolean {
  return ["running", "partial", "failed"].includes(state(index));
}

// A stage opens itself when it starts needing attention, but never closes
// itself: binding `open` straight to the derived state folded the panel the
// reader was using at the very moment its tasks finished.
const openStages = ref<Record<string, boolean>>({});

watch(
  () => STAGES.map((_stage, index) => needsAttention(index)),
  (next, previous) => {
    next.forEach((attention, index) => {
      if (attention && !previous?.[index]) {
        openStages.value[STAGES[index].key] = true;
      }
    });
  },
  { immediate: true },
);

function isOpen(key: string): boolean {
  return openStages.value[key] ?? false;
}

function rememberOpen(key: string, event: Event): void {
  openStages.value[key] = (event.target as HTMLDetailsElement).open;
}

defineExpose({
  open(key: string) {
    openStages.value[key] = true;
  },
});
</script>

<template>
  <ol class="stage-list">
    <li
      v-for="(stage, index) in STAGES"
      :key="stage.key"
      class="stage-group"
      :class="`stage-group--${state(index)}`"
      :data-stage="stage.key"
    >
      <details :open="isOpen(stage.key)" @toggle="rememberOpen(stage.key, $event)">
        <summary class="stage-row">
          <span class="stage-marker">
            <Check v-if="state(index) === 'succeeded'" :size="14" />
            <LoaderCircle v-else-if="state(index) === 'running'" class="spin" :size="14" />
            <AlertTriangle
              v-else-if="['failed', 'partial', 'skipped'].includes(state(index))"
              :size="14"
            />
            <Minus v-else-if="state(index) === 'cancelled'" :size="14" />
            <Circle v-else :size="11" />
          </span>
          <span class="stage-name">
            <strong>{{ stage.label }}</strong>
            <small>{{ stageSummary(index) }}</small>
          </span>
          <span class="stage-state">{{ stateLabel(state(index)) }}</span>
          <span class="stage-meta stage-meta--share">
            <small>耗时占比</small>
            <span class="share">
              <span class="share__track">
                <span :style="{ width: `${(share(index) ?? 0) * 100}%` }" />
              </span>
              <strong>{{ share(index) === null ? "-" : `${Math.round(share(index)! * 100)}%` }}</strong>
            </span>
          </span>
          <span class="stage-meta">
            <small>耗时</small>
            <strong>{{ elapsed(index) }}</strong>
          </span>
          <span class="stage-meta">
            <small>产出</small>
            <strong>{{ stageCandidates(index) === null ? "-" : `${stageCandidates(index)} 候选` }}</strong>
          </span>
          <span class="stage-meta">
            <small>重试</small>
            <strong>
              <RotateCcw v-if="attempts(index) !== '-'" :size="11" />
              {{ attempts(index) }}
            </strong>
          </span>
          <ChevronDown v-if="stageTasks(index).length" class="stage-chevron" :size="16" />
        </summary>

        <div v-if="stageTasks(index).length" class="task-list">
          <article
            v-for="task in stageTasks(index)"
            :key="task.id"
            class="task-row"
            :class="`task-row--${task.status}`"
          >
            <div class="task-main">
              <div class="task-heading">
                <strong>{{ taskTitle(task) }}</strong>
                <StatusBadge :value="task.status" />
                <span v-if="task.worker_name?.includes(':')" class="task-role">
                  {{ task.worker_name.split(":").at(-1) }}
                </span>
              </div>
              <p>{{ taskDescription(task) }}</p>
              <code>{{ task.scope_key }}</code>
              <small v-if="scopeMetadata(task)">{{ scopeMetadata(task) }}</small>
            </div>
            <dl class="task-facts">
              <div>
                <dt>尝试</dt>
                <dd>{{ task.attempt }} / {{ task.max_attempts }}</dd>
              </div>
              <div>
                <dt>Worker</dt>
                <dd :title="task.worker_name || '-'">{{ task.worker_name || "-" }}</dd>
              </div>
              <div>
                <dt>开始</dt>
                <dd>{{ formatDate(task.started_at || task.created_at) }}</dd>
              </div>
              <div>
                <dt>耗时</dt>
                <dd>{{ duration(task.started_at, task.finished_at) }}</dd>
              </div>
              <div>
                <dt>超时上限</dt>
                <dd>{{ timeoutLabel(task.timeout_seconds) }}</dd>
              </div>
              <div>
                <dt>工具版本</dt>
                <dd>{{ toolVersion(task) || "-" }}</dd>
              </div>
            </dl>
            <div v-if="task.output_artifact_ids?.length" class="task-artifacts">
              <span>产物</span>
              <a
                v-for="artifactId in task.output_artifact_ids"
                :key="artifactId"
                :href="reportApi.artifactUrl(artifactId)"
                target="_blank"
                rel="noopener"
              >
                <FileDown :size="12" />{{ shortId(artifactId) }}
              </a>
            </div>
            <div v-if="task.error_code || task.error_detail" class="task-error">
              <AlertTriangle :size="14" />
              <div>
                <strong>{{ task.error_code || "TASK_FAILED" }}</strong>
                <p>{{ taskErrorDescription(task) }}</p>
              </div>
            </div>
          </article>
        </div>
      </details>
    </li>
  </ol>
</template>

<style scoped>
.stage-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.stage-group {
  border-bottom: 1px solid var(--line);
}
.stage-group:last-child {
  border-bottom: 0;
}
.stage-group details[open] {
  background: #fbfcfc;
}
.stage-row {
  display: grid;
  min-height: 72px;
  grid-template-columns:
    28px minmax(190px, 1.4fr) 72px minmax(104px, 0.9fr)
    72px 72px 56px 18px;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  cursor: pointer;
  list-style: none;
}
.stage-row::-webkit-details-marker {
  display: none;
}
.stage-marker {
  display: inline-flex;
  width: 24px;
  height: 24px;
  align-items: center;
  justify-content: center;
  color: #7a8580;
  background: #edf0ef;
  border-radius: 50%;
}
.stage-group--succeeded .stage-marker {
  color: var(--success);
  background: var(--success-soft);
}
.stage-group--running .stage-marker {
  color: var(--info);
  background: var(--info-soft);
}
.stage-group--failed .stage-marker {
  color: var(--danger);
  background: var(--danger-soft);
}
/* A skipped stage is a coverage gap, so it carries the same weight as a
   partial one rather than the neutral grey of a stage that has not started. */
.stage-group--partial .stage-marker,
.stage-group--skipped .stage-marker {
  color: var(--warning);
  background: var(--warning-soft);
}
.stage-name {
  display: grid;
  min-width: 0;
  gap: 4px;
}
.stage-name strong {
  color: #2d3833;
  font-size: 12px;
}
.stage-name small {
  overflow: hidden;
  color: var(--muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stage-state {
  color: var(--muted);
  font-size: 11px;
  font-weight: 700;
}
.stage-group--running .stage-state {
  color: var(--info);
}
.stage-group--failed .stage-state {
  color: var(--danger);
}
.stage-group--partial .stage-state,
.stage-group--skipped .stage-state {
  color: var(--warning);
}
.stage-meta {
  display: grid;
  min-width: 0;
  gap: 3px;
}
.stage-meta small {
  color: var(--subtle);
  font-size: 10px;
}
.stage-meta strong {
  display: flex;
  align-items: center;
  gap: 4px;
  overflow: hidden;
  color: #53605a;
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.share {
  display: flex;
  align-items: center;
  gap: 6px;
}
.share__track {
  flex: 1;
  height: 5px;
  overflow: hidden;
  background: #e8ecea;
  border-radius: 3px;
}
.share__track > span {
  display: block;
  height: 100%;
  background: var(--accent);
}
.share strong {
  color: #53605a;
  font-size: 11px;
  font-weight: 600;
}
.stage-chevron {
  color: var(--subtle);
  transition: transform 0.15s ease;
}
details[open] .stage-chevron {
  transform: rotate(180deg);
}
.task-list {
  display: grid;
  gap: 8px;
  padding: 0 14px 14px 52px;
}
.task-row {
  display: grid;
  grid-template-columns: minmax(240px, 1.3fr) minmax(320px, 1fr);
  gap: 12px 18px;
  padding: 12px 14px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid #b8c1bd;
  border-radius: 7px;
}
.task-row--running,
.task-row--claimed {
  border-left-color: var(--info);
}
.task-row--succeeded {
  border-left-color: var(--success);
}
.task-row--failed {
  border-left-color: var(--danger);
}
.task-row--skipped {
  border-left-color: var(--warning);
}
.task-main {
  display: grid;
  min-width: 0;
  align-content: start;
  gap: 5px;
}
.task-heading {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.task-heading strong {
  color: #303b36;
  font-size: 12px;
}
.task-role {
  padding: 1px 6px;
  color: var(--info);
  font-size: 10px;
  background: var(--info-soft);
  border-radius: 4px;
}
.task-main p {
  margin: 0;
  color: var(--muted);
  font-size: 11px;
  line-height: 1.5;
}
.task-main code {
  overflow: hidden;
  color: #66736d;
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-main > small {
  color: var(--subtle);
  font-size: 10px;
}
.task-facts {
  display: grid;
  grid-template-columns:
    54px minmax(96px, 1fr) minmax(104px, 1fr) 66px 66px minmax(62px, 0.8fr);
  gap: 8px;
  margin: 0;
}
.task-facts div {
  min-width: 0;
}
.task-facts dt {
  margin-bottom: 4px;
  color: var(--subtle);
  font-size: 10px;
}
.task-facts dd {
  margin: 0;
  overflow: hidden;
  color: #53605a;
  font-size: 11px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-artifacts {
  display: flex;
  flex-wrap: wrap;
  grid-column: 1 / -1;
  align-items: center;
  gap: 6px 10px;
}
.task-artifacts span {
  color: var(--subtle);
  font-size: 10px;
}
.task-artifacts a {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  color: var(--accent);
  font-size: 10px;
  text-decoration: none;
}
.task-artifacts a:hover {
  text-decoration: underline;
}
.task-error {
  display: flex;
  grid-column: 1 / -1;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 10px;
  color: var(--danger);
  background: var(--danger-soft);
  border-radius: 5px;
}
.task-error strong {
  font-size: 10px;
}
.task-error p {
  margin: 3px 0 0;
  color: #7c3d3d;
  font-size: 11px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
@media (max-width: 1100px) {
  .stage-row {
    grid-template-columns: 28px minmax(180px, 1fr) 72px 72px 72px 56px 18px;
  }
  .stage-meta--share {
    display: none;
  }
}
@media (max-width: 860px) {
  .stage-row {
    grid-template-columns: 28px minmax(160px, 1fr) 72px 72px 18px;
  }
  .stage-meta:nth-of-type(3),
  .stage-meta:nth-of-type(4) {
    display: none;
  }
  .task-row {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 620px) {
  .stage-row {
    grid-template-columns: 28px minmax(140px, 1fr) 66px 18px;
  }
  .stage-meta {
    display: none;
  }
  .task-list {
    padding-left: 14px;
  }
  .task-facts {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
