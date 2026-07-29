<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref, watch } from "vue";

import { buildRunClock, type ClockBar } from "@/runClock";
import { isTerminal } from "@/stages";
import { compactDuration } from "@/taskLabels";
import type { AuditRun, AuditTask, ToolCoverageRecord } from "@/types/api";

const props = defineProps<{
  run: AuditRun;
  tasks: AuditTask[];
  toolCoverage?: Record<string, ToolCoverageRecord> | null;
}>();

const emit = defineEmits<{ (event: "select", taskId: string): void }>();

// A running bar has to keep growing, so the clock ticks while the run is live
// and stops the moment it settles.
const now = ref(Date.now());
let timer: number | null = null;

function stopTimer(): void {
  if (timer !== null) {
    window.clearInterval(timer);
    timer = null;
  }
}

function syncTimer(): void {
  stopTimer();
  if (isTerminal(props.run)) return;
  timer = window.setInterval(() => {
    now.value = Date.now();
  }, 1000);
}

onMounted(syncTimer);
onBeforeUnmount(stopTimer);
watch(() => props.run.status, syncTimer);

const clock = computed(() =>
  buildRunClock({
    run: props.run,
    tasks: props.tasks,
    toolCoverage: props.toolCoverage,
    nowMs: now.value,
    formatDuration: compactDuration,
  }),
);

function barStyle(bar: ClockBar): Record<string, string> {
  if (bar.offset === null) return { display: "none" };
  const width = bar.extent === null ? 0 : bar.extent * 100;
  return {
    left: `${bar.offset * 100}%`,
    width: `max(3px, ${width}%)`,
  };
}

function meta(bar: ClockBar): string {
  if (bar.durationMs !== null) return compactDuration(bar.durationMs);
  if (bar.status === "skipped") return "跳过";
  if (bar.status === "failed") return "失败";
  if (bar.status === "pending") return "等待";
  return "-";
}

const rows = computed(() => clock.value.bars);
</script>

<template>
  <section class="waterfall">
    <header class="waterfall__head">
      <h3>时间去向</h3>
      <span v-if="clock.totalMs">总计 {{ compactDuration(clock.totalMs) }}</span>
      <span v-else class="muted">尚无计时数据</span>
    </header>

    <div v-if="!clock.hasTiming" class="waterfall__empty">
      任务尚未开始执行，时间轴将在第一个任务启动后出现。
    </div>

    <template v-else>
      <div class="axis">
        <span
          v-for="tick in clock.ticks"
          :key="tick.offset"
          class="axis__tick"
          :style="{ left: `${tick.offset * 100}%` }"
        >
          {{ tick.label }}
        </span>
      </div>

      <ol class="rows">
        <li
          v-for="bar in rows"
          :key="bar.key"
          class="row"
          :class="[`row--${bar.kind}`, `row--${bar.status}`]"
        >
          <span class="row__label" :title="bar.label">{{ bar.label }}</span>
          <button
            type="button"
            class="row__track"
            :disabled="!bar.taskId"
            @click="bar.taskId && emit('select', bar.taskId)"
          >
            <span class="row__grid" />
            <span
              v-if="bar.offset !== null"
              class="row__bar"
              :style="barStyle(bar)"
              :title="`${bar.label} · ${meta(bar)}`"
            />
          </button>
          <span class="row__meta">
            <strong>{{ meta(bar) }}</strong>
            <small v-if="bar.candidateCount !== null" class="row__candidates">
              {{ bar.candidateCount }} 候选
            </small>
            <small v-if="bar.note" class="row__note">{{ bar.note }}</small>
            <small v-if="bar.timeoutHeadroomSeconds !== null" class="row__timeout">
              距超时 {{ compactDuration(bar.timeoutHeadroomSeconds * 1000) }}
            </small>
          </span>
        </li>
      </ol>
    </template>
  </section>
</template>

<style scoped>
.waterfall {
  padding: 14px 16px 16px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.waterfall__head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 12px;
}
.waterfall__head h3 {
  margin: 0;
  font-size: 12px;
}
.waterfall__head span {
  color: var(--muted);
  font-size: 11px;
}
.waterfall__empty {
  padding: 16px 0 4px;
  color: var(--muted);
  font-size: 12px;
}

.axis {
  position: relative;
  height: 16px;
  margin-left: 152px;
  margin-right: 118px;
  border-bottom: 1px solid var(--line);
}
.axis__tick {
  position: absolute;
  top: 0;
  color: var(--subtle);
  font-size: 10px;
  transform: translateX(-50%);
  white-space: nowrap;
}

.rows {
  display: grid;
  gap: 2px;
  margin: 6px 0 0;
  padding: 0;
  list-style: none;
}
.row {
  display: grid;
  grid-template-columns: 140px minmax(0, 1fr) 106px;
  align-items: center;
  gap: 12px;
  min-height: 24px;
}
.row__label {
  overflow: hidden;
  color: var(--muted);
  font-size: 11px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.row--stage .row__label {
  color: var(--ink);
  font-weight: 700;
}
.row--task .row__label {
  padding-left: 12px;
}
.row__track {
  position: relative;
  height: 14px;
  padding: 0;
  background: none;
  border: 0;
  border-radius: 3px;
}
.row__track:not(:disabled) {
  cursor: pointer;
}
.row__grid {
  position: absolute;
  inset: 5px 0;
  background: #f1f4f3;
  border-radius: 2px;
}
.row__bar {
  position: absolute;
  top: 3px;
  height: 8px;
  background: var(--line-strong);
  border-radius: 2px;
}
.row--stage .row__bar {
  top: 2px;
  height: 10px;
}
.row--succeeded .row__bar {
  background: var(--success);
}
.row--running .row__bar {
  background: var(--info);
  animation: barPulse 1.6s ease-in-out infinite;
}
.row--failed .row__bar {
  background: var(--danger);
}
.row--partial .row__bar,
.row--skipped .row__bar {
  background: var(--warning);
}
.row--cancelled .row__bar {
  background: #c3cbc7;
}
@keyframes barPulse {
  0%,
  100% {
    opacity: 1;
  }
  50% {
    opacity: 0.55;
  }
}

.row__meta {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 3px 6px;
  min-width: 0;
}
.row__meta strong {
  color: #53605a;
  font-size: 11px;
  font-weight: 600;
}
.row--skipped .row__meta strong,
.row--partial .row__meta strong {
  color: var(--warning);
}
.row--failed .row__meta strong {
  color: var(--danger);
}
.row__candidates {
  color: var(--muted);
  font-size: 10px;
}
.row__note {
  color: var(--warning);
  font-size: 10px;
}
.row__timeout {
  color: var(--danger);
  font-size: 10px;
}

@media (max-width: 760px) {
  .axis {
    margin-left: 92px;
    margin-right: 84px;
  }
  .row {
    grid-template-columns: 84px minmax(0, 1fr) 76px;
    gap: 8px;
  }
}
</style>
