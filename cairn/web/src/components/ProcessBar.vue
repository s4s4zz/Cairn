<script setup lang="ts">
import { computed } from "vue";

import { stageState } from "@/runClock";
import { STAGES, stageIndex } from "@/stages";
import type { AuditRun, AuditTask } from "@/types/api";

const props = defineProps<{
  run: AuditRun;
  tasks: AuditTask[];
  findingCounts: Record<string, number>;
  coverageWarnings: number;
}>();

const emit = defineEmits<{ (event: "focus-gaps"): void }>();

const currentIndex = computed(() => stageIndex(props.run.current_stage));

const cursor = computed(() =>
  STAGES.map((stage, index) => ({
    key: stage.key,
    short: stage.short,
    label: stage.label,
    state: stageState(props.run, props.tasks, index),
    current: index === currentIndex.value,
  })),
);

/**
 * The funnel is `FindingStatus` in pipeline order, so candidates are seen
 * flowing rightwards while the run proceeds. `awaiting_human_review` carries
 * the strongest colour because it is the only state that needs the reader.
 */
const SEGMENTS = [
  { key: "candidate", label: "候选" },
  { key: "validating", label: "验证中" },
  { key: "machine_confirmed", label: "机器确认" },
  { key: "awaiting_human_review", label: "待人工" },
  { key: "confirmed", label: "已确认" },
  { key: "rejected", label: "已驳回" },
  { key: "accepted_risk", label: "接受风险" },
] as const;

const total = computed(() =>
  Object.values(props.findingCounts).reduce((sum, value) => sum + value, 0),
);

const segments = computed(() =>
  SEGMENTS.map((segment) => ({
    ...segment,
    value: props.findingCounts[segment.key] ?? 0,
  })).filter((segment) => segment.value > 0),
);
</script>

<template>
  <section class="process-bar">
    <div class="process-cell process-cell--stages">
      <span class="process-cell__title">阶段</span>
      <ol class="cursor">
        <li
          v-for="stage in cursor"
          :key="stage.key"
          class="cursor__item"
          :class="[`cursor__item--${stage.state}`, { 'cursor__item--current': stage.current }]"
          :title="`${stage.label}`"
        >
          <span class="cursor__dot" />
          <span class="cursor__short">{{ stage.short }}</span>
        </li>
      </ol>
    </div>

    <div class="process-cell process-cell--funnel">
      <span class="process-cell__title">漏洞流转<em>{{ total }}</em></span>
      <div v-if="total" class="funnel">
        <span
          v-for="segment in segments"
          :key="segment.key"
          class="funnel__segment"
          :class="`funnel__segment--${segment.key}`"
          :style="{ flexGrow: segment.value }"
          :title="`${segment.label} ${segment.value}`"
        />
      </div>
      <div v-else class="funnel funnel--empty"><span /></div>
      <ul v-if="total" class="legend">
        <li v-for="segment in segments" :key="segment.key" :class="`legend--${segment.key}`">
          <span class="legend__swatch" />{{ segment.label }} {{ segment.value }}
        </li>
      </ul>
      <p v-else class="legend legend--none">尚无候选</p>
    </div>

    <button
      type="button"
      class="process-cell process-cell--gaps"
      :class="{ 'process-cell--alert': coverageWarnings > 0 }"
      @click="emit('focus-gaps')"
    >
      <span class="process-cell__title">覆盖缺口</span>
      <strong>{{ coverageWarnings }}</strong>
      <small>查看未审范围</small>
    </button>
  </section>
</template>

<style scoped>
.process-bar {
  display: grid;
  grid-template-columns: minmax(280px, 1.1fr) minmax(240px, 1fr) 132px;
  gap: 1px;
  margin-top: 14px;
  background: var(--line);
  border: 1px solid var(--line);
  border-radius: 8px;
  overflow: hidden;
}
.process-cell {
  display: grid;
  align-content: start;
  gap: 8px;
  padding: 12px 14px;
  background: var(--surface);
}
.process-cell__title {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--subtle);
  font-size: 11px;
}
.process-cell__title em {
  color: var(--ink);
  font-size: 12px;
  font-style: normal;
  font-weight: 700;
}

.cursor {
  display: flex;
  align-items: flex-start;
  gap: 2px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.cursor__item {
  display: grid;
  flex: 1;
  justify-items: center;
  gap: 4px;
  min-width: 0;
}
.cursor__dot {
  width: 9px;
  height: 9px;
  background: #d7dedb;
  border-radius: 50%;
}
.cursor__short {
  color: var(--subtle);
  font-size: 10px;
}
.cursor__item--succeeded .cursor__dot {
  background: var(--success);
}
.cursor__item--running .cursor__dot {
  background: var(--info);
  animation: cursorPulse 1.6s ease-in-out infinite;
}
.cursor__item--failed .cursor__dot {
  background: var(--danger);
}
.cursor__item--partial .cursor__dot,
.cursor__item--skipped .cursor__dot {
  background: var(--warning);
}
.cursor__item--current .cursor__short {
  color: var(--ink);
  font-weight: 700;
}
@keyframes cursorPulse {
  0%,
  100% {
    box-shadow: 0 0 0 0 rgba(42, 97, 141, 0.35);
  }
  50% {
    box-shadow: 0 0 0 4px rgba(42, 97, 141, 0);
  }
}

.funnel {
  display: flex;
  height: 10px;
  gap: 1px;
  overflow: hidden;
  border-radius: 3px;
}
.funnel--empty {
  background: #eef1f0;
}
.funnel__segment {
  min-width: 3px;
}
.funnel__segment--candidate,
.legend--candidate .legend__swatch {
  background: var(--line-strong);
}
.funnel__segment--validating,
.legend--validating .legend__swatch {
  background: #6d9ab8;
}
.funnel__segment--machine_confirmed,
.legend--machine_confirmed .legend__swatch {
  background: var(--info);
}
.funnel__segment--awaiting_human_review,
.legend--awaiting_human_review .legend__swatch {
  background: var(--warning);
}
.funnel__segment--confirmed,
.legend--confirmed .legend__swatch {
  background: var(--danger);
}
.funnel__segment--rejected,
.legend--rejected .legend__swatch {
  background: #c3cbc7;
}
.funnel__segment--accepted_risk,
.legend--accepted_risk .legend__swatch {
  background: #d8bd83;
}

.legend {
  display: flex;
  flex-wrap: wrap;
  gap: 4px 12px;
  margin: 0;
  padding: 0;
  color: var(--muted);
  font-size: 11px;
  list-style: none;
}
.legend li {
  display: flex;
  align-items: center;
  gap: 5px;
}
.legend__swatch {
  width: 8px;
  height: 8px;
  border-radius: 2px;
}
.legend--none {
  color: var(--subtle);
}

.process-cell--gaps {
  align-content: start;
  font: inherit;
  text-align: left;
  border: 0;
  cursor: pointer;
}
.process-cell--gaps strong {
  color: var(--ink);
  font-size: 20px;
  line-height: 1;
}
.process-cell--gaps small {
  color: var(--subtle);
  font-size: 10px;
}
.process-cell--alert strong {
  color: var(--warning);
}

@media (max-width: 900px) {
  .process-bar {
    grid-template-columns: 1fr;
  }
}
</style>
