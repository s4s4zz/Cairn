<script setup lang="ts">
import { Info, Radio } from "@lucide/vue";
import { ref } from "vue";

import type { RunEvent } from "@/composables/useRunNarrative";

defineProps<{
  events: RunEvent[];
  streamState: "idle" | "connecting" | "connected" | "disconnected";
}>();

const showNote = ref(false);

const stateLabels: Record<string, string> = {
  idle: "未连接",
  connecting: "连接中",
  connected: "实时",
  disconnected: "已断开，轮询兜底",
};

const TIME_FORMAT = new Intl.DateTimeFormat("zh-CN", {
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hour12: false,
});

function clock(value: string): string {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "--:--:--" : TIME_FORMAT.format(parsed);
}
</script>

<template>
  <section class="event-log">
    <header class="event-log__head">
      <h3>运行事件</h3>
      <span class="event-log__state" :class="`event-log__state--${streamState}`">
        <Radio :size="12" />{{ stateLabels[streamState] }}
      </span>
      <button type="button" class="event-log__info" @click="showNote = !showNote">
        <Info :size="13" />
      </button>
    </header>

    <p v-if="showNote" class="event-log__note">
      本面板由 SSE 快照差分重建，不是权威事件记录：两次快照之间的多个变化会合并
      为一条净变化，时间为浏览器观察到的时刻。完整的操作记录见审计日志。
    </p>

    <ol v-if="events.length" class="event-log__list">
      <li v-for="event in events" :key="event.id" :class="`event--${event.tone}`">
        <time>{{ clock(event.at) }}</time>
        <span>{{ event.text }}</span>
      </li>
    </ol>
    <p v-else class="event-log__empty">
      自本页打开以来还没有观察到变化。更早发生的事件不会出现在这里。
    </p>
  </section>
</template>

<style scoped>
.event-log {
  display: grid;
  align-content: start;
  gap: 10px;
  padding: 14px 15px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-radius: 8px;
}
.event-log__head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.event-log__head h3 {
  flex: 1;
  margin: 0;
  font-size: 12px;
}
.event-log__state {
  display: flex;
  align-items: center;
  gap: 4px;
  color: var(--muted);
  font-size: 10px;
}
.event-log__state--connected {
  color: var(--success);
}
.event-log__state--disconnected {
  color: var(--warning);
}
.event-log__info {
  display: flex;
  padding: 2px;
  color: var(--subtle);
  background: none;
  border: 0;
  cursor: pointer;
}
.event-log__note {
  margin: 0;
  padding: 9px 10px;
  color: var(--muted);
  font-size: 10px;
  line-height: 1.6;
  background: var(--surface-alt);
  border-radius: 6px;
}
.event-log__list {
  display: grid;
  gap: 1px;
  max-height: 420px;
  margin: 0;
  padding: 0;
  overflow-y: auto;
  list-style: none;
}
.event-log__list li {
  display: grid;
  grid-template-columns: 62px minmax(0, 1fr);
  gap: 8px;
  padding: 6px 7px;
  border-radius: 4px;
}
.event-log__list time {
  color: var(--subtle);
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}
.event-log__list span {
  color: #53605a;
  font-size: 11px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
.event--success span {
  color: var(--success);
}
.event--warning {
  background: var(--warning-soft);
}
.event--warning span {
  color: var(--warning);
}
.event--danger {
  background: var(--danger-soft);
}
.event--danger span {
  color: var(--danger);
}
.event--info span {
  color: var(--info);
}
.event-log__empty {
  margin: 0;
  color: var(--subtle);
  font-size: 11px;
  line-height: 1.6;
}
</style>
