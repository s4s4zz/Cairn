<script setup lang="ts">
import { AlertTriangle, MinusCircle, XCircle } from "@lucide/vue";

import type { CoverageGap } from "@/coverage";

defineProps<{ gaps: CoverageGap[] }>();
</script>

<template>
  <div v-if="!gaps.length" class="gap-empty">
    本次运行没有记录到未覆盖范围。
  </div>
  <ul v-else class="gap-list">
    <li v-for="gap in gaps" :key="gap.key" class="gap" :class="`gap--${gap.tone}`">
      <span class="gap__glyph">
        <XCircle v-if="gap.tone === 'failed'" :size="15" />
        <MinusCircle v-else-if="gap.tone === 'skipped'" :size="15" />
        <AlertTriangle v-else :size="15" />
      </span>
      <div class="gap__body">
        <div class="gap__head">
          <strong>{{ gap.title }}</strong>
          <code v-if="gap.code">{{ gap.code }}</code>
        </div>
        <p v-if="gap.detail">{{ gap.detail }}</p>
      </div>
      <span v-if="gap.stageLabel" class="gap__stage">→ {{ gap.stageLabel }}</span>
    </li>
  </ul>
</template>

<style scoped>
.gap-empty {
  padding: 18px 16px;
  color: var(--muted);
  font-size: 12px;
  background: var(--surface);
  border: 1px dashed var(--line-strong);
  border-radius: 7px;
}
.gap-list {
  display: grid;
  gap: 8px;
  margin: 0;
  padding: 0;
  list-style: none;
}
.gap {
  display: grid;
  grid-template-columns: 20px minmax(0, 1fr) auto;
  align-items: start;
  gap: 4px 10px;
  padding: 11px 13px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid var(--warning);
  border-radius: 7px;
}
/* A skipped tool is a coverage gap, so it never reads as neutral grey. */
.gap--skipped {
  border-left-color: var(--warning);
}
.gap--failed {
  border-left-color: var(--danger);
}
.gap__glyph {
  display: flex;
  padding-top: 1px;
  color: var(--warning);
}
.gap--failed .gap__glyph {
  color: var(--danger);
}
.gap__body {
  display: grid;
  min-width: 0;
  gap: 4px;
}
.gap__head {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.gap__head strong {
  color: var(--ink);
  font-size: 12px;
}
.gap__head code {
  color: var(--muted);
  font-size: 10px;
  overflow-wrap: anywhere;
}
.gap__body p {
  margin: 0;
  color: var(--muted);
  font-size: 11px;
  line-height: 1.5;
  overflow-wrap: anywhere;
}
.gap__stage {
  color: var(--subtle);
  font-size: 10px;
  white-space: nowrap;
}
@media (max-width: 620px) {
  .gap {
    grid-template-columns: 20px minmax(0, 1fr);
  }
  .gap__stage {
    grid-column: 2;
  }
}
</style>
