<script setup lang="ts">
import type { FindingSeverity } from "@/types/api";

defineProps<{ value: FindingSeverity }>();

const labels: Record<FindingSeverity, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
};
</script>

<template>
  <span class="severity" :class="`severity--${value}`"><i aria-hidden="true" />{{ labels[value] }}</span>
</template>
