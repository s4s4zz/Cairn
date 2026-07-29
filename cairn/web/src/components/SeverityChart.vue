<script setup lang="ts">
import { BarChart } from "echarts/charts";
import { GridComponent, TooltipComponent } from "echarts/components";
import { init, use, type ECharts } from "echarts/core";
import { CanvasRenderer } from "echarts/renderers";
import { nextTick, onBeforeUnmount, onMounted, ref, watch } from "vue";

use([BarChart, GridComponent, TooltipComponent, CanvasRenderer]);

const props = defineProps<{ values: number[] }>();
const container = ref<HTMLDivElement | null>(null);
let chart: ECharts | null = null;
let observer: ResizeObserver | null = null;

function render(): void {
  if (!container.value) return;
  chart ||= init(container.value, undefined, { renderer: "canvas" });
  chart.setOption({
    animationDuration: 250,
    grid: { left: 6, right: 16, top: 8, bottom: 4, containLabel: true },
    tooltip: { trigger: "axis", axisPointer: { type: "shadow" } },
    xAxis: { type: "value", minInterval: 1, axisLine: { show: false }, splitLine: { lineStyle: { color: "#edf0ef" } } },
    yAxis: {
      type: "category",
      data: ["严重", "高危", "中危", "低危", "提示"],
      axisTick: { show: false },
      axisLine: { show: false },
      axisLabel: { color: "#64716b", fontSize: 10 },
    },
    series: [
      {
        type: "bar",
        data: props.values.map((value, index) => ({ value, itemStyle: { color: ["#a62e35", "#b05424", "#967019", "#2f6e91", "#77827d"][index] } })),
        barWidth: 13,
        itemStyle: { borderRadius: 2 },
        label: { show: true, position: "right", color: "#59655f", fontSize: 10 },
      },
    ],
  });
}

watch(() => props.values, () => void nextTick(render), { deep: true });
onMounted(() => {
  render();
  if (container.value && "ResizeObserver" in window) {
    observer = new ResizeObserver(() => chart?.resize());
    observer.observe(container.value);
  }
});
onBeforeUnmount(() => {
  observer?.disconnect();
  chart?.dispose();
});
</script>

<template><div ref="container" class="severity-chart" role="img" aria-label="漏洞严重性分布图" /></template>

<style scoped>
.severity-chart { width: 100%; height: 218px; }
</style>
