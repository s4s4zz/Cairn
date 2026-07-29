<script setup lang="ts">
import { AlertTriangle, CircleDot, Clock3, ServerCog } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";

import { auditRunApi, findingApi, healthApi } from "@/api/resources";
import PageHeader from "@/components/PageHeader.vue";
import SeverityChart from "@/components/SeverityChart.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import type { AuditRun, ServiceHealth } from "@/types/api";
import { errorMessage, formatDate, progressValue, shortId } from "@/utils";

const loading = ref(true);
const error = ref("");
const recentRuns = ref<AuditRun[]>([]);
const runningCount = ref(0);
const reviewCount = ref(0);
const failedCount = ref(0);
const severityCounts = ref([0, 0, 0, 0, 0]);
const health = ref<ServiceHealth | null>(null);

const warningCount = computed(() => recentRuns.value.reduce((sum, run) => sum + run.warning_count, 0));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  const severity = ["critical", "high", "medium", "low", "info"] as const;
  try {
    const [recent, review, failed, findingPages] = await Promise.all([
      auditRunApi.list({ limit: 8 }),
      auditRunApi.list({ status: "human_review", limit: 1 }),
      auditRunApi.list({ status: "failed", limit: 1 }),
      Promise.all(severity.map((value) => findingApi.list({ severity: value, limit: 1 }))),
    ]);
    recentRuns.value = recent.items;
    reviewCount.value = review.meta.total;
    failedCount.value = failed.meta.total;
    severityCounts.value = findingPages.map((page) => page.meta.total);
    runningCount.value = recent.items.filter((run) => !["created", "completed", "completed_with_warnings", "cancelled", "failed"].includes(run.status)).length;

    const healthResult = await Promise.allSettled([healthApi.ready()]);
    const available = healthResult.find((result): result is PromiseFulfilledResult<ServiceHealth> => result.status === "fulfilled");
    health.value = available?.value ?? null;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<template>
  <PageHeader title="仪表盘" description="运行状态、待处置风险与平台健康概览。" />
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <template v-else>
    <section class="metrics-grid" aria-label="关键指标">
      <article class="metric"><div class="metric__top"><span>运行中</span><CircleDot :size="17" /></div><strong class="metric__value">{{ runningCount }}</strong><span class="metric__note">当前审计流水线</span></article>
      <article class="metric"><div class="metric__top"><span>等待复核</span><Clock3 :size="17" /></div><strong class="metric__value">{{ reviewCount }}</strong><span class="metric__note">需人工处置的运行</span></article>
      <article class="metric"><div class="metric__top"><span>失败任务</span><AlertTriangle :size="17" /></div><strong class="metric__value">{{ failedCount }}</strong><span class="metric__note">需要调查或重试</span></article>
      <article class="metric"><div class="metric__top"><span>覆盖警告</span><ServerCog :size="17" /></div><strong class="metric__value">{{ warningCount }}</strong><span class="metric__note">最近 8 次审计</span></article>
    </section>

    <div class="content-grid dashboard-grid">
      <section class="panel">
        <header class="panel__header"><h2>最近审计</h2><RouterLink class="row-link" to="/audit-runs">查看全部</RouterLink></header>
        <div v-if="!recentRuns.length" class="empty-inline">暂无审计任务</div>
        <div v-else class="table-wrap table-wrap--flat">
          <table class="data-table">
            <thead><tr><th style="width: 29%">任务</th><th style="width: 23%">状态</th><th>进度</th><th style="width: 25%">创建时间</th></tr></thead>
            <tbody>
              <tr v-for="run in recentRuns" :key="run.id">
                <td><RouterLink class="row-link cell-main mono" :to="`/audit-runs/${run.id}`">{{ shortId(run.id) }}</RouterLink><span class="cell-sub">策略 v{{ run.policy_version }}</span></td>
                <td><StatusBadge :value="run.status" /></td>
                <td><div class="progress-track" :title="`${progressValue(run.progress)}%`"><span :style="{ width: `${progressValue(run.progress)}%` }" /></div></td>
                <td class="muted nowrap">{{ formatDate(run.created_at) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      <section class="panel">
        <header class="panel__header"><h2>漏洞严重性</h2><RouterLink class="row-link" to="/findings">查看漏洞</RouterLink></header>
        <div class="panel__body"><SeverityChart :values="severityCounts" /></div>
      </section>
    </div>

    <section class="panel health-panel">
      <header class="panel__header"><h2>平台健康</h2><StatusBadge :value="health?.status || 'unknown'" /></header>
      <div class="health-grid">
        <div><span>API / 数据库</span><StatusBadge :value="health?.database === 'reachable' || health?.status === 'ready' ? 'ready' : health?.status || 'unknown'" /></div>
        <div v-for="name in ['workers', 'scanners', 'llm_gateway', 'sandbox_manager']" :key="name"><span>{{ { workers: 'Workers', scanners: '扫描器', llm_gateway: 'LLM Gateway', sandbox_manager: 'Sandbox Manager' }[name] }}</span><StatusBadge :value="health?.services?.[name]?.status || 'unknown'" /></div>
      </div>
    </section>
  </template>
</template>

<style scoped>
.dashboard-grid { margin-top: 14px; }
.table-wrap--flat { border: 0; border-radius: 0; }
.health-panel { margin-top: 14px; }
.health-grid { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); }
.health-grid > div { display: flex; min-height: 60px; align-items: center; justify-content: space-between; gap: 8px; padding: 12px 15px; border-right: 1px solid var(--line); }
.health-grid > div:last-child { border-right: 0; }
.health-grid span:first-child { color: #58655f; font-size: 11px; overflow-wrap: anywhere; }
@media (max-width: 1100px) { .health-grid { grid-template-columns: repeat(3, 1fr); } .health-grid > div:nth-child(3) { border-right: 0; } }
@media (max-width: 620px) { .health-grid { grid-template-columns: 1fr; } .health-grid > div { border-right: 0; border-bottom: 1px solid var(--line); } .health-grid > div:last-child { border-bottom: 0; } }
</style>
