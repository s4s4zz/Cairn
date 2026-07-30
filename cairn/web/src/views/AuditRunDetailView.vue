<script setup lang="ts">
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  Download,
  FileText,
  RefreshCw,
  Trash2,
} from "@lucide/vue";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { auditRunApi, reportApi } from "@/api/resources";
import GapList from "@/components/GapList.vue";
import ProcessBar from "@/components/ProcessBar.vue";
import RunEventLog from "@/components/RunEventLog.vue";
import RunNarrative from "@/components/RunNarrative.vue";
import RunWaterfall from "@/components/RunWaterfall.vue";
import StageTimeline from "@/components/StageTimeline.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuditRunEvents } from "@/composables/useAuditRunEvents";
import { useRunNarrative } from "@/composables/useRunNarrative";
import { buildStatusDisplay, collectGaps, coverageMetrics } from "@/coverage";
import { buildRunSummary } from "@/runSummary";
import { STAGES } from "@/stages";
import { useAuthStore } from "@/stores/auth";
import type {
  AuditCoverage,
  AuditRun,
  AuditRunEventSnapshot,
  AuditRunStageEvent,
  AuditTask,
  Report,
} from "@/types/api";
import { duration, errorMessage, formatDate, progressValue, shortId } from "@/utils";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const id = String(route.params.id);
const run = ref<AuditRun | null>(null);
const tasks = ref<AuditTask[]>([]);
const taskPageTotal = ref(0);
const taskPageLimit = ref(0);
const coverage = ref<AuditCoverage | null>(null);
const stageEvents = ref<AuditRunStageEvent[]>([]);
const taskCounts = ref<Record<string, number>>({});
const findingCounts = ref<Record<string, number>>({});
const coverageWarningCount = ref(0);
const report = ref<Report | null>(null);
const loading = ref(true);
const error = ref("");
const acting = ref(false);
const gapsSection = ref<HTMLElement | null>(null);
let pollTimer: number | null = null;
let taskRefreshPromise: Promise<void> | null = null;
let taskRefreshRequested = false;

const { events, record: recordSnapshot } = useRunNarrative();

const canManage = computed(() => auth.can(["admin", "auditor"]));
const canDelete = computed(() =>
  auth.can(["admin"]) &&
  Boolean(
    run.value &&
      [
        "human_review",
        "completed",
        "completed_with_warnings",
        "cancelled",
        "failed",
      ].includes(run.value.status),
  ),
);
const canGenerate = computed(() => canManage.value && run.value?.status === "human_review");
const isTerminal = computed(() => run.value ? ["completed", "completed_with_warnings", "cancelled", "failed"].includes(run.value.status) : false);
const hasReport = computed(() => Boolean(report.value) || (run.value ? ["completed", "completed_with_warnings"].includes(run.value.status) : false));

// `task_counts` already groups every task of the run server-side, so it is the
// authoritative total; the loaded list is only a page and is the fallback until
// the first SSE snapshot arrives.
const taskTotal = computed(() => {
  const counted = Object.values(taskCounts.value).reduce((sum, count) => sum + count, 0);
  return counted || tasks.value.length;
});
const tasksTruncated = computed(
  () => taskPageLimit.value > 0 && taskPageTotal.value > tasks.value.length,
);

const toolCoverage = computed(() => coverage.value?.static_tools_completed ?? null);
const metrics = computed(() =>
  run.value && coverage.value ? coverageMetrics(run.value, coverage.value) : [],
);
const buildStatus = computed(() =>
  run.value && coverage.value ? buildStatusDisplay(run.value, coverage.value) : null,
);
const gaps = computed(() =>
  coverage.value ? collectGaps(coverage.value, tasks.value) : [],
);
const summaryClauses = computed(() =>
  run.value
    ? buildRunSummary({
        run: run.value,
        tasks: tasks.value,
        coverage: coverage.value,
        findingCounts: findingCounts.value,
      })
    : [],
);

function applyEvent(event: AuditRunEventSnapshot): void {
  if (run.value && event.audit_run_id === run.value.id) {
    run.value = {
      ...run.value,
      status: event.status,
      current_stage: event.current_stage,
      progress: event.progress,
      warning_count: event.warning_count,
      failure_code: event.failure_code,
      failure_reason: event.failure_reason,
      completed_at: event.completed_at,
    };
  }
  taskCounts.value = event.task_counts;
  // The stream already carries what the run has found and how much of the
  // repository it had to leave out; discarding either left the page unable to
  // answer the two questions a reader actually has.
  findingCounts.value = event.finding_counts ?? {};
  coverageWarningCount.value = event.coverage_warning_count ?? 0;
  recordSnapshot(event);
  void refreshTasks().catch((reason) => { error.value = errorMessage(reason); });
  if (["completed", "completed_with_warnings", "cancelled", "failed"].includes(event.status)) disconnectStream();
}

const { state: streamState, connect: connectStream, disconnect: disconnectStream } = useAuditRunEvents(id, applyEvent);

function refreshTasks(): Promise<void> {
  taskRefreshRequested = true;
  if (!taskRefreshPromise) {
    taskRefreshPromise = (async () => {
      while (taskRefreshRequested) {
        taskRefreshRequested = false;
        const page = await auditRunApi.tasks(id);
        tasks.value = page.items;
        taskPageTotal.value = page.meta.total;
        taskPageLimit.value = page.meta.limit;
      }
    })().finally(() => { taskRefreshPromise = null; });
  }
  return taskRefreshPromise;
}

async function load(options: { quiet?: boolean } = {}): Promise<void> {
  if (!options.quiet) loading.value = true;
  error.value = "";
  try {
    const [nextRun, , coverageResult, reportPage] = await Promise.all([
      auditRunApi.get(id),
      refreshTasks(),
      auditRunApi.coverage(id).then(
        (value) => ({ status: "fulfilled", value }) as const,
        () => ({ status: "rejected" }) as const,
      ),
      reportApi.list({ audit_run_id: id, limit: 1 }),
      auditRunApi
        .stages(id)
        .then((value) => { stageEvents.value = value; })
        .catch(() => { /* Stage records are additive; the waterfall still has task timing. */ }),
    ]);
    run.value = nextRun;
    report.value = reportPage.items[0] ?? null;
    if (coverageResult.status === "fulfilled") {
      coverage.value = coverageResult.value;
      if (!coverageWarningCount.value) {
        coverageWarningCount.value = coverageResult.value.coverage_warnings.length;
      }
    }
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

async function cancel(): Promise<void> {
  acting.value = true;
  try { run.value = await auditRunApi.cancel(id); } catch (reason) { error.value = errorMessage(reason); } finally { acting.value = false; }
}

async function retry(): Promise<void> {
  acting.value = true;
  try { const next = await auditRunApi.retry(id); await router.push(`/audit-runs/${next.id}`); } catch (reason) { error.value = errorMessage(reason); } finally { acting.value = false; }
}

async function remove(): Promise<void> {
  if (
    !window.confirm(
      `确认删除审计 ${shortId(id)}？\n\n该操作会删除本次运行的任务、漏洞、证据和报告，无法恢复；固定 Snapshot 会保留。`,
    )
  ) {
    return;
  }
  acting.value = true;
  error.value = "";
  try {
    disconnectStream();
    await auditRunApi.remove(id);
    await router.push("/audit-runs");
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    acting.value = false;
  }
}

async function generateReport(): Promise<void> {
  acting.value = true;
  error.value = "";
  try {
    report.value = await reportApi.generate(id);
    const [nextRun, reportPage] = await Promise.all([
      auditRunApi.get(id),
      reportApi.list({ audit_run_id: id, limit: 1 }),
      refreshTasks(),
    ]);
    run.value = nextRun;
    report.value = reportPage.items[0] ?? report.value;
    disconnectStream();
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    acting.value = false;
  }
}

function focusGaps(): void {
  gapsSection.value?.scrollIntoView({ behavior: "smooth", block: "start" });
}

function stageLabel(key: string): string {
  return STAGES.find((stage) => stage.key === key)?.label ?? key;
}

onMounted(async () => {
  await load();
  connectStream();
  pollTimer = window.setInterval(() => { if (!isTerminal.value) void load({ quiet: true }); }, 30000);
});
onBeforeUnmount(() => { if (pollTimer) window.clearInterval(pollTimer); });
</script>

<template>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error && !run" kind="error" :message="error" retryable @retry="load" />
  <template v-else-if="run">
    <RouterLink class="back-link" to="/audit-runs"><ArrowLeft :size="15" />返回审计任务</RouterLink>
    <header class="run-header">
      <div>
        <div class="run-title"><h1>审计 {{ shortId(run.id) }}</h1><StatusBadge :value="run.status" /></div>
        <p class="mono">{{ run.id }}</p>
        <RunNarrative
          :run="run"
          :tasks="tasks"
          :finding-counts="findingCounts"
          :coverage-warnings="coverageWarningCount"
        />
      </div>
      <div class="run-actions">
        <RouterLink class="button button--secondary" :to="{ path: '/findings', query: { audit_run_id: run.id } }">查看漏洞</RouterLink>
        <button v-if="canGenerate" class="button" type="button" :disabled="acting" @click="generateReport"><FileText :size="15" />生成报告并完成</button>
        <RouterLink v-if="hasReport" class="button button--secondary" :to="{ path: '/reports', query: { audit_run_id: run.id } }"><FileText :size="15" />报告</RouterLink>
        <button v-if="canManage && !isTerminal" class="button button--danger" type="button" :disabled="acting" @click="cancel"><Ban :size="15" />取消</button>
        <button v-if="canManage && ['failed','cancelled'].includes(run.status)" class="button" type="button" :disabled="acting" @click="retry"><RefreshCw :size="15" />重试</button>
        <button v-if="canDelete" class="button button--danger" type="button" :disabled="acting" @click="remove"><Trash2 :size="15" />删除</button>
      </div>
    </header>

    <div v-if="error" class="inline-error run-error">{{ error }}</div>
    <div v-if="report" class="notice notice--success report-ready"><FileText :size="17" /><strong>报告 v{{ report.version }}</strong><a :href="reportApi.downloadUrl(report.id, 'html')" target="_blank">HTML</a><a :href="reportApi.downloadUrl(report.id, 'json')">JSON</a><a :href="reportApi.downloadUrl(report.id, 'sarif')"><Download :size="13" />SARIF</a></div>
    <section v-if="run.failure_reason" class="notice notice--danger"><AlertTriangle :size="17" /><div><strong>{{ run.failure_code || "审计失败" }}</strong><br />{{ run.failure_reason }}</div></section>

    <ProcessBar
      :run="run"
      :tasks="tasks"
      :finding-counts="findingCounts"
      :coverage-warnings="coverageWarningCount"
      @focus-gaps="focusGaps"
    />

    <dl class="detail-grid run-summary">
      <div class="detail-item"><dt>当前阶段</dt><dd><StatusBadge :value="run.current_stage || 'created'" /></dd></div>
      <div class="detail-item"><dt>总体进度</dt><dd class="progress-cell"><div class="progress-track"><span :style="{ width: `${progressValue(run.progress)}%` }" /></div>{{ progressValue(run.progress).toFixed(0) }}%</dd></div>
      <div class="detail-item"><dt>策略版本</dt><dd>v{{ run.policy_version }}</dd></div>
      <div class="detail-item"><dt>运行时长</dt><dd>{{ duration(run.started_at, run.completed_at) }}</dd></div>
      <div class="detail-item"><dt>开始时间</dt><dd>{{ formatDate(run.started_at || run.created_at) }}</dd></div>
    </dl>

    <section v-if="summaryClauses.length" class="run-digest">
      <h2>本次运行摘要</h2>
      <p>{{ summaryClauses.join("；") }}。</p>
    </section>

    <div class="run-body">
      <div class="run-main">
        <RunWaterfall
          :run="run"
          :tasks="tasks"
          :tool-coverage="toolCoverage"
          :stage-events="stageEvents"
        />

        <div class="section-title"><h2>审计阶段</h2><p>{{ taskTotal }} 个任务 · {{ run.warning_count }} 条警告</p></div>
        <div v-if="tasksTruncated" class="notice notice--warning task-truncated">
          <AlertTriangle :size="15" />
          <span>本次运行共 {{ taskPageTotal }} 个任务，页面仅加载了前 {{ tasks.length }} 个，下方列表不完整。</span>
        </div>
        <section class="panel"><StageTimeline
            :run="run"
            :tasks="tasks"
            :tool-coverage="toolCoverage"
            :stage-events="stageEvents"
          /></section>

        <div class="section-title">
          <h2>覆盖与缺口</h2>
          <p>左侧是已列出范围的完成度，不是召回率；右侧是本次运行明确没有覆盖的部分。</p>
        </div>
        <StatePanel
          v-if="!coverage"
          kind="empty"
          title="Coverage 尚未生成"
          message="项目盘点开始后将在此显示。"
        />
        <div v-else ref="gapsSection" class="coverage-contrast">
          <article class="coverage-side">
            <h3>已列出范围</h3>
            <ul class="metric-list">
              <li v-for="metric in metrics" :key="metric.key">
                <div class="metric-head">
                  <span>{{ metric.label }}</span>
                  <strong v-if="metric.state === 'ready'">{{ metric.value }} / {{ metric.total }}</strong>
                  <strong v-else class="metric-head__pending">
                    待统计<em v-if="metric.total"> · 共 {{ metric.total }}</em>
                  </strong>
                </div>
                <div class="progress-track">
                  <span :style="{ width: `${metric.state === 'ready' ? metric.ratio : 0}%` }" />
                </div>
                <small v-if="metric.state === 'ready'">{{ metric.ratio }}%</small>
                <small v-else class="muted">{{ stageLabel(metric.producedBy) }}完成后给出</small>
              </li>
            </ul>
            <div class="build-row">
              <span>构建状态</span>
              <span class="badge" :class="`badge--${buildStatus?.tone}`">{{ buildStatus?.label }}</span>
              <small v-if="!buildStatus?.known">该字段在构建阶段完成前不可用</small>
            </div>
            <p class="metric-note">
              分母是平台已经识别出的入口与 Sink 数量，不是仓库中真实存在的总数。
            </p>
          </article>

          <article class="coverage-side">
            <h3>未审范围<em>{{ gaps.length }}</em></h3>
            <GapList :gaps="gaps" />
            <p v-if="coverage" class="metric-note">更新时间 {{ formatDate(coverage.updated_at) }}</p>
          </article>
        </div>
      </div>

      <aside class="run-aside">
        <RunEventLog :events="events" :stream-state="streamState" />
      </aside>
    </div>
  </template>
</template>

<style scoped>
.back-link { display: inline-flex; align-items: center; gap: 5px; margin-bottom: 12px; color: var(--muted); font-size: 11px; text-decoration: none; }
.run-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 16px; }
.run-title { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.run-title h1 { margin: 0; font-size: 23px; }
.run-header p.mono { margin: 6px 0 0; color: var(--muted); overflow-wrap: anywhere; }
.run-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
.run-error { margin-bottom: 12px; }
.report-ready { margin-bottom: 12px; }
.report-ready a { display: inline-flex; align-items: center; gap: 4px; color: var(--success); font-size: 10px; font-weight: 700; }
.run-summary { margin-top: 14px; }
.run-digest { margin-top: 14px; padding: 14px 16px; background: var(--surface); border: 1px solid var(--line); border-left: 3px solid var(--accent); border-radius: 8px; }
.run-digest h2 { margin: 0 0 7px; font-size: 12px; }
.run-digest p { margin: 0; color: #4a564f; font-size: 12px; line-height: 1.75; overflow-wrap: anywhere; }
.progress-cell { display: flex; align-items: center; gap: 8px; }
.progress-cell .progress-track { max-width: 130px; }

.run-body { display: grid; grid-template-columns: minmax(0, 1fr) 300px; gap: 14px; align-items: start; margin-top: 16px; }.run-main { display: grid; min-width: 0; gap: 0; }
.run-aside { position: sticky; top: 14px; }
.task-truncated { margin-bottom: 10px; }

.coverage-contrast { display: grid; grid-template-columns: minmax(260px, 0.9fr) minmax(0, 1.1fr); gap: 12px; align-items: start; }
.coverage-side { min-width: 0; padding: 14px 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 8px; }
.coverage-side > h3 { display: flex; align-items: center; gap: 8px; margin: 0 0 12px; font-size: 12px; }
.coverage-side > h3 em { color: var(--warning); font-size: 13px; font-style: normal; font-weight: 700; }
.metric-list { display: grid; gap: 12px; margin: 0; padding: 0; list-style: none; }
.metric-list li { display: grid; gap: 5px; }
.metric-head { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; font-size: 12px; }
.metric-head span { color: var(--muted); }
.metric-head strong { color: var(--ink); font-size: 12px; }
.metric-head__pending { color: var(--subtle); font-weight: 600; }
.metric-head__pending em { font-style: normal; }
.metric-list small { color: var(--muted); font-size: 10px; }
.metric-list small.muted { color: var(--subtle); }
.build-row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin-top: 14px; padding-top: 12px; font-size: 12px; color: var(--muted); border-top: 1px solid var(--line); }
.build-row small { color: var(--subtle); font-size: 10px; }
.metric-note { margin: 12px 0 0; color: var(--subtle); font-size: 10px; line-height: 1.6; }

@media (max-width: 1180px) {
  .run-body { grid-template-columns: 1fr; }
  .run-aside { position: static; }
}
@media (max-width: 900px) { .coverage-contrast { grid-template-columns: 1fr; } }
@media (max-width: 620px) { .run-header { display: grid; } .run-actions { justify-content: flex-start; } .run-actions .button { flex: 1; } }
</style>
