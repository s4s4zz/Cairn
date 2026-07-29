<script setup lang="ts">
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  Download,
  FileText,
  Radio,
  RefreshCw,
  Trash2,
} from "@lucide/vue";
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { auditRunApi, reportApi } from "@/api/resources";
import StageTimeline from "@/components/StageTimeline.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuditRunEvents } from "@/composables/useAuditRunEvents";
import { useAuthStore } from "@/stores/auth";
import type { AuditCoverage, AuditRun, AuditRunEventSnapshot, AuditTask, Report } from "@/types/api";
import { duration, errorMessage, formatDate, progressValue, shortId } from "@/utils";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const id = String(route.params.id);
const run = ref<AuditRun | null>(null);
const tasks = ref<AuditTask[]>([]);
const coverage = ref<AuditCoverage | null>(null);
const warnings = ref<Array<{ code?: string; message: string }>>([]);
const taskCounts = ref<Record<string, number>>({});
const report = ref<Report | null>(null);
const loading = ref(true);
const error = ref("");
const acting = ref(false);
let pollTimer: number | null = null;
let taskRefreshPromise: Promise<void> | null = null;
let taskRefreshRequested = false;

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
const coverageItems = computed(() => coverage.value ? [
  { label: "模块", value: coverage.value.modules_analyzed, total: coverage.value.modules_total },
  { label: "Java 文件", value: coverage.value.java_files_analyzed, total: coverage.value.java_files_total },
  { label: "入口点", value: coverage.value.entrypoints_analyzed, total: coverage.value.entrypoints_total },
  { label: "敏感 Sink", value: coverage.value.sensitive_sinks_analyzed, total: coverage.value.sensitive_sinks_total },
] : []);

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
  void refreshTasks().catch((reason) => { error.value = errorMessage(reason); });
  if (["completed", "completed_with_warnings", "cancelled", "failed"].includes(event.status)) disconnectStream();
}

const { state: streamState, connect: connectStream, disconnect: disconnectStream } = useAuditRunEvents(id, applyEvent);

function coverageWarning(item: Record<string, unknown>): { code?: string; message: string } {
  const code = typeof item.code === "string" ? item.code : typeof item.reason_code === "string" ? item.reason_code : undefined;
  const message = typeof item.message === "string" ? item.message : typeof item.detail === "string" ? item.detail : JSON.stringify(item);
  return { code, message };
}

function refreshTasks(): Promise<void> {
  taskRefreshRequested = true;
  if (!taskRefreshPromise) {
    taskRefreshPromise = (async () => {
      while (taskRefreshRequested) {
        taskRefreshRequested = false;
        const page = await auditRunApi.tasks(id);
        tasks.value = page.items;
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
    ]);
    run.value = nextRun;
    report.value = reportPage.items[0] ?? null;
    if (coverageResult.status === "fulfilled") {
      coverage.value = coverageResult.value;
      warnings.value = coverageResult.value.coverage_warnings.map(coverageWarning);
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

function ratio(value: number, total: number): number { return total ? Math.round((value / total) * 100) : 0; }

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
      <div><div class="run-title"><h1>审计 {{ shortId(run.id) }}</h1><StatusBadge :value="run.status" /></div><p class="mono">{{ run.id }}</p></div>
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

    <dl class="detail-grid run-summary">
      <div class="detail-item"><dt>当前阶段</dt><dd><StatusBadge :value="run.current_stage || 'created'" /></dd></div>
      <div class="detail-item"><dt>总体进度</dt><dd class="progress-cell"><div class="progress-track"><span :style="{ width: `${progressValue(run.progress)}%` }" /></div>{{ progressValue(run.progress).toFixed(0) }}%</dd></div>
      <div class="detail-item"><dt>SSE 状态</dt><dd class="stream-state"><Radio :size="13" />{{ { idle: '未连接', connecting: '连接中', connected: '实时连接', disconnected: '连接中断，轮询兜底' }[streamState] }}</dd></div>
      <div class="detail-item"><dt>策略版本</dt><dd>v{{ run.policy_version }}</dd></div>
      <div class="detail-item"><dt>运行时长</dt><dd>{{ duration(run.started_at, run.completed_at) }}</dd></div>
      <div class="detail-item"><dt>开始时间</dt><dd>{{ formatDate(run.started_at || run.created_at) }}</dd></div>
    </dl>

    <div class="section-title"><h2>审计阶段</h2><p>{{ Object.values(taskCounts).reduce((sum, count) => sum + count, tasks.length) }} 个任务 · {{ run.warning_count }} 条警告</p></div>
    <section class="panel"><StageTimeline :run="run" :tasks="tasks" /></section>

    <div class="section-title"><h2>Coverage</h2><p>构建、文件、入口与敏感调用覆盖情况</p></div>
    <StatePanel v-if="!coverage" kind="empty" title="Coverage 尚未生成" message="覆盖检查阶段完成后将在此显示。" />
    <template v-else>
      <section class="coverage-grid">
        <article v-for="item in coverageItems" :key="item.label"><div><span>{{ item.label }}</span><strong>{{ item.value }} / {{ item.total }}</strong></div><div class="progress-track"><span :style="{ width: `${ratio(item.value, item.total)}%` }" /></div><small>{{ ratio(item.value, item.total) }}%</small></article>
      </section>
      <div class="coverage-footer"><span>构建状态</span><StatusBadge :value="coverage.build_status" /><span>更新时间 {{ formatDate(coverage.updated_at) }}</span></div>
      <section class="coverage-details">
        <article><h3>静态工具</h3><ul><li v-for="(result, tool) in coverage.static_tools_completed" :key="tool"><span>{{ tool }}</span><code>{{ typeof result === 'object' ? JSON.stringify(result) : result }}</code></li><li v-if="!Object.keys(coverage.static_tools_completed).length">无记录</li></ul></article>
        <article><h3>跳过路径</h3><ul><li v-for="path in coverage.skipped_paths" :key="path" class="mono">{{ path }}</li><li v-if="!coverage.skipped_paths.length">无</li></ul></article>
        <article><h3>不支持组件</h3><ul><li v-for="(component, index) in coverage.unsupported_components" :key="index"><code>{{ JSON.stringify(component) }}</code></li><li v-if="!coverage.unsupported_components.length">无</li></ul></article>
      </section>
    </template>

    <div v-if="warnings.length" class="section-title"><h2>运行警告</h2><p>{{ warnings.length }} 条</p></div>
    <section v-if="warnings.length" class="warning-list"><article v-for="(warning, index) in warnings" :key="`${warning.code}-${index}`"><AlertTriangle :size="16" /><div><strong>{{ warning.code || "COVERAGE_WARNING" }}</strong><p>{{ warning.message }}</p></div></article></section>
  </template>
</template>

<style scoped>
.back-link { display: inline-flex; align-items: center; gap: 5px; margin-bottom: 12px; color: var(--muted); font-size: 11px; text-decoration: none; }
.run-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 20px; }
.run-title { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.run-title h1 { margin: 0; font-size: 23px; }
.run-header p { margin: 6px 0 0; color: var(--muted); overflow-wrap: anywhere; }
.run-actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 8px; }
.run-error { margin-bottom: 12px; }
.report-ready { margin-bottom: 12px; }
.report-ready a { display: inline-flex; align-items: center; gap: 4px; color: var(--success); font-size: 10px; font-weight: 700; }
.run-summary { margin-top: 14px; }
.progress-cell { display: flex; align-items: center; gap: 8px; }
.progress-cell .progress-track { max-width: 130px; }
.stream-state { display: flex; align-items: center; gap: 6px; }
.coverage-grid { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px; }
.coverage-grid article { display: grid; grid-template-columns: 1fr auto; gap: 9px 12px; padding: 14px; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
.coverage-grid article > div:first-child { display: flex; grid-column: 1 / -1; justify-content: space-between; gap: 8px; font-size: 11px; }
.coverage-grid article strong { font-size: 12px; }
.coverage-grid small { color: var(--muted); font-size: 9px; }
.coverage-footer { display: flex; align-items: center; gap: 9px; margin-top: 9px; color: var(--muted); font-size: 10px; }
.coverage-footer span:last-child { margin-left: auto; }
.coverage-details { display: grid; grid-template-columns: 1.3fr 1fr 1fr; gap: 10px; margin-top: 10px; }
.coverage-details article { min-width: 0; padding: 12px 14px; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
.coverage-details h3 { margin: 0 0 8px; font-size: 10px; }
.coverage-details ul { display: grid; gap: 6px; margin: 0; padding: 0; color: var(--muted); font-size: 9px; list-style: none; }
.coverage-details li { min-width: 0; overflow-wrap: anywhere; }
.coverage-details li span { margin-right: 6px; color: var(--text); }
.coverage-details code { white-space: pre-wrap; overflow-wrap: anywhere; }
.warning-list { display: grid; gap: 8px; }
.warning-list article { display: flex; align-items: flex-start; gap: 10px; padding: 12px 14px; color: var(--warning); background: var(--warning-soft); border: 1px solid #ead9a8; border-radius: 6px; }
.warning-list strong { font-size: 10px; }
.warning-list p { margin: 3px 0 0; color: #765b27; font-size: 11px; line-height: 1.5; overflow-wrap: anywhere; }
@media (max-width: 900px) { .coverage-grid { grid-template-columns: 1fr 1fr; } .coverage-details { grid-template-columns: 1fr; } }
@media (max-width: 620px) { .run-header { display: grid; } .run-actions { justify-content: flex-start; } .run-actions .button { flex: 1; } .coverage-grid { grid-template-columns: 1fr; } .coverage-footer { align-items: flex-start; flex-wrap: wrap; } .coverage-footer span:last-child { width: 100%; margin-left: 0; } }
</style>
