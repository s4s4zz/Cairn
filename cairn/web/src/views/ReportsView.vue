<script setup lang="ts">
import { Download, FileJson, FileText, Plus } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import { auditRunApi, reportApi } from "@/api/resources";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { AuditRun, Report } from "@/types/api";
import { errorMessage, formatDate, shortId } from "@/utils";

const route = useRoute();
const auth = useAuthStore();
const reports = ref<Report[]>([]);
const runs = ref<AuditRun[]>([]);
const loading = ref(true);
const error = ref("");
const generating = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 25;
const runFilter = typeof route.query.audit_run_id === "string" ? route.query.audit_run_id : "";
const canWrite = computed(() => auth.can(["admin", "auditor"]));

async function loadCandidates(): Promise<AuditRun[]> {
  if (runFilter) {
    const run = await auditRunApi.get(runFilter);
    return run.status === "human_review" ? [run] : [];
  }
  const page = await auditRunApi.list({ status: "human_review", limit: 100 });
  return page.items.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const [reportPage, candidates] = await Promise.all([
      reportApi.list({ audit_run_id: runFilter || undefined, limit, offset: offset.value }),
      loadCandidates(),
    ]);
    reports.value = reportPage.items;
    total.value = reportPage.meta.total;
    runs.value = candidates;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

async function generate(run: AuditRun): Promise<void> {
  generating.value = run.id;
  error.value = "";
  try {
    await reportApi.generate(run.id);
    offset.value = 0;
    await load();
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    generating.value = "";
  }
}

async function changePage(value: number): Promise<void> {
  offset.value = value;
  await load();
}

onMounted(load);
</script>

<template>
  <PageHeader title="报告" description="生成并下载包含 Coverage、未审计范围与处置结论的审计报告。" />
  <div v-if="error" class="inline-error report-notice">{{ error }}</div>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="!runs.length && !reports.length" kind="empty" title="暂无可用报告" message="完成严重与高危漏洞处置后，可为 human_review 状态的 AuditRun 生成报告。" />
  <template v-else>
    <template v-if="runs.length">
      <div class="section-title"><h2>待生成</h2><p>{{ runs.length }} 个 AuditRun 已进入人工复核</p></div>
      <section class="report-list candidate-list">
        <article v-for="run in runs" :key="run.id" class="report-row report-row--candidate">
          <div class="report-row__run"><FileText :size="19" /><div><RouterLink class="row-link" :to="`/audit-runs/${run.id}`">AuditRun {{ shortId(run.id) }}</RouterLink><span>{{ formatDate(run.created_at) }} · 策略 v{{ run.policy_version }}</span></div></div>
          <div class="report-row__risk"><StatusBadge :value="run.status" /><span>{{ run.warning_count }} 条运行警告</span></div>
          <button v-if="canWrite" class="button button--small" type="button" :disabled="generating === run.id" @click="generate(run)"><Plus :size="14" />{{ generating === run.id ? "生成中" : "生成报告" }}</button>
        </article>
      </section>
    </template>

    <div class="section-title"><h2>已生成报告</h2><p>{{ total }} 份</p></div>
    <StatePanel v-if="!reports.length" kind="empty" title="暂无已生成报告" />
    <section v-else class="report-list">
      <article v-for="item in reports" :key="item.id" class="report-row report-row--stored">
        <div class="report-row__run"><FileText :size="19" /><div><RouterLink class="row-link" :to="`/audit-runs/${item.audit_run_id}`">AuditRun {{ shortId(item.audit_run_id) }}</RouterLink><span>{{ formatDate(item.generated_at) }}</span></div></div>
        <div class="report-row__risk"><strong>报告 v{{ item.version }}</strong><span class="mono">{{ shortId(item.id) }}</span></div>
        <div class="report-files">
          <a class="icon-button" :href="reportApi.downloadUrl(item.id, 'html')" target="_blank" title="打开 HTML 报告"><FileText :size="16" /></a>
          <a class="icon-button" :href="reportApi.downloadUrl(item.id, 'json')" title="下载 JSON 报告"><FileJson :size="16" /></a>
          <a class="icon-button" :href="reportApi.downloadUrl(item.id, 'sarif')" title="下载 SARIF 报告"><Download :size="16" /></a>
        </div>
      </article>
      <PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" />
    </section>
  </template>
</template>

<style scoped>
.report-notice { margin-bottom: 12px; }
.candidate-list { margin-bottom: 18px; }
.report-list { overflow: hidden; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
.report-row { display: grid; min-height: 74px; grid-template-columns: minmax(220px, 1.5fr) minmax(150px, .8fr) minmax(145px, .8fr) auto; align-items: center; gap: 16px; padding: 12px 15px; border-bottom: 1px solid var(--line); }
.report-row--candidate { grid-template-columns: minmax(220px, 1.5fr) minmax(150px, .8fr) auto; }
.report-row--stored { grid-template-columns: minmax(220px, 1.5fr) minmax(130px, .7fr) minmax(145px, .8fr); }
.report-row:last-child { border-bottom: 0; }
.report-row__run { display: flex; min-width: 0; align-items: center; gap: 10px; }
.report-row__run > div { display: grid; min-width: 0; gap: 4px; }
.report-row__run a { overflow: hidden; font-size: 12px; font-weight: 650; text-overflow: ellipsis; white-space: nowrap; }
.report-row__run span, .report-row__risk span { color: var(--muted); font-size: 9px; }
.report-row__risk { display: grid; justify-items: start; gap: 5px; }
.report-row__risk strong { font-size: 11px; }
.report-files { display: flex; min-width: 120px; align-items: center; gap: 3px; }
@media (max-width: 850px) { .report-row { grid-template-columns: 1fr auto; } .report-row__risk { display: none; } }
@media (max-width: 540px) { .report-row { align-items: start; grid-template-columns: 1fr; } .report-files { justify-content: flex-start; } .report-row > .button { width: 100%; } }
</style>
