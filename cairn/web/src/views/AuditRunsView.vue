<script setup lang="ts">
import { Ban, RefreshCw, Trash2 } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import { useRouter } from "vue-router";

import { auditRunApi } from "@/api/resources";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { AuditRun, AuditRunStatus } from "@/types/api";
import { errorMessage, formatDate, progressValue, shortId } from "@/utils";

const router = useRouter();
const auth = useAuthStore();
const items = ref<AuditRun[]>([]);
const status = ref<AuditRunStatus | "">("");
const repositoryId = ref("");
const loading = ref(true);
const error = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 25;
const acting = ref("");
const canManage = computed(() => auth.can(["admin", "auditor"]));
const canDelete = computed(() => auth.can(["admin"]));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const page = await auditRunApi.list({ repository_id: repositoryId.value || undefined, status: status.value || undefined, limit, offset: offset.value });
    items.value = page.items;
    total.value = page.meta.total;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

function cancellable(run: AuditRun): boolean {
  return !["completed", "completed_with_warnings", "cancelled", "failed", "cancelling"].includes(run.status);
}

function deletable(run: AuditRun): boolean {
  return [
    "human_review",
    "completed",
    "completed_with_warnings",
    "cancelled",
    "failed",
  ].includes(run.status);
}

async function cancel(run: AuditRun): Promise<void> {
  acting.value = run.id;
  try { await auditRunApi.cancel(run.id); await load(); } catch (reason) { error.value = errorMessage(reason); } finally { acting.value = ""; }
}

async function retry(run: AuditRun): Promise<void> {
  acting.value = run.id;
  try { const next = await auditRunApi.retry(run.id); await router.push(`/audit-runs/${next.id}`); } catch (reason) { error.value = errorMessage(reason); } finally { acting.value = ""; }
}

async function remove(run: AuditRun): Promise<void> {
  if (
    !window.confirm(
      `确认删除审计 ${shortId(run.id)}？\n\n本次运行的任务、漏洞、证据和报告将被删除且无法恢复；固定 Snapshot 会保留。`,
    )
  ) {
    return;
  }
  acting.value = run.id;
  try {
    await auditRunApi.remove(run.id);
    await load();
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    acting.value = "";
  }
}

async function filter(): Promise<void> { offset.value = 0; await load(); }
async function changePage(value: number): Promise<void> { offset.value = value; await load(); }
onMounted(load);
</script>

<template>
  <PageHeader title="审计任务" description="查看所有审计流水线、当前阶段和处置状态。" />
  <div class="toolbar"><div class="toolbar__filters">
    <div class="field"><label for="run-status">状态</label><select id="run-status" v-model="status" class="select" @change="filter"><option value="">全部</option><option v-for="value in ['created','ingesting','preprocessing','static_scanning','semantic_auditing','dynamic_verifying','machine_review','human_review','reporting','completed','completed_with_warnings','cancelling','cancelled','failed']" :key="value" :value="value">{{ value }}</option></select></div>
    <div class="field"><label for="run-repository">仓库 ID</label><input id="run-repository" v-model.trim="repositoryId" class="input mono" placeholder="UUID" @keyup.enter="filter" /></div>
  </div><button class="button button--secondary" type="button" @click="load"><RefreshCw :size="15" />刷新</button></div>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="没有符合条件的审计任务" />
  <div v-else class="table-wrap"><table class="data-table runs-table"><thead><tr><th style="width:21%">任务</th><th style="width:16%">状态</th><th style="width:18%">阶段</th><th>进度</th><th style="width:17%">开始时间</th><th style="width:90px"></th></tr></thead><tbody>
    <tr v-for="run in items" :key="run.id"><td><RouterLink class="row-link cell-main mono" :to="`/audit-runs/${run.id}`">{{ shortId(run.id) }}</RouterLink><span class="cell-sub mono">仓库 {{ shortId(run.repository_id) }}</span></td><td><StatusBadge :value="run.status" /></td><td><StatusBadge :value="run.current_stage || 'created'" /></td><td><div class="run-progress"><div class="progress-track"><span :style="{ width: `${progressValue(run.progress)}%` }" /></div><small>{{ progressValue(run.progress).toFixed(0) }}%</small></div></td><td class="muted nowrap">{{ formatDate(run.started_at || run.created_at) }}</td><td><div v-if="canManage || canDelete" class="row-actions"><button v-if="canManage && cancellable(run)" class="icon-button" type="button" title="取消任务" :disabled="acting === run.id" @click="cancel(run)"><Ban :size="16" /></button><button v-if="canManage && ['failed','cancelled'].includes(run.status)" class="icon-button" type="button" title="重试任务" :disabled="acting === run.id" @click="retry(run)"><RefreshCw :size="16" /></button><button v-if="canDelete && deletable(run)" class="icon-button icon-button--danger" type="button" title="删除审计任务" :disabled="acting === run.id" @click="remove(run)"><Trash2 :size="16" /></button></div></td></tr>
  </tbody></table><PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" /></div>
</template>

<style scoped>
.run-progress { display: flex; align-items: center; gap: 8px; }
.run-progress .progress-track { flex: 1; }
.run-progress small { width: 28px; color: var(--muted); font-size: 9px; }
.icon-button--danger { color: var(--danger); }
@media (max-width: 720px) { .runs-table { min-width: 780px; } }
</style>
