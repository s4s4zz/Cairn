<script setup lang="ts">
import { Eye, Search } from "@lucide/vue";
import { onMounted, reactive, ref } from "vue";

import { auditLogApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import type { AuditLogEntry } from "@/types/api";
import { errorMessage, formatDate, shortId } from "@/utils";

const items = ref<AuditLogEntry[]>([]);
const loading = ref(true);
const error = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 50;
const selected = ref<AuditLogEntry | null>(null);
const filters = reactive({ actor: "", action: "", targetType: "", targetId: "" });

async function load(): Promise<void> {
  loading.value = true; error.value = "";
  try { const page = await auditLogApi.list({ actor_username: filters.actor || undefined, action: filters.action || undefined, target_type: filters.targetType || undefined, target_id: filters.targetId || undefined, limit, offset: offset.value }); items.value = page.items; total.value = page.meta.total; } catch (reason) { error.value = errorMessage(reason); } finally { loading.value = false; }
}
async function search(): Promise<void> { offset.value = 0; await load(); }
async function changePage(value: number): Promise<void> { offset.value = value; await load(); }
onMounted(load);
</script>

<template>
  <PageHeader title="审计日志" description="只读查看关键操作、拒绝访问、目标对象与请求关联信息。" />
  <form class="toolbar logs-toolbar" @submit.prevent="search"><div class="toolbar__filters"><div class="field"><label for="log-actor">操作人</label><input id="log-actor" v-model.trim="filters.actor" class="input" /></div><div class="field"><label for="log-action">动作</label><input id="log-action" v-model.trim="filters.action" class="input" placeholder="finding_reviewed" /></div><div class="field"><label for="log-target-type">目标类型</label><input id="log-target-type" v-model.trim="filters.targetType" class="input" /></div><div class="field log-target"><label for="log-target-id">目标 ID</label><input id="log-target-id" v-model.trim="filters.targetId" class="input mono" /></div></div><button class="button button--secondary" type="submit"><Search :size="15" />查询</button></form>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="没有符合条件的审计日志" />
  <div v-else class="table-wrap"><table class="data-table logs-table"><thead><tr><th style="width:17%">时间</th><th style="width:15%">操作人</th><th style="width:22%">动作</th><th style="width:20%">目标</th><th style="width:12%">结果</th><th>请求 ID</th><th style="width:44px"></th></tr></thead><tbody>
    <tr v-for="entry in items" :key="entry.id"><td class="muted nowrap">{{ formatDate(entry.created_at) }}</td><td><span class="cell-main">{{ entry.actor_username }}</span><span class="cell-sub">{{ entry.actor_role || '-' }}</span></td><td class="mono">{{ entry.action }}</td><td><span class="cell-main">{{ entry.target_type || '-' }}</span><span class="cell-sub mono">{{ shortId(entry.target_id, 14) }}</span></td><td><StatusBadge :value="entry.outcome === 'denied' ? 'rejected' : 'succeeded'" /></td><td class="mono muted">{{ shortId(entry.request_id, 12) }}</td><td><button class="icon-button" type="button" title="查看详情" @click="selected = entry"><Eye :size="15" /></button></td></tr>
  </tbody></table><PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" /></div>
  <ModalDialog :open="Boolean(selected)" title="审计日志详情" @close="selected = null"><dl v-if="selected" class="log-detail"><div><dt>动作</dt><dd class="mono">{{ selected.action }}</dd></div><div><dt>操作人</dt><dd>{{ selected.actor_username }} · {{ selected.actor_role || '-' }}</dd></div><div><dt>目标</dt><dd class="mono">{{ selected.target_type || '-' }} / {{ selected.target_id || '-' }}</dd></div><div><dt>HTTP / IP</dt><dd>{{ selected.http_status || '-' }} · {{ selected.client_ip || '-' }}</dd></div><div><dt>请求 ID</dt><dd class="mono">{{ selected.request_id || '-' }}</dd></div><div><dt>时间</dt><dd>{{ formatDate(selected.created_at) }}</dd></div><div class="wide"><dt>详情</dt><dd><pre>{{ JSON.stringify(selected.detail, null, 2) }}</pre></dd></div></dl></ModalDialog>
</template>

<style scoped>
.log-target { flex: 1; min-width: 200px; }
.log-detail { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; margin: 0; overflow: hidden; background: var(--line); border: 1px solid var(--line); border-radius: 6px; }
.log-detail > div { min-width: 0; padding: 11px; background: #fff; }
.log-detail .wide { grid-column: 1 / -1; }
.log-detail dt { margin-bottom: 5px; color: var(--muted); font-size: 9px; }
.log-detail dd { margin: 0; font-size: 11px; overflow-wrap: anywhere; }
.log-detail pre { max-height: 280px; margin: 0; padding: 10px; overflow: auto; color: #36423c; background: #f6f8f7; border-radius: 4px; font-size: 10px; white-space: pre-wrap; }
@media (max-width: 780px) { .logs-table { min-width: 920px; } }
@media (max-width: 560px) { .logs-toolbar .toolbar__filters { grid-template-columns: 1fr 1fr; } .log-target { grid-column: 1 / -1; } .log-detail { grid-template-columns: 1fr; } .log-detail .wide { grid-column: auto; } }
</style>
