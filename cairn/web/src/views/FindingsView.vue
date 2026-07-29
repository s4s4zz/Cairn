<script setup lang="ts">
import { RefreshCw } from "@lucide/vue";
import { onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { findingApi } from "@/api/resources";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import type { Finding, FindingSeverity, FindingStatus } from "@/types/api";
import { categoryLabel, errorMessage, formatDate, shortId } from "@/utils";

const route = useRoute();
const router = useRouter();
const items = ref<Finding[]>([]);
const severity = ref<FindingSeverity | "">((route.query.severity as FindingSeverity) || "");
const status = ref<FindingStatus | "">((route.query.status as FindingStatus) || "");
const cweId = ref(typeof route.query.cwe_id === "string" ? route.query.cwe_id : "");
const auditRunId = ref(typeof route.query.audit_run_id === "string" ? route.query.audit_run_id : "");
const loading = ref(true);
const error = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 25;

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const page = await findingApi.list({
      severity: severity.value || undefined,
      status: status.value || undefined,
      cwe_id: cweId.value.trim() || undefined,
      audit_run_id: auditRunId.value.trim() || undefined,
      limit,
      offset: offset.value,
    });
    items.value = page.items;
    total.value = page.meta.total;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

async function applyFilters(): Promise<void> {
  offset.value = 0;
  await router.replace({ query: {
    ...(severity.value ? { severity: severity.value } : {}),
    ...(status.value ? { status: status.value } : {}),
    ...(cweId.value ? { cwe_id: cweId.value } : {}),
    ...(auditRunId.value ? { audit_run_id: auditRunId.value } : {}),
  } });
  await load();
}

async function changePage(value: number): Promise<void> { offset.value = value; await load(); }
onMounted(load);
</script>

<template>
  <PageHeader title="漏洞" description="按审计任务、CWE、严重性和处置状态筛选结构化 Finding。" />
  <div class="toolbar finding-toolbar"><div class="toolbar__filters">
    <div class="field"><label for="finding-severity">严重性</label><select id="finding-severity" v-model="severity" class="select" @change="applyFilters"><option value="">全部</option><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">提示</option></select></div>
    <div class="field"><label for="finding-status">状态</label><select id="finding-status" v-model="status" class="select" @change="applyFilters"><option value="">全部</option><option v-for="value in ['candidate','validating','machine_confirmed','awaiting_human_review','confirmed','rejected','accepted_risk']" :key="value" :value="value">{{ value }}</option></select></div>
    <div class="field"><label for="finding-cwe">CWE</label><input id="finding-cwe" v-model.trim="cweId" class="input" placeholder="CWE-89" @keyup.enter="applyFilters" /></div>
    <div class="field field--run"><label for="finding-run">AuditRun ID</label><input id="finding-run" v-model.trim="auditRunId" class="input mono" placeholder="UUID" @keyup.enter="applyFilters" /></div>
  </div><button class="button button--secondary" type="button" @click="load"><RefreshCw :size="15" />刷新</button></div>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="没有符合条件的漏洞" />
  <div v-else class="table-wrap"><table class="data-table findings-table"><thead><tr><th style="width:34%">漏洞</th><th style="width:13%">严重性</th><th style="width:20%">状态</th><th style="width:14%">验证</th><th style="width:19%">更新时间</th></tr></thead><tbody>
    <tr v-for="finding in items" :key="finding.id"><td><RouterLink class="row-link cell-main" :to="`/findings/${finding.id}`">{{ finding.title }}</RouterLink><span class="cell-sub">{{ finding.cwe_id }} · {{ categoryLabel(finding.category) }} · {{ shortId(finding.id) }}</span></td><td><SeverityBadge :value="finding.severity" /></td><td><StatusBadge :value="finding.status" /></td><td><StatusBadge :value="finding.runtime_verification" /></td><td class="muted nowrap">{{ formatDate(finding.updated_at) }}</td></tr>
  </tbody></table><PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" /></div>
</template>

<style scoped>
.field--run { flex: 1; min-width: 210px; }
@media (max-width: 760px) { .findings-table { min-width: 760px; } }
@media (max-width: 560px) { .finding-toolbar .toolbar__filters { grid-template-columns: 1fr 1fr; } .field--run { grid-column: 1 / -1; } }
</style>
