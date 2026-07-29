<script setup lang="ts">
import { CheckCircle2, RefreshCw, ShieldAlert } from "@lucide/vue";
import { computed, onMounted, reactive, ref } from "vue";
import { useRoute } from "vue-router";

import { findingApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { Finding, FindingDetail, FindingSeverity, ReverifyMethod, ReviewVerdict } from "@/types/api";
import { categoryLabel, errorMessage, formatDate } from "@/utils";

const route = useRoute();
const auth = useAuthStore();
const items = ref<Finding[]>([]);
const loading = ref(true);
const error = ref("");
const detail = ref<FindingDetail | null>(null);
const dialogOpen = ref(false);
const detailLoading = ref(false);
const saving = ref(false);
const actionError = ref("");
const form = reactive({
  verdict: "confirmed" as ReviewVerdict,
  finalSeverity: "high" as FindingSeverity,
  reverifyMethod: "independent_agent" as ReverifyMethod,
  comment: "",
});
const canDecide = computed(() => auth.can(["admin", "reviewer"]));
const canReverify = computed(() => auth.can(["admin", "auditor"]));
const verdictOptions = computed<Array<{ value: ReviewVerdict; label: string }>>(() => [
  ...(canDecide.value ? [
    { value: "confirmed" as const, label: "确认漏洞" },
    { value: "rejected" as const, label: "驳回" },
    { value: "accepted_risk" as const, label: "接受风险" },
  ] : []),
  ...(canReverify.value ? [{ value: "reverify" as const, label: "重新验证" }] : []),
]);

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const [critical, high] = await Promise.all([
      findingApi.list({ status: "awaiting_human_review", severity: "critical", limit: 100 }),
      findingApi.list({ status: "awaiting_human_review", severity: "high", limit: 100 }),
    ]);
    items.value = [...critical.items, ...high.items].sort((a, b) => b.updated_at.localeCompare(a.updated_at));
    const requested = typeof route.query.finding === "string" ? route.query.finding : "";
    if (requested) {
      const finding = items.value.find((item) => item.id === requested);
      if (finding) await openReview(finding);
    }
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

async function openReview(finding: Finding): Promise<void> {
  dialogOpen.value = true;
  detailLoading.value = true;
  actionError.value = "";
  form.verdict = canDecide.value ? "confirmed" : "reverify";
  form.finalSeverity = finding.severity;
  form.reverifyMethod = "independent_agent";
  form.comment = "";
  try { detail.value = await findingApi.get(finding.id); } catch (reason) { actionError.value = errorMessage(reason); } finally { detailLoading.value = false; }
}

async function submit(): Promise<void> {
  if (!detail.value || !form.comment.trim()) return;
  saving.value = true;
  actionError.value = "";
  try {
    if (form.verdict === "reverify") {
      await findingApi.reverify(detail.value.id, form.reverifyMethod, form.comment.trim());
    } else {
      await findingApi.review(detail.value.id, { verdict: form.verdict, final_severity: form.finalSeverity, comment: form.comment.trim() });
    }
    dialogOpen.value = false;
    items.value = items.value.filter((item) => item.id !== detail.value?.id);
    detail.value = null;
  } catch (reason) {
    actionError.value = errorMessage(reason);
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <PageHeader title="人工复核" description="处置已通过机器复核的严重与高危漏洞。">
    <template #actions><button class="button button--secondary" type="button" @click="load"><RefreshCw :size="15" />刷新队列</button></template>
  </PageHeader>
  <div class="review-summary"><ShieldAlert :size="18" /><div><strong>{{ items.length }}</strong><span>条漏洞等待处置</span></div><p>确认、驳回、接受风险或请求重新验证均会写入操作审计日志。</p></div>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="复核队列已清空" message="当前没有等待人工处置的严重或高危漏洞。" />
  <div v-else class="table-wrap"><table class="data-table review-table"><thead><tr><th style="width:40%">漏洞</th><th style="width:13%">严重性</th><th style="width:19%">机器状态</th><th>进入队列</th><th style="width:88px"></th></tr></thead><tbody>
    <tr v-for="finding in items" :key="finding.id"><td><RouterLink class="row-link cell-main" :to="`/findings/${finding.id}`">{{ finding.title }}</RouterLink><span class="cell-sub">{{ finding.cwe_id }} · {{ categoryLabel(finding.category) }}</span></td><td><SeverityBadge :value="finding.severity" /></td><td><StatusBadge :value="finding.status" /></td><td class="muted nowrap">{{ formatDate(finding.updated_at) }}</td><td><button class="button button--small" type="button" @click="openReview(finding)"><CheckCircle2 :size="14" />处置</button></td></tr>
  </tbody></table></div>

  <ModalDialog :open="dialogOpen" title="人工处置" width="large" @close="dialogOpen = false">
    <StatePanel v-if="detailLoading" kind="loading" />
    <form v-else-if="detail" id="review-form" class="review-form" @submit.prevent="submit">
      <section class="review-finding"><div><SeverityBadge :value="detail.severity" /><StatusBadge :value="detail.runtime_verification" /></div><h3>{{ detail.title }}</h3><p>{{ detail.description }}</p><dl><div><dt>攻击前提</dt><dd>{{ detail.attack_preconditions }}</dd></div><div><dt>影响</dt><dd>{{ detail.impact }}</dd></div></dl></section>
      <div class="field"><span class="field-label">处置结论</span><div class="verdict-grid">
        <button v-for="option in verdictOptions" :key="option.value" type="button" :class="{ active: form.verdict === option.value }" @click="form.verdict = option.value">{{ option.label }}</button>
      </div></div>
      <div v-if="form.verdict !== 'reverify'" class="field"><label for="final-severity">最终严重性</label><select id="final-severity" v-model="form.finalSeverity" class="select"><option value="critical">严重</option><option value="high">高危</option><option value="medium">中危</option><option value="low">低危</option><option value="info">提示</option></select></div>
      <div v-else class="field"><label for="reverify-method">重新验证方式</label><select id="reverify-method" v-model="form.reverifyMethod" class="select"><option value="independent_agent">独立 Agent</option><option value="dynamic_poc">动态 PoC</option></select></div>
      <div class="field"><label for="review-comment">复核意见</label><textarea id="review-comment" v-model="form.comment" class="textarea" minlength="2" required placeholder="记录判断依据、风险接受原因或重新验证范围" /></div>
      <div v-if="actionError" class="inline-error">{{ actionError }}</div>
    </form>
    <div v-else-if="actionError" class="inline-error">{{ actionError }}</div>
    <template #footer><button class="button button--secondary" type="button" @click="dialogOpen = false">取消</button><button class="button" type="submit" form="review-form" :disabled="saving || detailLoading || !form.comment.trim()">{{ saving ? "正在提交" : "提交处置" }}</button></template>
  </ModalDialog>
</template>

<style scoped>
.review-summary { display: flex; align-items: center; gap: 12px; margin-bottom: 14px; padding: 13px 15px; color: #795a20; background: var(--warning-soft); border: 1px solid #ead8a6; border-radius: 7px; }
.review-summary > div { display: grid; min-width: 80px; }
.review-summary strong { font-size: 20px; line-height: 1; }
.review-summary span { margin-top: 4px; font-size: 9px; }
.review-summary p { margin: 0 0 0 auto; font-size: 10px; }
.review-form { display: grid; gap: 16px; }
.review-finding { padding: 14px; background: var(--surface-alt); border: 1px solid var(--line); border-radius: 6px; }
.review-finding > div { display: flex; gap: 7px; }
.review-finding h3 { margin: 10px 0 6px; font-size: 14px; overflow-wrap: anywhere; }
.review-finding p { margin: 0; color: #56635c; font-size: 11px; line-height: 1.55; }
.review-finding dl { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 12px 0 0; }
.review-finding dl div { padding-top: 9px; border-top: 1px solid var(--line); }
.review-finding dt { color: var(--muted); font-size: 9px; }
.review-finding dd { margin: 4px 0 0; font-size: 10px; line-height: 1.5; }
.verdict-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 7px; }
.verdict-grid button { min-height: 38px; padding: 7px; color: #59665f; background: #fff; border: 1px solid var(--line-strong); border-radius: 5px; cursor: pointer; font-size: 10px; }
.verdict-grid button.active { color: var(--accent); background: var(--accent-soft); border-color: #69a897; font-weight: 700; }
@media (max-width: 700px) { .review-table { min-width: 720px; } .verdict-grid { grid-template-columns: 1fr 1fr; } .review-finding dl { grid-template-columns: 1fr; } .review-summary p { display: none; } }
</style>
