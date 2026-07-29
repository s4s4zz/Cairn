<script setup lang="ts">
import { Plus, ShieldAlert } from "@lucide/vue";
import { computed, onMounted, reactive, ref } from "vue";

import { policyApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { AuditPolicy } from "@/types/api";
import { errorMessage, formatDate } from "@/utils";

const supportedScanners = ["codeql", "config-rules", "dependency-check", "findsecbugs", "gitleaks", "semgrep", "trivy"];
const auth = useAuthStore();
const items = ref<AuditPolicy[]>([]);
const loading = ref(true);
const error = ref("");
const dialogOpen = ref(false);
const saving = ref(false);
const formError = ref("");
const form = reactive({
  name: "",
  includePaths: "**",
  excludePaths: "",
  enabledScanners: [...supportedScanners],
  dynamicVerification: "required" as AuditPolicy["dynamic_verification"],
  severityThresholds: "{}",
  resourceBudget: "{}",
  active: true,
});
const canManage = computed(() => auth.can(["admin"]));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try { items.value = (await policyApi.list({ limit: 100 })).items; } catch (reason) { error.value = errorMessage(reason); } finally { loading.value = false; }
}

function lines(value: string): string[] {
  return [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))];
}

function jsonObject(value: string, label: string): Record<string, unknown> {
  const parsed = JSON.parse(value) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error(`${label}必须是 JSON 对象`);
  return parsed as Record<string, unknown>;
}

function reset(): void {
  Object.assign(form, {
    name: "",
    includePaths: "**",
    excludePaths: "",
    enabledScanners: [...supportedScanners],
    dynamicVerification: "required",
    severityThresholds: "{}",
    resourceBudget: "{}",
    active: true,
  });
  formError.value = "";
}

async function createPolicy(): Promise<void> {
  saving.value = true;
  formError.value = "";
  try {
    if (!form.enabledScanners.length) throw new Error("至少启用一个扫描器");
    await policyApi.create({
      name: form.name.trim(),
      include_paths: lines(form.includePaths),
      exclude_paths: lines(form.excludePaths),
      enabled_scanners: form.enabledScanners,
      dynamic_verification: form.dynamicVerification,
      severity_thresholds: jsonObject(form.severityThresholds, "严重性阈值"),
      resource_budget: jsonObject(form.resourceBudget, "资源预算"),
      active: form.active,
    });
    dialogOpen.value = false;
    reset();
    await load();
  } catch (reason) {
    formError.value = errorMessage(reason);
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <PageHeader title="规则与策略" description="查看审计范围、扫描器组合、动态验证与资源预算。">
    <template #actions><button v-if="canManage" class="button" type="button" @click="dialogOpen = true"><Plus :size="15" />创建策略版本</button></template>
  </PageHeader>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="暂无审计策略" />
  <section v-else class="policy-list">
    <article v-for="policy in items" :key="policy.id" class="policy-row">
      <div class="policy-name"><div><strong>{{ policy.name }}</strong><StatusBadge :value="policy.active ? 'active' : 'inactive'" /></div><span>版本 {{ policy.version }} · {{ formatDate(policy.created_at) }}</span></div>
      <div class="policy-scanners"><span v-for="scanner in policy.enabled_scanners" :key="scanner">{{ scanner }}</span></div>
      <div class="policy-verify" :class="{ 'policy-verify--warning': policy.dynamic_verification === 'disabled' }"><ShieldAlert :size="15" /><div><strong>动态验证 {{ policy.dynamic_verification }}</strong><span>{{ policy.include_paths.join(', ') }}</span></div></div>
    </article>
  </section>

  <ModalDialog :open="dialogOpen" title="创建策略版本" width="large" @close="dialogOpen = false">
    <form id="policy-create" class="policy-form" @submit.prevent="createPolicy">
      <div class="policy-form__grid"><div class="field"><label for="policy-name">策略名称</label><input id="policy-name" v-model.trim="form.name" class="input" maxlength="255" required /></div><div class="field"><label for="dynamic-verification">动态验证</label><select id="dynamic-verification" v-model="form.dynamicVerification" class="select"><option value="required">必须</option><option value="preferred">优先</option><option value="disabled">禁用</option></select></div></div>
      <div class="policy-form__grid"><div class="field"><label for="include-paths">包含路径（每行一项）</label><textarea id="include-paths" v-model="form.includePaths" class="textarea" required /></div><div class="field"><label for="exclude-paths">排除路径（每行一项）</label><textarea id="exclude-paths" v-model="form.excludePaths" class="textarea" /></div></div>
      <fieldset class="scanner-field"><legend>扫描器</legend><label v-for="scanner in supportedScanners" :key="scanner"><input v-model="form.enabledScanners" type="checkbox" :value="scanner" />{{ scanner }}</label></fieldset>
      <div class="policy-form__grid"><div class="field"><label for="severity-thresholds">严重性阈值 JSON</label><textarea id="severity-thresholds" v-model="form.severityThresholds" class="textarea mono" required /></div><div class="field"><label for="resource-budget">资源预算 JSON</label><textarea id="resource-budget" v-model="form.resourceBudget" class="textarea mono" required /></div></div>
      <label class="toggle-row"><input v-model="form.active" type="checkbox" />创建后启用</label>
      <div v-if="formError" class="inline-error">{{ formError }}</div>
    </form>
    <template #footer><button class="button button--secondary" type="button" @click="dialogOpen = false">取消</button><button class="button" type="submit" form="policy-create" :disabled="saving">{{ saving ? "创建中" : "创建版本" }}</button></template>
  </ModalDialog>
</template>

<style scoped>
.policy-list { overflow: hidden; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
.policy-row { display: grid; min-height: 88px; grid-template-columns: minmax(190px, .8fr) minmax(260px, 1.4fr) minmax(190px, .8fr); align-items: center; gap: 18px; padding: 14px 16px; border-bottom: 1px solid var(--line); }
.policy-row:last-child { border-bottom: 0; }
.policy-name, .policy-verify > div { display: grid; min-width: 0; gap: 5px; }
.policy-name > div { display: flex; align-items: center; gap: 8px; }
.policy-name strong { font-size: 12px; }
.policy-name span, .policy-verify span { overflow: hidden; color: var(--muted); font-size: 9px; text-overflow: ellipsis; white-space: nowrap; }
.policy-scanners { display: flex; flex-wrap: wrap; gap: 5px; }
.policy-scanners span { padding: 3px 6px; color: #45534c; background: #edf1ef; border-radius: 4px; font-size: 9px; }
.policy-verify { display: flex; min-width: 0; align-items: center; gap: 8px; color: var(--success); }
.policy-verify--warning { color: var(--warning); }
.policy-verify strong { font-size: 10px; }
.policy-form { display: grid; gap: 15px; }
.policy-form__grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
.scanner-field { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; margin: 0; padding: 11px 12px 12px; border: 1px solid var(--line); border-radius: 6px; }
.scanner-field legend { padding: 0 5px; color: var(--muted); font-size: 10px; }
.scanner-field label, .toggle-row { display: flex; align-items: center; gap: 6px; color: #4b5852; font-size: 10px; }
@media (max-width: 760px) { .policy-row, .policy-form__grid { grid-template-columns: 1fr; gap: 10px; } .scanner-field { grid-template-columns: 1fr 1fr; } }
</style>
