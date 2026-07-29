<script setup lang="ts">
import { CheckCircle2, Eye, EyeOff, RefreshCw, Save } from "@lucide/vue";
import { computed, onMounted, reactive, ref } from "vue";

import { modelProviderApi } from "@/api/resources";
import PageHeader from "@/components/PageHeader.vue";
import StatePanel from "@/components/StatePanel.vue";
import type { ModelProvider, ModelProviderStatus, ModelSummary } from "@/types/api";
import { errorMessage, formatDate } from "@/utils";

const defaults: Record<ModelProvider, string> = {
  openai: "https://api.openai.com",
  anthropic: "https://api.anthropic.com",
};
const loading = ref(true);
const saving = ref(false);
const discovering = ref(false);
const error = ref("");
const notice = ref("");
const revealKey = ref(false);
const status = ref<ModelProviderStatus | null>(null);
const models = ref<ModelSummary[]>([]);
const form = reactive({
  provider: "anthropic" as ModelProvider,
  baseUrl: defaults.anthropic,
  apiKey: "",
  model: "",
});

const configured = computed(() => Boolean(status.value?.configured));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    status.value = await modelProviderApi.get();
    if (status.value.configured && status.value.provider) {
      form.provider = status.value.provider;
      form.baseUrl = status.value.base_url || defaults[form.provider];
      form.model = status.value.model || "";
    }
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

function selectProvider(provider: ModelProvider): void {
  if (form.provider === provider) return;
  form.provider = provider;
  form.baseUrl = defaults[provider];
  form.apiKey = "";
  form.model = "";
  models.value = [];
  notice.value = "";
}

async function discover(): Promise<void> {
  discovering.value = true;
  error.value = "";
  notice.value = "";
  try {
    const response = await modelProviderApi.models({
      provider: form.provider,
      base_url: form.baseUrl.trim(),
      ...(form.apiKey ? { api_key: form.apiKey } : {}),
    });
    models.value = response.models;
    if (!form.model && models.value.length) form.model = models.value[0].id;
    notice.value = `已获取 ${models.value.length} 个模型`;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    discovering.value = false;
  }
}

async function save(): Promise<void> {
  saving.value = true;
  error.value = "";
  notice.value = "";
  try {
    status.value = await modelProviderApi.update({
      provider: form.provider,
      base_url: form.baseUrl.trim(),
      model: form.model.trim(),
      ...(form.apiKey ? { api_key: form.apiKey } : {}),
    });
    form.apiKey = "";
    notice.value = "配置已保存";
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    saving.value = false;
  }
}

onMounted(load);
</script>

<template>
  <PageHeader title="系统配置" />
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error && !status" kind="error" :message="error" retryable @retry="load" />
  <section v-else class="settings-panel">
    <div class="settings-heading">
      <div><h2>模型供应商</h2><span v-if="configured"><CheckCircle2 :size="14" />已配置 · {{ formatDate(status?.updated_at) }}</span></div>
      <div class="provider-switch" role="group" aria-label="模型供应商">
        <button type="button" :class="{ active: form.provider === 'openai' }" @click="selectProvider('openai')">OpenAI</button>
        <button type="button" :class="{ active: form.provider === 'anthropic' }" @click="selectProvider('anthropic')">Anthropic</button>
      </div>
    </div>

    <form class="settings-form" @submit.prevent="save">
      <div class="field field--wide"><label for="provider-base-url">Base URL</label><input id="provider-base-url" v-model.trim="form.baseUrl" class="input mono" type="url" required /></div>
      <div class="field field--wide"><label for="provider-api-key">API Key</label><div class="secret-input"><input id="provider-api-key" v-model="form.apiKey" class="input mono" :type="revealKey ? 'text' : 'password'" autocomplete="new-password" :placeholder="configured ? '已保存，留空保持不变' : ''" /><button class="icon-button" type="button" :title="revealKey ? '隐藏密钥' : '显示密钥'" @click="revealKey = !revealKey"><EyeOff v-if="revealKey" :size="16" /><Eye v-else :size="16" /></button></div></div>
      <div class="field field--wide"><label for="provider-model">模型</label><div class="model-input"><input id="provider-model" v-model.trim="form.model" class="input mono" list="provider-model-options" required /><datalist id="provider-model-options"><option v-for="item in models" :key="item.id" :value="item.id">{{ item.display_name || item.id }}</option></datalist><button class="button button--secondary" type="button" :disabled="discovering || (!form.apiKey && !configured)" @click="discover"><RefreshCw :size="15" :class="{ spinning: discovering }" />{{ discovering ? "获取中" : "获取模型" }}</button></div></div>
      <div v-if="error" class="inline-error field--wide">{{ error }}</div>
      <div v-if="notice" class="inline-success field--wide">{{ notice }}</div>
      <div class="settings-actions field--wide"><button class="button" type="submit" :disabled="saving"><Save :size="15" />{{ saving ? "保存中" : "保存配置" }}</button></div>
    </form>
  </section>
</template>

<style scoped>
.settings-panel { max-width: 820px; overflow: hidden; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; }
.settings-heading { display: flex; align-items: center; justify-content: space-between; gap: 20px; padding: 18px 20px; background: var(--surface-alt); border-bottom: 1px solid var(--line); }
.settings-heading h2 { margin: 0 0 5px; font-size: 15px; }
.settings-heading span { display: flex; align-items: center; gap: 5px; color: var(--success); font-size: 10px; }
.provider-switch { display: inline-flex; padding: 3px; background: #e8edeb; border-radius: 6px; }
.provider-switch button { min-width: 102px; padding: 7px 12px; color: var(--muted); background: transparent; border: 0; border-radius: 4px; cursor: pointer; font-size: 11px; font-weight: 650; }
.provider-switch button.active { color: var(--ink); background: #fff; box-shadow: 0 1px 4px rgba(20, 35, 29, .12); }
.settings-form { display: grid; grid-template-columns: 1fr; gap: 17px; padding: 22px 20px; }
.secret-input, .model-input { display: flex; align-items: center; gap: 8px; }
.secret-input .input, .model-input .input { flex: 1; }
.secret-input { position: relative; }
.secret-input .input { padding-right: 42px; }
.secret-input .icon-button { position: absolute; right: 3px; }
.settings-actions { display: flex; justify-content: flex-end; padding-top: 3px; }
.inline-success { padding: 9px 11px; color: var(--success); background: var(--success-soft); border-radius: 5px; font-size: 11px; }
.spinning { animation: spin .9s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
@media (max-width: 640px) { .settings-heading { align-items: stretch; flex-direction: column; } .provider-switch button { flex: 1; min-width: 0; } .model-input { align-items: stretch; flex-direction: column; } }
</style>
