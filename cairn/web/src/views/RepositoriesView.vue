<script setup lang="ts">
import { Archive, FolderOpen, GitBranch, Plus, Trash2, Upload } from "@lucide/vue";
import { computed, onMounted, reactive, ref } from "vue";
import { useRouter } from "vue-router";

import { repositoryApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import PaginationBar from "@/components/PaginationBar.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { Repository, SourceType } from "@/types/api";
import { archiveDirectory } from "@/utils/sourceArchive";
import { errorMessage, formatDate, shortId } from "@/utils";

const router = useRouter();
const auth = useAuthStore();
const items = ref<Repository[]>([]);
const loading = ref(true);
const error = ref("");
const total = ref(0);
const offset = ref(0);
const limit = 25;
const sourceType = ref<SourceType | "">("");
const createOpen = ref(false);
const saving = ref(false);
const formError = ref("");
const uploadFile = ref<File | null>(null);
const directoryFiles = ref<File[]>([]);
const form = reactive({ mode: "git" as SourceType, name: "", remoteUrl: "", defaultBranch: "main", credentialRef: "" });

const canManage = computed(() => auth.can(["admin", "auditor"]));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const page = await repositoryApi.list({ source_type: sourceType.value || undefined, limit, offset: offset.value });
    items.value = page.items;
    total.value = page.meta.total;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

function resetForm(): void {
  Object.assign(form, { mode: "git", name: "", remoteUrl: "", defaultBranch: "main", credentialRef: "" });
  uploadFile.value = null;
  directoryFiles.value = [];
  formError.value = "";
}

function chooseFile(event: Event): void {
  uploadFile.value = (event.target as HTMLInputElement).files?.[0] ?? null;
}

function chooseDirectory(event: Event): void {
  directoryFiles.value = Array.from((event.target as HTMLInputElement).files ?? []);
}

async function createRepository(): Promise<void> {
  formError.value = "";
  saving.value = true;
  try {
    if (form.mode === "git") {
      const repository = await repositoryApi.create({
        name: form.name.trim(),
        source_type: "git",
        remote_url: form.remoteUrl.trim(),
        default_branch: form.defaultBranch.trim(),
        ...(form.credentialRef.trim() ? { credential_ref: form.credentialRef.trim() } : {}),
      });
      createOpen.value = false;
      resetForm();
      await router.push(`/repositories/${repository.id}`);
      return;
    }

    const sourceType: Exclude<SourceType, "git"> = form.mode === "local_upload" ? "local_upload" : "zip";
    const sourceFile = sourceType === "local_upload"
      ? await archiveDirectory(directoryFiles.value)
      : uploadFile.value;
    if (!sourceFile) throw new Error("请选择 ZIP 文件");
    const repository = await repositoryApi.create({ name: form.name.trim(), source_type: sourceType });
    const upload = await repositoryApi.upload(sourceFile, sourceType);
    const snapshot = await repositoryApi.createUploadSnapshot(repository.id, upload.id);
    createOpen.value = false;
    resetForm();
    await router.push({ path: `/repositories/${repository.id}`, query: { snapshot: snapshot.id } });
  } catch (reason) {
    formError.value = errorMessage(reason);
  } finally {
    saving.value = false;
  }
}

async function remove(repository: Repository): Promise<void> {
  if (!window.confirm(`确认删除仓库“${repository.name}”？`)) return;
  try {
    await repositoryApi.remove(repository.id);
    await load();
  } catch (reason) {
    error.value = errorMessage(reason);
  }
}

async function changePage(value: number): Promise<void> {
  offset.value = value;
  await load();
}

onMounted(load);
</script>

<template>
  <PageHeader title="仓库" description="管理受审计源码来源、固定 Snapshot 并启动审计。">
    <template #actions><button v-if="canManage" class="button" type="button" @click="createOpen = true"><Plus :size="16" />新增仓库</button></template>
  </PageHeader>

  <div class="toolbar">
    <div class="toolbar__filters">
      <div class="field"><label for="source-type">来源类型</label><select id="source-type" v-model="sourceType" class="select" @change="offset = 0; load()"><option value="">全部</option><option value="git">Git</option><option value="zip">ZIP</option><option value="local_upload">目录上传</option></select></div>
    </div>
  </div>

  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error" kind="error" :message="error" retryable @retry="load" />
  <StatePanel v-else-if="!items.length" kind="empty" title="暂无仓库" message="创建 Git 或 ZIP 来源后即可固定快照并发起审计。" />
  <div v-else class="table-wrap">
    <table class="data-table repositories-table">
      <thead><tr><th style="width: 27%">仓库</th><th style="width: 14%">来源</th><th>远程地址 / 标识</th><th style="width: 18%">更新时间</th><th style="width: 72px"></th></tr></thead>
      <tbody>
        <tr v-for="repository in items" :key="repository.id">
          <td><RouterLink class="row-link cell-main" :to="`/repositories/${repository.id}`">{{ repository.name }}</RouterLink><span class="cell-sub mono">{{ shortId(repository.id) }}</span></td>
          <td><StatusBadge :value="repository.source_type === 'git' ? 'Git' : repository.source_type.toUpperCase()" /></td>
          <td><span class="cell-main mono">{{ repository.remote_url || repository.default_branch || "本地上传" }}</span><span class="cell-sub">由 {{ repository.created_by }} 创建</span></td>
          <td class="muted nowrap">{{ formatDate(repository.updated_at) }}</td>
          <td><div class="row-actions"><button v-if="canManage" class="icon-button" type="button" title="删除仓库" @click="remove(repository)"><Trash2 :size="16" /></button></div></td>
        </tr>
      </tbody>
    </table>
    <PaginationBar :total="total" :offset="offset" :limit="limit" @change="changePage" />
  </div>

  <ModalDialog :open="createOpen" title="新增仓库" @close="createOpen = false">
    <form id="repository-create" class="repository-form" @submit.prevent="createRepository">
      <div class="segmented source-segment" aria-label="来源类型">
        <button type="button" :class="{ active: form.mode === 'git' }" @click="form.mode = 'git'"><GitBranch :size="15" />Git</button>
        <button type="button" :class="{ active: form.mode === 'zip' }" @click="form.mode = 'zip'"><Archive :size="15" />ZIP 上传</button>
        <button type="button" :class="{ active: form.mode === 'local_upload' }" @click="form.mode = 'local_upload'"><FolderOpen :size="15" />目录</button>
      </div>
      <div class="field"><label for="repository-name">仓库名称</label><input id="repository-name" v-model="form.name" class="input" maxlength="255" required /></div>
      <template v-if="form.mode === 'git'">
        <div class="field"><label for="remote-url">Git URL</label><input id="remote-url" v-model="form.remoteUrl" class="input" type="url" placeholder="https://git.example.com/team/project.git" required /></div>
        <div class="field"><label for="default-branch">默认 Branch / Tag</label><input id="default-branch" v-model="form.defaultBranch" class="input" maxlength="255" required /></div>
        <div class="field"><label for="credential-reference">凭据引用（可选）</label><input id="credential-reference" v-model.trim="form.credentialRef" class="input mono" maxlength="255" autocomplete="off" /></div>
      </template>
      <div v-else-if="form.mode === 'zip'" class="field">
        <label for="zip-file">源码 ZIP</label>
        <label class="file-picker" for="zip-file"><Upload :size="20" /><span>{{ uploadFile?.name || "选择 ZIP 文件" }}</span><small v-if="uploadFile">{{ (uploadFile.size / 1024 / 1024).toFixed(1) }} MB</small></label>
        <input id="zip-file" class="visually-hidden" type="file" accept=".zip,application/zip" required @change="chooseFile" />
      </div>
      <div v-else class="field">
        <label for="directory-files">源码目录</label>
        <label class="file-picker" for="directory-files"><FolderOpen :size="20" /><span>{{ directoryFiles.length ? `${directoryFiles.length} 个文件` : "选择源码目录" }}</span><small v-if="directoryFiles.length">浏览器内打包为 ZIP</small></label>
        <input id="directory-files" class="visually-hidden" type="file" webkitdirectory multiple required @change="chooseDirectory" />
      </div>
      <div v-if="formError" class="inline-error">{{ formError }}</div>
    </form>
    <template #footer><button class="button button--secondary" type="button" @click="createOpen = false">取消</button><button class="button" type="submit" form="repository-create" :disabled="saving">{{ saving ? "正在处理" : form.mode === "git" ? "创建仓库" : "导入并创建" }}</button></template>
  </ModalDialog>
</template>

<style scoped>
.repository-form { display: grid; gap: 16px; }
.source-segment { width: 100%; }
.source-segment button { display: flex; flex: 1; align-items: center; justify-content: center; gap: 6px; }
.file-picker { display: flex; min-height: 72px; align-items: center; gap: 10px; padding: 14px; color: #51605a; background: #f8faf9; border: 1px dashed #b8c4be; border-radius: 6px; cursor: pointer; }
.file-picker span { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-picker small { color: var(--muted); }
.visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
@media (max-width: 620px) { .repositories-table { min-width: 700px; } }
</style>
