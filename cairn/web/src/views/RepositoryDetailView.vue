<script setup lang="ts">
import { ArrowLeft, FileArchive, FolderOpen, GitCommitHorizontal, Play, Upload } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { auditRunApi, policyApi, repositoryApi, snapshotApi } from "@/api/resources";
import ModalDialog from "@/components/ModalDialog.vue";
import PageHeader from "@/components/PageHeader.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { AuditPolicy, AuditRun, Repository, Snapshot } from "@/types/api";
import { archiveDirectory } from "@/utils/sourceArchive";
import { errorMessage, formatBytes, formatDate, shortId } from "@/utils";

const route = useRoute();
const router = useRouter();
const auth = useAuthStore();
const repository = ref<Repository | null>(null);
const snapshots = ref<Snapshot[]>([]);
const selectedSnapshot = ref<Snapshot | null>(null);
const runs = ref<AuditRun[]>([]);
const policies = ref<AuditPolicy[]>([]);
const loading = ref(true);
const error = ref("");
const snapshotOpen = ref(false);
const auditOpen = ref(false);
const busy = ref(false);
const actionError = ref("");
const gitRef = ref("");
const uploadFile = ref<File | null>(null);
const directoryFiles = ref<File[]>([]);
const selectedPolicy = ref("");

const repositoryId = computed(() => String(route.params.id));
const canManage = computed(() => auth.can(["admin", "auditor"]));

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    const [repo, snapshotPage, runPage, policyPage] = await Promise.all([
      repositoryApi.get(repositoryId.value),
      snapshotApi.list(repositoryId.value, { limit: 100 }),
      auditRunApi.list({ repository_id: repositoryId.value, limit: 20 }),
      policyApi.list({ active: true, limit: 100 }),
    ]);
    repository.value = repo;
    runs.value = runPage.items;
    policies.value = policyPage.items;
    selectedPolicy.value ||= policyPage.items[0]?.id || "";
    gitRef.value ||= repo.default_branch || "main";

    const snapshotId = typeof route.query.snapshot === "string" ? route.query.snapshot : "";
    snapshots.value = snapshotPage.items;
    if (snapshotId) selectedSnapshot.value = snapshots.value.find((item) => item.id === snapshotId) ?? null;
    selectedSnapshot.value ||= snapshots.value[0] ?? null;
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

function chooseFile(event: Event): void {
  uploadFile.value = (event.target as HTMLInputElement).files?.[0] ?? null;
}

function chooseDirectory(event: Event): void {
  directoryFiles.value = Array.from((event.target as HTMLInputElement).files ?? []);
}

async function createSnapshot(): Promise<void> {
  if (!repository.value) return;
  busy.value = true;
  actionError.value = "";
  try {
    let snapshot: Snapshot;
    if (repository.value.source_type === "git") {
      snapshot = await repositoryApi.createGitSnapshot(repository.value.id, gitRef.value.trim());
    } else {
      const sourceType = repository.value.source_type === "local_upload" ? "local_upload" : "zip";
      const sourceFile = sourceType === "local_upload" ? await archiveDirectory(directoryFiles.value) : uploadFile.value;
      if (!sourceFile) throw new Error("请选择 ZIP 文件");
      const upload = await repositoryApi.upload(sourceFile, sourceType);
      snapshot = await repositoryApi.createUploadSnapshot(repository.value.id, upload.id);
    }
    selectedSnapshot.value = snapshot;
    snapshots.value = [snapshot, ...snapshots.value.filter((item) => item.id !== snapshot.id)];
    snapshotOpen.value = false;
    await router.replace({ query: { snapshot: snapshot.id } });
  } catch (reason) {
    actionError.value = errorMessage(reason);
  } finally {
    busy.value = false;
  }
}

async function startAudit(): Promise<void> {
  if (!selectedSnapshot.value || !selectedPolicy.value) return;
  busy.value = true;
  actionError.value = "";
  try {
    const run = await auditRunApi.create({
      repository_id: repositoryId.value,
      policy_id: selectedPolicy.value,
      source_request: { type: "snapshot", snapshot_id: selectedSnapshot.value.id },
    });
    auditOpen.value = false;
    await router.push(`/audit-runs/${run.id}`);
  } catch (reason) {
    actionError.value = errorMessage(reason);
  } finally {
    busy.value = false;
  }
}

onMounted(load);
</script>

<template>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error || !repository" kind="error" :message="error || '仓库不存在'" retryable @retry="load" />
  <template v-else>
    <RouterLink class="back-link" to="/repositories"><ArrowLeft :size="15" />返回仓库</RouterLink>
    <PageHeader :title="repository.name" :description="repository.remote_url || '本地上传源码仓库'">
      <template #actions>
        <button v-if="canManage" class="button button--secondary" type="button" @click="snapshotOpen = true"><GitCommitHorizontal :size="16" />创建 Snapshot</button>
        <button v-if="canManage" class="button" type="button" :disabled="!selectedSnapshot" @click="auditOpen = true"><Play :size="16" />发起审计</button>
      </template>
    </PageHeader>

    <dl class="detail-grid">
      <div class="detail-item"><dt>来源类型</dt><dd>{{ repository.source_type.toUpperCase() }}</dd></div>
      <div class="detail-item"><dt>默认分支</dt><dd>{{ repository.default_branch || "-" }}</dd></div>
      <div class="detail-item"><dt>凭据状态</dt><dd>{{ repository.credential_ref ? "已配置" : "未配置" }}</dd></div>
      <div class="detail-item"><dt>创建者</dt><dd>{{ repository.created_by }}</dd></div>
      <div class="detail-item"><dt>创建时间</dt><dd>{{ formatDate(repository.created_at) }}</dd></div>
      <div class="detail-item"><dt>仓库 ID</dt><dd class="mono">{{ repository.id }}</dd></div>
    </dl>

    <div class="section-title"><h2>源码 Snapshot</h2><p>{{ snapshots.length ? `共 ${snapshots.length} 个可见快照` : "尚未创建快照" }}</p></div>
    <StatePanel v-if="!selectedSnapshot" kind="empty" title="尚未固定源码" message="创建 Snapshot 后才可发起审计。" />
    <section v-else class="snapshot-band">
      <div class="snapshot-selector">
        <label for="snapshot-select">当前 Snapshot</label>
        <select id="snapshot-select" v-model="selectedSnapshot" class="select">
          <option v-for="snapshot in snapshots" :key="snapshot.id" :value="snapshot">{{ shortId(snapshot.id) }} · {{ snapshot.branch_or_tag || snapshot.content_sha256.slice(0, 10) }}</option>
        </select>
      </div>
      <dl class="detail-grid snapshot-details">
        <div class="detail-item"><dt>状态</dt><dd><StatusBadge :value="selectedSnapshot.status" /></dd></div>
        <div class="detail-item"><dt>Commit / 内容哈希</dt><dd class="mono">{{ selectedSnapshot.commit_sha || selectedSnapshot.content_sha256 }}</dd></div>
        <div class="detail-item"><dt>Java 文件</dt><dd>{{ selectedSnapshot.java_file_count }} / {{ selectedSnapshot.file_count }}</dd></div>
        <div class="detail-item"><dt>源码大小</dt><dd>{{ formatBytes(selectedSnapshot.total_bytes) }}</dd></div>
        <div class="detail-item"><dt>构建系统</dt><dd>{{ selectedSnapshot.build_system }}</dd></div>
        <div class="detail-item"><dt>Java 版本</dt><dd>{{ selectedSnapshot.java_version || "待识别" }}</dd></div>
      </dl>
    </section>

    <div class="section-title"><h2>历史审计</h2><p>最近 {{ runs.length }} 次</p></div>
    <StatePanel v-if="!runs.length" kind="empty" title="暂无审计记录" />
    <div v-else class="table-wrap">
      <table class="data-table audit-history"><thead><tr><th style="width: 28%">任务</th><th style="width: 23%">状态</th><th>风险概览</th><th style="width: 24%">创建时间</th></tr></thead><tbody>
        <tr v-for="run in runs" :key="run.id"><td><RouterLink class="row-link cell-main mono" :to="`/audit-runs/${run.id}`">{{ shortId(run.id) }}</RouterLink><span class="cell-sub">策略 v{{ run.policy_version }}</span></td><td><StatusBadge :value="run.status" /></td><td><SeverityBadge value="info" /> <span class="muted">{{ run.warning_count }} 条警告</span></td><td class="muted nowrap">{{ formatDate(run.created_at) }}</td></tr>
      </tbody></table>
    </div>

    <ModalDialog :open="snapshotOpen" title="创建源码 Snapshot" @close="snapshotOpen = false">
      <form id="snapshot-form" class="action-form" @submit.prevent="createSnapshot">
        <div v-if="repository.source_type === 'git'" class="field"><label for="git-ref">Branch / Tag / Commit</label><input id="git-ref" v-model="gitRef" class="input" maxlength="255" required /></div>
        <div v-else-if="repository.source_type === 'zip'" class="field"><label for="source-upload">源码 ZIP</label><label class="upload-row" for="source-upload"><FileArchive :size="20" /><span>{{ uploadFile?.name || "选择 ZIP 文件" }}</span><Upload :size="16" /></label><input id="source-upload" class="visually-hidden" type="file" accept=".zip,application/zip" required @change="chooseFile" /></div>
        <div v-else class="field"><label for="source-directory">源码目录</label><label class="upload-row" for="source-directory"><FolderOpen :size="20" /><span>{{ directoryFiles.length ? `${directoryFiles.length} 个文件` : "选择源码目录" }}</span><Upload :size="16" /></label><input id="source-directory" class="visually-hidden" type="file" webkitdirectory multiple required @change="chooseDirectory" /></div>
        <div v-if="actionError" class="inline-error">{{ actionError }}</div>
      </form>
      <template #footer><button class="button button--secondary" type="button" @click="snapshotOpen = false">取消</button><button class="button" type="submit" form="snapshot-form" :disabled="busy">{{ busy ? "正在处理" : "创建 Snapshot" }}</button></template>
    </ModalDialog>

    <ModalDialog :open="auditOpen" title="发起审计" @close="auditOpen = false">
      <form id="audit-form" class="action-form" @submit.prevent="startAudit">
        <div class="field"><label>源码 Snapshot</label><input class="input mono" :value="selectedSnapshot?.id" disabled /></div>
        <div class="field"><label for="policy">审计策略</label><select id="policy" v-model="selectedPolicy" class="select" required><option disabled value="">请选择策略</option><option v-for="policy in policies" :key="policy.id" :value="policy.id">{{ policy.name }} · v{{ policy.version }} · 动态验证 {{ policy.dynamic_verification }}</option></select></div>
        <div v-if="!policies.length" class="notice">没有可用的活动策略，请联系管理员创建策略。</div>
        <div v-if="actionError" class="inline-error">{{ actionError }}</div>
      </form>
      <template #footer><button class="button button--secondary" type="button" @click="auditOpen = false">取消</button><button class="button" type="submit" form="audit-form" :disabled="busy || !selectedPolicy">{{ busy ? "正在创建" : "发起审计" }}</button></template>
    </ModalDialog>
  </template>
</template>

<style scoped>
.back-link { display: inline-flex; align-items: center; gap: 5px; margin-bottom: 12px; color: var(--muted); font-size: 11px; text-decoration: none; }
.back-link:hover { color: var(--accent); }
.snapshot-band { display: grid; gap: 11px; }
.snapshot-selector { display: flex; align-items: center; gap: 10px; }
.snapshot-selector label { color: var(--muted); font-size: 11px; }
.snapshot-selector .select { max-width: 390px; }
.snapshot-details .detail-item:nth-child(2) dd { font-size: 10px; }
.action-form { display: grid; gap: 15px; }
.upload-row { display: flex; min-height: 62px; align-items: center; gap: 10px; padding: 12px; color: var(--muted); background: var(--surface-alt); border: 1px dashed var(--line-strong); border-radius: 6px; cursor: pointer; }
.upload-row span { min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.visually-hidden { position: absolute; width: 1px; height: 1px; overflow: hidden; clip: rect(0 0 0 0); }
@media (max-width: 620px) { .snapshot-selector { align-items: stretch; flex-direction: column; } .snapshot-selector .select { max-width: none; } .audit-history { min-width: 640px; } }
</style>
