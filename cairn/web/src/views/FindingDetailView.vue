<script setup lang="ts">
import { ArrowLeft, ExternalLink, GitMerge, ShieldCheck } from "@lucide/vue";
import { computed, onMounted, ref } from "vue";
import { useRoute } from "vue-router";

import { auditRunApi, findingApi, reportApi, snapshotApi } from "@/api/resources";
import CodeViewer from "@/components/CodeViewer.vue";
import SeverityBadge from "@/components/SeverityBadge.vue";
import StatePanel from "@/components/StatePanel.vue";
import StatusBadge from "@/components/StatusBadge.vue";
import { useAuthStore } from "@/stores/auth";
import type { FindingDetail, FindingLocation } from "@/types/api";
import { errorMessage, formatDate } from "@/utils";

const route = useRoute();
const auth = useAuthStore();
const finding = ref<FindingDetail | null>(null);
const selectedLocation = ref<FindingLocation | null>(null);
const sourceCode = ref("");
const sourceStartLine = ref(1);
const sourceNotice = ref("");
const loading = ref(true);
const error = ref("");
const snapshotId = ref("");
let sourceRequestVersion = 0;

const canReview = computed(() => auth.can(["admin", "auditor", "reviewer"]) && finding.value?.status === "awaiting_human_review");
const selectedSourceHasLines = computed(() => {
  const location = selectedLocation.value;
  return location?.origin_kind === "source"
    && location.start_line !== null
    && location.end_line !== null;
});
const selectedSourceHighlightLine = computed(() => {
  const location = selectedLocation.value;
  return location?.origin_kind === "source" && location.start_line !== null
    ? location.start_line
    : 1;
});

function sourcePath(location: FindingLocation): string | null {
  return location.source_path ?? location.file_path;
}

function logicalPath(location: FindingLocation): string {
  if (location.container_path && location.entry_path) {
    return `${location.container_path}!/${location.entry_path}`;
  }
  return location.entry_path ?? sourcePath(location) ?? location.container_path ?? "-";
}

function locationName(location: FindingLocation): string {
  if (location.symbol) return location.symbol;
  if (location.class_name) return location.class_name;
  const path = logicalPath(location);
  return path === "-" ? "未命名位置" : (path.split("/").at(-1) || path);
}

function lineRange(start: number | null, end: number | null, prefix = "第 "): string | null {
  if (start === null || end === null) return null;
  return start === end ? `${prefix}${start} 行` : `${prefix}${start}–${end} 行`;
}

function locationDetail(location: FindingLocation): string {
  if (location.origin_kind === "source") {
    return lineRange(location.start_line, location.end_line) ?? "源码行号不可用";
  }
  if (location.decompiled_start_line !== null && location.decompiled_end_line !== null) {
    return lineRange(location.decompiled_start_line, location.decompiled_end_line, "反编译第 ")!;
  }
  if (location.bytecode_offset !== null) return `字节码偏移 ${location.bytecode_offset}`;
  return {
    bytecode: "字节码位置",
    config: "配置位置",
    decompiled: "反编译位置",
  }[location.origin_kind];
}

async function loadSource(): Promise<void> {
  const requestVersion = ++sourceRequestVersion;
  const location = selectedLocation.value;
  sourceNotice.value = "";
  sourceCode.value = "";
  sourceStartLine.value = 1;
  if (!location || location.origin_kind !== "source") return;

  sourceCode.value = location.code_snippet ?? "";
  if (location.start_line !== null) sourceStartLine.value = location.start_line;
  if (!snapshotId.value) {
    sourceNotice.value = "当前运行未关联可读取的 Snapshot，显示 Finding 中保存的代码片段。";
    return;
  }
  const path = sourcePath(location);
  if (!path || location.start_line === null || location.end_line === null) {
    sourceNotice.value = "该位置缺少完整源码定位信息。";
    return;
  }
  try {
    const source = await snapshotApi.source(
      snapshotId.value,
      path,
      Math.max(1, location.start_line - 40),
      location.end_line + 80,
    );
    if (requestVersion !== sourceRequestVersion) return;
    sourceCode.value = source.content;
    sourceStartLine.value = source.start_line;
    if (source.truncated) sourceNotice.value = "文件超过浏览上限，当前显示受限内容。";
  } catch {
    if (requestVersion !== sourceRequestVersion) return;
    sourceNotice.value = "完整源码读取端点暂不可用，显示 Finding 中保存的可追溯代码片段。";
  }
}

function selectLocation(location: FindingLocation): void {
  selectedLocation.value = location;
  void loadSource();
}

async function load(): Promise<void> {
  loading.value = true;
  error.value = "";
  try {
    finding.value = await findingApi.get(String(route.params.id));
    selectedLocation.value = finding.value.locations.slice().sort((a, b) => a.ordinal - b.ordinal)[0] ?? null;
    const run = await auditRunApi.get(finding.value.audit_run_id);
    snapshotId.value = run.snapshot_id || "";
    await loadSource();
  } catch (reason) {
    error.value = errorMessage(reason);
  } finally {
    loading.value = false;
  }
}

onMounted(load);
</script>

<template>
  <StatePanel v-if="loading" kind="loading" />
  <StatePanel v-else-if="error || !finding" kind="error" :message="error || '漏洞不存在'" retryable @retry="load" />
  <template v-else>
    <RouterLink class="back-link" :to="{ path: '/findings', query: { audit_run_id: finding.audit_run_id } }"><ArrowLeft :size="15" />返回漏洞列表</RouterLink>
    <header class="finding-header">
      <div><div class="finding-title"><SeverityBadge :value="finding.severity" /><h1>{{ finding.title }}</h1></div><p>{{ finding.cwe_id }} · {{ finding.category }}<template v-if="finding.owasp_category"> · {{ finding.owasp_category }}</template></p></div>
      <div class="finding-header__status"><StatusBadge :value="finding.status" /><StatusBadge :value="finding.runtime_verification" /><RouterLink v-if="canReview" class="button" :to="{ path: '/review', query: { finding: finding.id } }"><ShieldCheck :size="15" />复核漏洞</RouterLink></div>
    </header>

    <dl class="detail-grid">
      <div class="detail-item"><dt>置信度</dt><dd>{{ finding.confidence }}</dd></div>
      <div class="detail-item"><dt>发现来源</dt><dd>{{ finding.discovered_by }}</dd></div>
      <div class="detail-item"><dt>首次发现</dt><dd>{{ formatDate(finding.first_seen_at) }}</dd></div>
      <div class="detail-item"><dt>AuditRun</dt><dd><RouterLink class="row-link mono" :to="`/audit-runs/${finding.audit_run_id}`">{{ finding.audit_run_id }}</RouterLink></dd></div>
      <div class="detail-item"><dt>Snapshot</dt><dd class="mono">{{ snapshotId || "-" }}</dd></div>
      <div class="detail-item"><dt>Fingerprint</dt><dd class="mono">{{ finding.fingerprint }}</dd></div>
    </dl>

    <section class="finding-copy-grid">
      <article><h2>漏洞说明</h2><p>{{ finding.description }}</p></article>
      <article><h2>攻击前提</h2><p>{{ finding.attack_preconditions }}</p></article>
      <article><h2>影响</h2><p>{{ finding.impact }}</p></article>
      <article><h2>修复建议</h2><p>{{ finding.remediation }}</p></article>
    </section>

    <div class="section-title"><h2>调用链与源码定位</h2><p>{{ finding.locations.length }} 个位置</p></div>
    <section class="source-layout">
      <ol class="location-list">
        <li v-for="location in finding.locations.slice().sort((a,b) => a.ordinal - b.ordinal)" :key="location.id">
          <button type="button" :class="{ active: selectedLocation?.id === location.id }" @click="selectLocation(location)">
            <span class="location-role"><GitMerge :size="13" />{{ location.role }}</span><strong>{{ locationName(location) }}</strong><small>{{ logicalPath(location) }}<template v-if="location.bytecode_offset !== null"> · offset {{ location.bytecode_offset }}</template><template v-else-if="location.start_line !== null">:{{ location.start_line }}</template></small>
          </button>
        </li>
      </ol>
      <div class="source-pane">
        <header v-if="selectedLocation"><div><strong>{{ logicalPath(selectedLocation) }}</strong><span>{{ locationDetail(selectedLocation) }}</span></div><span class="mono">{{ selectedLocation.snapshot_sha.slice(0, 12) }}</span></header>
        <template v-if="selectedLocation?.origin_kind === 'source'">
          <div v-if="sourceNotice" class="source-notice">{{ sourceNotice }}</div>
          <CodeViewer v-if="selectedSourceHasLines" :code="sourceCode" :start-line="sourceStartLine" :highlight-line="selectedSourceHighlightLine" />
          <div v-else class="location-empty">源码定位信息不完整</div>
        </template>
        <section v-else-if="selectedLocation" class="location-metadata">
          <dl>
            <div><dt>逻辑归档路径</dt><dd class="mono">{{ logicalPath(selectedLocation) }}</dd></div>
            <div><dt>容器路径</dt><dd class="mono">{{ selectedLocation.container_path ?? '-' }}</dd></div>
            <div><dt>归档条目</dt><dd class="mono">{{ selectedLocation.entry_path ?? '-' }}</dd></div>
            <div><dt>类</dt><dd class="mono">{{ selectedLocation.class_name ?? '-' }}</dd></div>
            <div><dt>方法</dt><dd class="mono">{{ selectedLocation.method_name ?? '-' }}</dd></div>
            <div><dt>方法描述符</dt><dd class="mono">{{ selectedLocation.method_descriptor ?? '-' }}</dd></div>
            <div><dt>字节码偏移</dt><dd class="mono">{{ selectedLocation.bytecode_offset ?? '-' }}</dd></div>
          </dl>
          <a v-if="selectedLocation.decompiled_artifact_id" class="button button--secondary location-artifact" :href="reportApi.artifactUrl(selectedLocation.decompiled_artifact_id)" target="_blank" rel="noopener noreferrer"><ExternalLink :size="15" />下载反编译 Artifact</a>
        </section>
        <div v-else class="location-empty">暂无定位信息</div>
      </div>
    </section>

    <div class="evidence-grid">
      <section class="panel">
        <header class="panel__header"><h2>证据</h2><span class="muted">{{ finding.evidence.length }}</span></header>
        <div v-if="!finding.evidence.length" class="empty-inline">暂无证据</div>
        <ul v-else class="record-list"><li v-for="evidence in finding.evidence" :key="evidence.id"><div><strong>{{ evidence.type }}</strong><p>{{ evidence.summary }}</p><small>{{ formatDate(evidence.created_at) }}</small></div><a v-if="evidence.artifact_id" class="icon-button" :href="reportApi.artifactUrl(evidence.artifact_id)" target="_blank" title="查看 Artifact"><ExternalLink :size="15" /></a></li></ul>
      </section>
      <section class="panel">
        <header class="panel__header"><h2>独立验证</h2><span class="muted">{{ finding.verifications.length }}</span></header>
        <div v-if="!finding.verifications.length" class="empty-inline">暂无独立验证</div>
        <ul v-else class="record-list"><li v-for="verification in finding.verifications" :key="verification.id"><div><div class="record-heading"><strong>{{ verification.method }}</strong><StatusBadge :value="verification.verdict" /></div><p>{{ verification.reasoning }}</p><small>{{ verification.verifier }} · {{ formatDate(verification.created_at) }}</small></div></li></ul>
      </section>
    </div>

    <template v-if="finding.human_reviews.length">
      <div class="section-title"><h2>人工复核记录</h2><p>{{ finding.human_reviews.length }} 条</p></div>
      <section class="table-wrap"><table class="data-table"><thead><tr><th>结论</th><th>严重性调整</th><th>意见</th><th>复核人</th><th>时间</th></tr></thead><tbody><tr v-for="review in finding.human_reviews" :key="review.id"><td><StatusBadge :value="review.verdict" /></td><td><SeverityBadge :value="review.original_severity" /> → <SeverityBadge :value="review.final_severity" /></td><td>{{ review.comment }}</td><td>{{ review.reviewer_id }}</td><td>{{ formatDate(review.reviewed_at) }}</td></tr></tbody></table></section>
    </template>
  </template>
</template>

<style scoped>
.back-link { display: inline-flex; align-items: center; gap: 5px; margin-bottom: 12px; color: var(--muted); font-size: 11px; text-decoration: none; }
.finding-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 22px; margin-bottom: 20px; }
.finding-title { display: flex; align-items: flex-start; gap: 10px; }
.finding-title h1 { max-width: 820px; margin: -2px 0 0; font-size: 22px; line-height: 1.35; overflow-wrap: anywhere; }
.finding-header p { margin: 7px 0 0; color: var(--muted); font-size: 11px; }
.finding-header__status { display: flex; flex: 0 0 auto; flex-wrap: wrap; align-items: center; justify-content: flex-end; gap: 7px; }
.finding-copy-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 1px; margin-top: 14px; overflow: hidden; background: var(--line); border: 1px solid var(--line); border-radius: 7px; }
.finding-copy-grid article { min-width: 0; padding: 15px; background: var(--surface); }
.finding-copy-grid h2 { margin-bottom: 7px; color: #425049; font-size: 11px; }
.finding-copy-grid p { margin: 0; color: #313d37; font-size: 12px; line-height: 1.65; white-space: pre-wrap; overflow-wrap: anywhere; }
.source-layout { display: grid; grid-template-columns: 260px minmax(0, 1fr); gap: 10px; }
.location-list { max-height: 442px; margin: 0; padding: 0; overflow-y: auto; background: var(--surface); border: 1px solid var(--line); border-radius: 7px; list-style: none; }
.location-list li { border-bottom: 1px solid var(--line); }
.location-list li:last-child { border-bottom: 0; }
.location-list button { display: grid; width: 100%; gap: 5px; padding: 12px; text-align: left; color: #36423c; background: transparent; border: 0; border-left: 3px solid transparent; cursor: pointer; }
.location-list button:hover { background: var(--surface-alt); }
.location-list button.active { background: var(--accent-soft); border-left-color: var(--accent); }
.location-role { display: flex; align-items: center; gap: 5px; color: var(--accent); font-size: 9px; font-weight: 700; text-transform: uppercase; }
.location-list strong, .location-list small { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.location-list strong { font-size: 11px; }
.location-list small { color: var(--muted); font-size: 9px; }
.source-pane { min-width: 0; }
.source-pane > header { display: flex; min-height: 48px; align-items: center; justify-content: space-between; gap: 10px; padding: 9px 13px; background: #f7f9f8; border: 1px solid var(--line); border-bottom: 0; border-radius: 7px 7px 0 0; }
.source-pane > header div { display: grid; min-width: 0; gap: 3px; }
.source-pane > header strong { overflow: hidden; font-size: 11px; text-overflow: ellipsis; white-space: nowrap; }
.source-pane > header span { color: var(--muted); font-size: 9px; }
.source-notice { padding: 7px 12px; color: #765b27; background: var(--warning-soft); border: 1px solid #ead9a8; border-bottom: 0; font-size: 10px; }
.location-empty { display: grid; min-height: 380px; place-items: center; color: var(--muted); background: var(--surface); border: 1px solid var(--line); border-radius: 0 0 7px 7px; font-size: 11px; }
.location-metadata { min-height: 380px; padding: 16px; background: var(--surface); border: 1px solid var(--line); border-radius: 0 0 7px 7px; }
.location-metadata dl { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 1px; margin: 0; overflow: hidden; background: var(--line); border: 1px solid var(--line); border-radius: 6px; }
.location-metadata dl > div { min-width: 0; padding: 11px 12px; background: #fff; }
.location-metadata dt { margin-bottom: 5px; color: var(--muted); font-size: 9px; }
.location-metadata dd { margin: 0; color: #354139; font-size: 11px; overflow-wrap: anywhere; }
.location-artifact { margin-top: 14px; }
.evidence-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 26px; }
.record-list { margin: 0; padding: 0; list-style: none; }
.record-list li { display: flex; align-items: flex-start; justify-content: space-between; gap: 8px; padding: 12px 14px; border-bottom: 1px solid var(--line); }
.record-list li:last-child { border-bottom: 0; }
.record-list li > div { min-width: 0; flex: 1; }
.record-list strong { color: #3a4740; font-size: 10px; }
.record-list p { margin: 5px 0; color: #55615b; font-size: 11px; line-height: 1.55; white-space: pre-wrap; overflow-wrap: anywhere; }
.record-list small { color: var(--subtle); font-size: 9px; }
.record-heading { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
@media (max-width: 880px) { .source-layout { grid-template-columns: 1fr; } .location-list { display: flex; max-height: none; overflow-x: auto; } .location-list li { min-width: 210px; border-right: 1px solid var(--line); border-bottom: 0; } }
@media (max-width: 680px) { .finding-header { display: grid; } .finding-header__status { justify-content: flex-start; } .finding-copy-grid, .evidence-grid, .location-metadata dl { grid-template-columns: 1fr; } }
</style>
