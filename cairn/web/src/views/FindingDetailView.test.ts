import { createPinia, setActivePinia } from "pinia";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuthStore } from "@/stores/auth";
import type { AuditRun, FindingDetail, FindingLocation, SourceFile } from "@/types/api";

const auditRunApi = vi.hoisted(() => ({ get: vi.fn() }));
const findingApi = vi.hoisted(() => ({ get: vi.fn() }));
const snapshotApi = vi.hoisted(() => ({ source: vi.fn() }));
const reportApi = vi.hoisted(() => ({
  artifactUrl: vi.fn((artifactId: string) => `/artifacts/${artifactId}`),
}));

vi.mock("@/api/resources", () => ({ auditRunApi, findingApi, reportApi, snapshotApi }));
vi.mock("@/components/CodeViewer.vue", () => ({
  default: {
    props: {
      code: { type: String, required: true },
      startLine: { type: Number, required: true },
      highlightLine: { type: Number, required: true },
    },
    template: `<pre
      data-testid="code-viewer"
      :data-start-line="startLine"
      :data-highlight-line="highlightLine"
    >{{ code }}</pre>`,
  },
}));

import FindingDetailView from "./FindingDetailView.vue";

const snapshotSha = "a".repeat(64);

const run: AuditRun = {
  id: "run-1",
  repository_id: "repository-1",
  source_request: {},
  snapshot_id: "snapshot-1",
  policy_id: "policy-1",
  policy_version: 1,
  status: "human_review",
  current_stage: "human_review",
  progress: 90,
  warning_count: 0,
  failure_code: null,
  failure_reason: null,
  created_by: "auditor",
  created_at: "2026-07-29T01:00:00Z",
  started_at: "2026-07-29T01:01:00Z",
  completed_at: null,
};

function location(overrides: Partial<FindingLocation> = {}): FindingLocation {
  return {
    id: "location-1",
    role: "sink",
    origin_kind: "source",
    file_path: "src/main/java/com/acme/Sink.java",
    source_path: "src/main/java/com/acme/Sink.java",
    start_line: 50,
    end_line: 52,
    symbol: "Sink.run",
    code_snippet: "dangerous(input);",
    container_path: null,
    entry_path: null,
    class_name: null,
    method_name: null,
    method_descriptor: null,
    bytecode_offset: null,
    decompiled_artifact_id: null,
    decompiled_start_line: null,
    decompiled_end_line: null,
    snapshot_sha: snapshotSha,
    ordinal: 0,
    ...overrides,
  };
}

function finding(locations: FindingLocation[]): FindingDetail {
  return {
    id: "finding-1",
    audit_run_id: run.id,
    fingerprint: "fingerprint-1",
    title: "命令注入",
    description: "不可信输入进入命令执行。",
    category: "injection",
    cwe_id: "CWE-78",
    owasp_category: "A03",
    severity: "high",
    confidence: "high",
    status: "awaiting_human_review",
    attack_preconditions: "攻击者可控制输入。",
    impact: "执行任意命令。",
    remediation: "使用安全 API。",
    runtime_verification: "unverified",
    discovered_by: "semantic-agent",
    first_seen_at: "2026-07-29T01:10:00Z",
    updated_at: "2026-07-29T01:11:00Z",
    locations,
    evidence: [],
    verifications: [],
    human_reviews: [],
  };
}

const sourceFile: SourceFile = {
  snapshot_id: "snapshot-1",
  snapshot_sha: snapshotSha,
  path: "src/main/java/com/acme/Sink.java",
  start_line: 10,
  end_line: 132,
  total_lines: 200,
  content: "class Sink { void run() {} }",
  truncated: false,
};

async function renderView(detail: FindingDetail) {
  findingApi.get.mockResolvedValue(detail);
  const pinia = createPinia();
  setActivePinia(pinia);
  useAuthStore().user = {
    id: "viewer-1",
    username: "viewer",
    role: "viewer",
    is_active: true,
    created_at: "2026-07-29T00:00:00Z",
    last_login_at: null,
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/findings/:id", component: FindingDetailView },
      { path: "/:pathMatch(.*)*", component: { template: "<div />" } },
    ],
  });
  await router.push(`/findings/${detail.id}`);
  await router.isReady();
  const wrapper = mount(FindingDetailView, { global: { plugins: [pinia, router] } });
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.clearAllMocks();
  auditRunApi.get.mockResolvedValue(run);
  snapshotApi.source.mockResolvedValue(sourceFile);
});

describe("FindingDetailView CodeLocationV2", () => {
  it("fetches and renders source only when the source location is complete", async () => {
    const source = location({ file_path: null });
    const wrapper = await renderView(finding([source]));

    expect(snapshotApi.source).toHaveBeenCalledOnce();
    expect(snapshotApi.source).toHaveBeenCalledWith(
      "snapshot-1",
      "src/main/java/com/acme/Sink.java",
      10,
      132,
    );
    const viewer = wrapper.get('[data-testid="code-viewer"]');
    expect(viewer.text()).toContain(sourceFile.content);
    expect(viewer.attributes("data-start-line")).toBe("10");
    expect(viewer.attributes("data-highlight-line")).toBe("50");
    wrapper.unmount();
  });

  it("renders bytecode identity without requesting snapshot source", async () => {
    const bytecode = location({
      origin_kind: "bytecode",
      file_path: null,
      source_path: null,
      start_line: null,
      end_line: null,
      code_snippet: null,
      symbol: null,
      container_path: "build/libs/app.jar",
      entry_path: "BOOT-INF/lib/core.jar!/com/acme/Sink.class",
      class_name: "com.acme.Sink",
      method_name: "run",
      method_descriptor: "(Ljava/lang/String;)V",
      bytecode_offset: 0,
    });
    const wrapper = await renderView(finding([bytecode]));

    expect(snapshotApi.source).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="code-viewer"]').exists()).toBe(false);
    expect(wrapper.text()).toContain("build/libs/app.jar!/BOOT-INF/lib/core.jar!/com/acme/Sink.class");
    expect(wrapper.text()).toContain("com.acme.Sink");
    expect(wrapper.text()).toContain("run");
    expect(wrapper.text()).toContain("(Ljava/lang/String;)V");
    expect(wrapper.text()).toContain("字节码偏移0");
    wrapper.unmount();
  });

  it("links a decompiled location to its Artifact", async () => {
    const decompiled = location({
      origin_kind: "decompiled",
      file_path: null,
      source_path: null,
      start_line: null,
      end_line: null,
      code_snippet: null,
      container_path: "vendor/service.jar",
      entry_path: "com/vendor/Service.class",
      class_name: "com.vendor.Service",
      method_name: "execute",
      method_descriptor: "()V",
      bytecode_offset: 24,
      decompiled_artifact_id: "artifact-cfr-1",
      decompiled_start_line: 30,
      decompiled_end_line: 38,
    });
    const wrapper = await renderView(finding([decompiled]));

    expect(snapshotApi.source).not.toHaveBeenCalled();
    expect(reportApi.artifactUrl).toHaveBeenCalledWith("artifact-cfr-1");
    const artifact = wrapper.get(".location-artifact");
    expect(artifact.attributes("href")).toBe("/artifacts/artifact-cfr-1");
    expect(wrapper.text()).toContain("反编译第 30–38 行");
    wrapper.unmount();
  });

  it("does not mount CodeViewer or perform arithmetic for nullable source fields", async () => {
    const incompleteSource = location({
      file_path: null,
      source_path: null,
      start_line: null,
      end_line: null,
      code_snippet: null,
      symbol: null,
    });
    const wrapper = await renderView(finding([incompleteSource]));

    expect(snapshotApi.source).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="code-viewer"]').exists()).toBe(false);
    expect(wrapper.text()).toContain("源码定位信息不完整");
    expect(wrapper.text()).toContain("未命名位置");
    wrapper.unmount();
  });
});
