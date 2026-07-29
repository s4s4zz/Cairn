import { createPinia, setActivePinia } from "pinia";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuthStore } from "@/stores/auth";
import type { AuditCoverage, AuditRun, AuditRunEventSnapshot, AuditTask, Report } from "@/types/api";

const auditRunApi = vi.hoisted(() => ({
  get: vi.fn(),
  tasks: vi.fn(),
  coverage: vi.fn(),
  cancel: vi.fn(),
  retry: vi.fn(),
  remove: vi.fn(),
}));
const reportApi = vi.hoisted(() => ({
  list: vi.fn(),
  generate: vi.fn(),
  downloadUrl: vi.fn((id: string, format: string) => `/api/v1/reports/${id}?format=${format}`),
}));
const stream = vi.hoisted(() => ({
  callback: undefined as ((event: AuditRunEventSnapshot) => void) | undefined,
  connect: vi.fn(),
  disconnect: vi.fn(),
}));

vi.mock("@/api/resources", () => ({ auditRunApi, reportApi }));
vi.mock("@/composables/useAuditRunEvents", async () => {
  const { ref } = await import("vue");
  return {
    useAuditRunEvents: (_id: string, callback: (event: AuditRunEventSnapshot) => void) => {
      stream.callback = callback;
      return { state: ref("connected"), connect: stream.connect, disconnect: stream.disconnect };
    },
  };
});

import AuditRunDetailView from "./AuditRunDetailView.vue";

const run: AuditRun = {
  id: "run-12345678",
  repository_id: "repository-1",
  source_request: {},
  snapshot_id: "snapshot-1",
  policy_id: "policy-1",
  policy_version: 3,
  status: "human_review",
  current_stage: "human_review",
  progress: 90,
  warning_count: 1,
  failure_code: null,
  failure_reason: null,
  created_by: "auditor",
  created_at: "2026-07-29T01:00:00Z",
  started_at: "2026-07-29T01:01:00Z",
  completed_at: null,
};

const coverage: AuditCoverage = {
  audit_run_id: run.id,
  modules_total: 1,
  modules_analyzed: 1,
  java_files_total: 2,
  java_files_analyzed: 2,
  entrypoints_total: 1,
  entrypoints_analyzed: 1,
  sensitive_sinks_total: 1,
  sensitive_sinks_analyzed: 1,
  build_status: "success",
  static_tools_completed: {},
  skipped_paths: [],
  unsupported_components: [],
  coverage_warnings: [],
  updated_at: "2026-07-29T01:10:00Z",
};

const report: Report = {
  id: "report-12345678",
  audit_run_id: run.id,
  version: 2,
  summary_json: {},
  html_artifact_id: "html-1",
  json_artifact_id: "json-1",
  sarif_artifact_id: "sarif-1",
  generated_at: "2026-07-29T02:00:00Z",
};

function task(workerName: string, status: AuditTask["status"] = "running"): AuditTask {
  return {
    id: `task-${workerName}`,
    audit_run_id: run.id,
    type: "build",
    scope_key: "deterministic:build",
    scope: {},
    status,
    worker_name: workerName,
    attempt: 1,
    max_attempts: 2,
    timeout_seconds: 900,
    error_code: null,
    error_detail: null,
    started_at: "2026-07-29T01:02:00Z",
    finished_at: status === "succeeded" ? "2026-07-29T01:03:00Z" : null,
    created_at: "2026-07-29T01:01:30Z",
  };
}

async function renderView() {
  const pinia = createPinia();
  setActivePinia(pinia);
  useAuthStore().user = {
    id: "admin-1", username: "admin", role: "admin", is_active: true,
    created_at: "2026-07-29T00:00:00Z", last_login_at: null,
  };
  const router = createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/audit-runs/:id", component: AuditRunDetailView },
      { path: "/:pathMatch(.*)*", component: { template: "<div />" } },
    ],
  });
  await router.push(`/audit-runs/${run.id}`);
  await router.isReady();
  const wrapper = mount(AuditRunDetailView, { global: { plugins: [pinia, router] } });
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.clearAllMocks();
  stream.callback = undefined;
  auditRunApi.get.mockResolvedValue(run);
  auditRunApi.tasks.mockResolvedValue({ items: [task("worker-alpha")], meta: { limit: 500, offset: 0, total: 1 } });
  auditRunApi.coverage.mockResolvedValue(coverage);
  auditRunApi.remove.mockResolvedValue(undefined);
  reportApi.list.mockResolvedValue({ items: [report], meta: { limit: 1, offset: 0, total: 1 } });
  reportApi.generate.mockResolvedValue({ ...report, id: "report-new", version: 3 });
});

describe("AuditRunDetailView", () => {
  it("loads real tasks and an existing report, then serializes SSE task refreshes", async () => {
    const wrapper = await renderView();

    expect(auditRunApi.tasks).toHaveBeenCalledWith(run.id);
    expect(reportApi.list).toHaveBeenCalledWith({ audit_run_id: run.id, limit: 1 });
    expect(wrapper.text()).toContain("worker-alpha");
    expect(wrapper.text()).toContain("报告 v2");

    let resolveRefresh!: (page: { items: AuditTask[]; meta: { limit: number; offset: number; total: number } }) => void;
    auditRunApi.tasks
      .mockReturnValueOnce(new Promise((resolve) => { resolveRefresh = resolve; }))
      .mockResolvedValueOnce({
        items: [task("worker-gamma", "succeeded")],
        meta: { limit: 500, offset: 0, total: 1 },
      });
    const snapshot: AuditRunEventSnapshot = {
      audit_run_id: run.id,
      status: "human_review",
      current_stage: "human_review",
      progress: 92,
      warning_count: 1,
      failure_code: null,
      failure_reason: null,
      task_counts: { succeeded: 1 },
      finding_counts: {},
      coverage_warning_count: 0,
      completed_at: null,
    };
    stream.callback?.(snapshot);
    stream.callback?.(snapshot);
    expect(auditRunApi.tasks).toHaveBeenCalledTimes(2);

    resolveRefresh({
      items: [task("worker-beta", "succeeded")],
      meta: { limit: 500, offset: 0, total: 1 },
    });
    await flushPromises();

    expect(auditRunApi.tasks).toHaveBeenCalledTimes(3);
    expect(wrapper.text()).toContain("worker-gamma");
    wrapper.unmount();
  });

  it("reloads the run, report list and tasks after report generation", async () => {
    const wrapper = await renderView();
    auditRunApi.get.mockResolvedValueOnce({ ...run, status: "completed", current_stage: "reporting", progress: 100 });
    reportApi.list.mockResolvedValueOnce({
      items: [{ ...report, id: "report-new", version: 3 }],
      meta: { limit: 1, offset: 0, total: 1 },
    });

    await wrapper.get("button").trigger("click");
    await flushPromises();

    expect(reportApi.generate).toHaveBeenCalledWith(run.id);
    expect(auditRunApi.get).toHaveBeenCalledTimes(2);
    expect(auditRunApi.tasks).toHaveBeenCalledTimes(2);
    expect(reportApi.list).toHaveBeenCalledTimes(2);
    expect(wrapper.text()).toContain("报告 v3");
    wrapper.unmount();
  });

  it("counts run tasks from the SSE snapshot instead of adding the loaded page", async () => {
    const wrapper = await renderView();

    expect(wrapper.text()).toContain("1 个任务");

    stream.callback?.({
      audit_run_id: run.id,
      status: "static_scanning",
      current_stage: "static_scanning",
      progress: 40,
      warning_count: 1,
      failure_code: null,
      failure_reason: null,
      task_counts: { succeeded: 4, queued: 2 },
      finding_counts: {},
      coverage_warning_count: 0,
      completed_at: null,
    });
    await flushPromises();

    expect(wrapper.text()).toContain("6 个任务");
    wrapper.unmount();
  });

  it("never reports a failed build or zero coverage before those stages ran", async () => {
    auditRunApi.get.mockResolvedValue({
      ...run,
      status: "preprocessing",
      current_stage: "preprocessing",
    });
    auditRunApi.coverage.mockResolvedValue({
      ...coverage,
      // Exactly what a freshly created AuditCoverage row holds mid-run.
      build_status: "failed",
      entrypoints_total: 47,
      entrypoints_analyzed: 0,
      sensitive_sinks_total: 128,
      sensitive_sinks_analyzed: 0,
    });

    const wrapper = await renderView();

    const badge = wrapper.get(".build-row .badge");
    expect(badge.text()).toBe("尚未构建");
    expect(badge.classes()).toContain("badge--neutral");
    expect(wrapper.text()).toContain("待统计");
    expect(wrapper.text()).not.toContain("0 / 47");
    wrapper.unmount();
  });

  it("says so when the task list was truncated instead of showing a short list silently", async () => {
    auditRunApi.tasks.mockResolvedValue({
      items: [task("worker-alpha")],
      meta: { limit: 500, offset: 0, total: 812 },
    });

    const wrapper = await renderView();

    expect(wrapper.text()).toContain("本次运行共 812 个任务");
    wrapper.unmount();
  });

  it("consumes the finding counts and coverage warnings the stream already carries", async () => {
    const wrapper = await renderView();

    stream.callback?.({
      audit_run_id: run.id,
      status: "human_review",
      current_stage: "human_review",
      progress: 90,
      warning_count: 3,
      failure_code: null,
      failure_reason: null,
      task_counts: { succeeded: 4 },
      finding_counts: { candidate: 8, awaiting_human_review: 2 },
      coverage_warning_count: 3,
      completed_at: null,
    });
    await flushPromises();

    expect(wrapper.text()).toContain("等待人工处置 2 个 Finding");
    expect(wrapper.text()).toContain("待人工 2");
    expect(wrapper.text()).toContain("候选 8");
    wrapper.unmount();
  });

  it("rebuilds a narrative from consecutive snapshots", async () => {
    const wrapper = await renderView();
    const base = {
      audit_run_id: run.id,
      progress: 40,
      warning_count: 0,
      failure_code: null,
      failure_reason: null,
      task_counts: {},
      finding_counts: {},
      coverage_warning_count: 0,
      completed_at: null,
    } as const;

    stream.callback?.({ ...base, status: "static_scanning", current_stage: "static_scanning" });
    await flushPromises();
    stream.callback?.({
      ...base,
      status: "semantic_auditing",
      current_stage: "semantic_auditing",
      finding_counts: { candidate: 5 },
    });
    await flushPromises();

    expect(wrapper.text()).toContain("进入 AI 语义审计");
    expect(wrapper.text()).toContain("新增 5 个候选（累计 5）");
    wrapper.unmount();
  });

  it("lets an admin delete a settled run after explicit confirmation", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    const wrapper = await renderView();
    const deleteButton = wrapper
      .findAll("button")
      .find((button) => button.text().includes("删除"));

    expect(deleteButton).toBeDefined();
    await deleteButton!.trigger("click");
    await flushPromises();

    expect(auditRunApi.remove).toHaveBeenCalledWith(run.id);
    wrapper.unmount();
  });
});
