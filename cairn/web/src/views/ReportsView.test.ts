import { createPinia, setActivePinia } from "pinia";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuthStore } from "@/stores/auth";
import type { AuditRun, Report } from "@/types/api";

const auditRunApi = vi.hoisted(() => ({ list: vi.fn(), get: vi.fn() }));
const reportApi = vi.hoisted(() => ({
  list: vi.fn(),
  generate: vi.fn(),
  downloadUrl: vi.fn((id: string, format: string) => `/downloads/${id}/${format}`),
}));

vi.mock("@/api/resources", () => ({ auditRunApi, reportApi }));

import ReportsView from "./ReportsView.vue";

const candidate: AuditRun = {
  id: "run-candidate-1234",
  repository_id: "repository-1",
  source_request: {},
  snapshot_id: "snapshot-1",
  policy_id: "policy-1",
  policy_version: 4,
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

function report(offset: number): Report {
  return {
    id: `report-${offset}`,
    audit_run_id: `run-reported-${offset}`,
    version: offset ? 3 : 2,
    summary_json: {},
    html_artifact_id: `html-${offset}`,
    json_artifact_id: `json-${offset}`,
    sarif_artifact_id: `sarif-${offset}`,
    generated_at: "2026-07-29T02:00:00Z",
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
      { path: "/reports", component: ReportsView },
      { path: "/audit-runs/:id", component: { template: "<div />" } },
    ],
  });
  await router.push("/reports");
  await router.isReady();
  const wrapper = mount(ReportsView, { global: { plugins: [pinia, router] } });
  await flushPromises();
  return wrapper;
}

beforeEach(() => {
  vi.clearAllMocks();
  auditRunApi.list.mockResolvedValue({ items: [candidate], meta: { limit: 100, offset: 0, total: 1 } });
  auditRunApi.get.mockResolvedValue(candidate);
  reportApi.list.mockImplementation(({ offset = 0 }: { offset?: number }) => Promise.resolve({
    items: [report(offset)],
    meta: { limit: 25, offset, total: 30 },
  }));
  reportApi.generate.mockResolvedValue(report(0));
});

describe("ReportsView", () => {
  it("renders server reports and changes the server-side offset", async () => {
    const wrapper = await renderView();

    expect(reportApi.list).toHaveBeenCalledWith({ audit_run_id: undefined, limit: 25, offset: 0 });
    expect(wrapper.text()).toContain("报告 v2");
    expect(wrapper.get('[title="打开 HTML 报告"]').attributes("href")).toBe("/downloads/report-0/html");

    await wrapper.get('[title="下一页"]').trigger("click");
    await flushPromises();

    expect(reportApi.list).toHaveBeenLastCalledWith({ audit_run_id: undefined, limit: 25, offset: 25 });
    expect(wrapper.text()).toContain("报告 v3");
    wrapper.unmount();
  });

  it("resets pagination and reloads server reports after generation", async () => {
    const wrapper = await renderView();
    await wrapper.get('[title="下一页"]').trigger("click");
    await flushPromises();

    const generateButton = wrapper.findAll("button").find((button) => button.text().includes("生成报告"));
    await generateButton?.trigger("click");
    await flushPromises();

    expect(reportApi.generate).toHaveBeenCalledWith(candidate.id);
    expect(reportApi.list).toHaveBeenLastCalledWith({ audit_run_id: undefined, limit: 25, offset: 0 });
    expect(auditRunApi.list).toHaveBeenLastCalledWith({ status: "human_review", limit: 100 });
    wrapper.unmount();
  });
});
