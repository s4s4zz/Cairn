import { createPinia, setActivePinia } from "pinia";
import { flushPromises, mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { useAuthStore } from "@/stores/auth";
import type { Finding, FindingDetail, UserRole } from "@/types/api";

const findingApi = vi.hoisted(() => ({
  list: vi.fn(),
  get: vi.fn(),
  review: vi.fn(),
  reverify: vi.fn(),
}));

vi.mock("@/api/resources", () => ({ findingApi }));

import ReviewQueueView from "./ReviewQueueView.vue";

const finding: Finding = {
  id: "finding-1", audit_run_id: "run-1", fingerprint: "a".repeat(64), title: "SQL injection",
  description: "Untrusted input reaches a query.", category: "injection", cwe_id: "CWE-89", owasp_category: null,
  severity: "high", confidence: "high", status: "awaiting_human_review", attack_preconditions: "Attacker input",
  impact: "Database access", remediation: "Use parameters", runtime_verification: "unverified", discovered_by: "semgrep",
  first_seen_at: "2026-01-01T00:00:00Z", updated_at: "2026-01-02T00:00:00Z",
};
const detail: FindingDetail = { ...finding, locations: [], evidence: [], verifications: [], human_reviews: [] };

async function render(role: UserRole) {
  const pinia = createPinia();
  setActivePinia(pinia);
  useAuthStore().user = { id: role, username: role, role, is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null };
  const router = createRouter({ history: createMemoryHistory(), routes: [
    { path: "/review", component: ReviewQueueView },
    { path: "/:pathMatch(.*)*", component: { template: "<div />" } },
  ] });
  await router.push("/review");
  await router.isReady();
  const wrapper = mount(ReviewQueueView, { global: { plugins: [pinia, router] } });
  await flushPromises();
  const action = wrapper.findAll("button").find((button) => button.text() === "处置");
  await action?.trigger("click");
  await flushPromises();
  return wrapper;
}

async function submitComment(comment: string): Promise<void> {
  const textarea = document.querySelector<HTMLTextAreaElement>("#review-comment");
  const form = document.querySelector<HTMLFormElement>("#review-form");
  if (!textarea || !form) throw new Error("review form was not rendered");
  textarea.value = comment;
  textarea.dispatchEvent(new Event("input", { bubbles: true }));
  form.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await flushPromises();
}

beforeEach(() => {
  vi.clearAllMocks();
  findingApi.list.mockImplementation(({ severity }: { severity: string }) => Promise.resolve({
    items: severity === "high" ? [finding] : [],
    meta: { limit: 100, offset: 0, total: severity === "high" ? 1 : 0 },
  }));
  findingApi.get.mockResolvedValue(detail);
  findingApi.review.mockResolvedValue({ ...detail, status: "confirmed" });
  findingApi.reverify.mockResolvedValue({ finding: { ...finding, status: "validating" }, review: {}, task_id: "task-1" });
});

describe("ReviewQueueView role actions", () => {
  it("offers disposition and severity adjustment to reviewers", async () => {
    const wrapper = await render("reviewer");
    expect(document.body.textContent).toContain("确认漏洞");
    expect(document.body.textContent).toContain("接受风险");
    expect(document.body.textContent).not.toContain("重新验证方式");
    await submitComment("人工证据确认");
    expect(findingApi.review).toHaveBeenCalledWith("finding-1", {
      verdict: "confirmed", final_severity: "high", comment: "人工证据确认",
    });
    expect(findingApi.reverify).not.toHaveBeenCalled();
    wrapper.unmount();
  });

  it("offers independent re-verification to auditors without disposition controls", async () => {
    const wrapper = await render("auditor");
    expect(document.body.textContent).toContain("重新验证方式");
    expect(document.body.textContent).not.toContain("确认漏洞");
    await submitComment("需要独立验证");
    expect(findingApi.reverify).toHaveBeenCalledWith("finding-1", "independent_agent", "需要独立验证");
    expect(findingApi.review).not.toHaveBeenCalled();
    wrapper.unmount();
  });
});
