import { createPinia, setActivePinia } from "pinia";
import { mount } from "@vue/test-utils";
import { createMemoryHistory, createRouter } from "vue-router";
import { describe, expect, it } from "vitest";

import { useAuthStore } from "@/stores/auth";
import type { User, UserRole } from "@/types/api";
import AppShell from "./AppShell.vue";

function user(role: UserRole): User {
  return { id: role, username: `${role}-user`, role, is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null };
}

async function render(role: UserRole) {
  const pinia = createPinia();
  setActivePinia(pinia);
  const auth = useAuthStore();
  auth.user = user(role);
  const router = createRouter({ history: createMemoryHistory(), routes: [{ path: "/:pathMatch(.*)*", component: { template: "<div />" } }] });
  await router.push("/");
  await router.isReady();
  return mount(AppShell, { global: { plugins: [pinia, router] }, slots: { default: "content" } });
}

describe("AppShell RBAC navigation", () => {
  it("hides privileged navigation from viewers", async () => {
    const wrapper = await render("viewer");
    expect(wrapper.text()).not.toContain("人工复核");
    expect(wrapper.text()).not.toContain("用户管理");
    expect(wrapper.text()).not.toContain("审计日志");
    expect(wrapper.text()).toContain("仓库");
    wrapper.unmount();
  });

  it("shows reverify navigation to auditors but keeps admin pages hidden", async () => {
    const wrapper = await render("auditor");
    expect(wrapper.text()).toContain("人工复核");
    expect(wrapper.text()).not.toContain("用户管理");
    expect(wrapper.text()).not.toContain("审计日志");
    wrapper.unmount();
  });

  it("shows administration navigation to admins", async () => {
    const wrapper = await render("admin");
    expect(wrapper.text()).toContain("人工复核");
    expect(wrapper.text()).toContain("用户管理");
    expect(wrapper.text()).toContain("审计日志");
    wrapper.unmount();
  });
});
