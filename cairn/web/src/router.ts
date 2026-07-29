import { createRouter, createWebHistory, type RouteLocationNormalized } from "vue-router";

import { pinia } from "@/stores";
import { useAuthStore } from "@/stores/auth";
import type { UserRole } from "@/types/api";

declare module "vue-router" {
  interface RouteMeta {
    title?: string;
    public?: boolean;
    roles?: UserRole[];
  }
}

const router = createRouter({
  history: createWebHistory(),
  scrollBehavior: () => ({ top: 0 }),
  routes: [
    { path: "/login", name: "login", component: () => import("@/views/LoginView.vue"), meta: { title: "登录", public: true } },
    { path: "/", name: "dashboard", component: () => import("@/views/DashboardView.vue"), meta: { title: "仪表盘" } },
    { path: "/repositories", name: "repositories", component: () => import("@/views/RepositoriesView.vue"), meta: { title: "仓库" } },
    { path: "/repositories/:id", name: "repository-detail", component: () => import("@/views/RepositoryDetailView.vue"), meta: { title: "仓库详情" } },
    { path: "/audit-runs", name: "audit-runs", component: () => import("@/views/AuditRunsView.vue"), meta: { title: "审计任务" } },
    { path: "/audit-runs/:id", name: "audit-run-detail", component: () => import("@/views/AuditRunDetailView.vue"), meta: { title: "审计任务详情" } },
    { path: "/findings", name: "findings", component: () => import("@/views/FindingsView.vue"), meta: { title: "漏洞" } },
    { path: "/findings/:id", name: "finding-detail", component: () => import("@/views/FindingDetailView.vue"), meta: { title: "漏洞详情" } },
    {
      path: "/review",
      name: "review",
      component: () => import("@/views/ReviewQueueView.vue"),
      meta: { title: "人工复核", roles: ["admin", "auditor", "reviewer"] },
    },
    { path: "/reports", name: "reports", component: () => import("@/views/ReportsView.vue"), meta: { title: "报告" } },
    { path: "/policies", name: "policies", component: () => import("@/views/PoliciesView.vue"), meta: { title: "规则与策略" } },
    {
      path: "/settings",
      name: "settings",
      component: () => import("@/views/SettingsView.vue"),
      meta: { title: "系统配置", roles: ["admin"] },
    },
    {
      path: "/users",
      name: "users",
      component: () => import("@/views/UsersView.vue"),
      meta: { title: "用户管理", roles: ["admin"] },
    },
    {
      path: "/audit-logs",
      name: "audit-logs",
      component: () => import("@/views/AuditLogsView.vue"),
      meta: { title: "审计日志", roles: ["admin"] },
    },
    { path: "/:pathMatch(.*)*", redirect: "/" },
  ],
});

function allowed(to: RouteLocationNormalized, role: UserRole | null): boolean {
  return !to.meta.roles || (role !== null && to.meta.roles.includes(role));
}

router.beforeEach(async (to) => {
  const auth = useAuthStore(pinia);
  await auth.initialize();
  document.title = `${to.meta.title || "工作台"} · Cairn`;

  if (to.meta.public) {
    if (to.name === "login" && auth.isAuthenticated) return { name: "dashboard" };
    return true;
  }
  if (!auth.isAuthenticated) return { name: "login", query: { redirect: to.fullPath } };
  if (!allowed(to, auth.role)) return { name: "dashboard" };
  return true;
});

export default router;
