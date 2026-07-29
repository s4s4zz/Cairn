<script setup lang="ts">
import {
  Archive,
  BarChart3,
  BookOpenCheck,
  Bug,
  ClipboardCheck,
  FileClock,
  FileText,
  LayoutDashboard,
  KeyRound,
  LogOut,
  Menu,
  ShieldCheck,
  Settings,
  Users,
  X,
} from "@lucide/vue";
import { computed, reactive, ref } from "vue";
import { useRoute, useRouter } from "vue-router";

import { useAuthStore } from "@/stores/auth";
import type { UserRole } from "@/types/api";
import { errorMessage } from "@/utils";
import ModalDialog from "@/components/ModalDialog.vue";

interface NavigationItem {
  label: string;
  to: string;
  icon: typeof LayoutDashboard;
  roles?: UserRole[];
}

const auth = useAuthStore();
const route = useRoute();
const router = useRouter();
const mobileOpen = ref(false);
const passwordOpen = ref(false);
const passwordError = ref("");
const passwordForm = reactive({ current: "", next: "", confirm: "" });

const primary: NavigationItem[] = [
  { label: "仪表盘", to: "/", icon: LayoutDashboard },
  { label: "仓库", to: "/repositories", icon: Archive },
  { label: "审计任务", to: "/audit-runs", icon: BarChart3 },
  { label: "漏洞", to: "/findings", icon: Bug },
  { label: "人工复核", to: "/review", icon: ClipboardCheck, roles: ["admin", "auditor", "reviewer"] },
  { label: "报告", to: "/reports", icon: FileText },
  { label: "规则与策略", to: "/policies", icon: BookOpenCheck },
];

const administration: NavigationItem[] = [
  { label: "系统配置", to: "/settings", icon: Settings, roles: ["admin"] },
  { label: "用户管理", to: "/users", icon: Users, roles: ["admin"] },
  { label: "审计日志", to: "/audit-logs", icon: FileClock, roles: ["admin"] },
];

function visible(items: NavigationItem[]): NavigationItem[] {
  return items.filter((item) => !item.roles || auth.can(item.roles));
}

function active(to: string): boolean {
  return to === "/" ? route.path === "/" : route.path.startsWith(to);
}

async function logout(): Promise<void> {
  await auth.logout();
  await router.replace({ name: "login" });
}

function openPassword(): void {
  Object.assign(passwordForm, { current: "", next: "", confirm: "" });
  passwordError.value = "";
  passwordOpen.value = true;
}

async function changePassword(): Promise<void> {
  passwordError.value = "";
  if (passwordForm.next !== passwordForm.confirm) {
    passwordError.value = "两次输入的新密码不一致";
    return;
  }
  try {
    await auth.changePassword(passwordForm.current, passwordForm.next);
    passwordOpen.value = false;
    await router.replace({ name: "login" });
  } catch (reason) {
    passwordError.value = errorMessage(reason);
  }
}

const initials = computed(() => auth.user?.username.slice(0, 2).toUpperCase() || "--");
const roleLabel = computed(() => ({ admin: "管理员", auditor: "审计员", reviewer: "复核员", viewer: "只读用户" })[auth.role || "viewer"]);
</script>

<template>
  <div class="app-shell">
    <header class="mobile-bar">
      <button class="icon-button icon-button--dark" type="button" title="打开导航" @click="mobileOpen = true"><Menu :size="20" /></button>
      <div class="brand brand--compact"><ShieldCheck :size="20" /><strong>Cairn</strong></div>
      <span class="avatar avatar--small">{{ initials }}</span>
    </header>

    <div v-if="mobileOpen" class="sidebar-scrim" @click="mobileOpen = false" />
    <aside class="sidebar" :class="{ 'sidebar--open': mobileOpen }">
      <div class="sidebar__brand">
        <div class="brand"><ShieldCheck :size="24" /><div><strong>Cairn</strong><span>Java Audit</span></div></div>
        <button class="icon-button icon-button--dark sidebar__close" type="button" title="关闭导航" @click="mobileOpen = false"><X :size="20" /></button>
      </div>

      <nav class="sidebar__nav" aria-label="主导航">
        <RouterLink
          v-for="item in visible(primary)"
          :key="item.to"
          :to="item.to"
          class="nav-item"
          :class="{ 'nav-item--active': active(item.to) }"
          @click="mobileOpen = false"
        >
          <component :is="item.icon" :size="18" />
          <span>{{ item.label }}</span>
        </RouterLink>

        <template v-if="visible(administration).length">
          <p class="nav-section">系统管理</p>
          <RouterLink
            v-for="item in visible(administration)"
            :key="item.to"
            :to="item.to"
            class="nav-item"
            :class="{ 'nav-item--active': active(item.to) }"
            @click="mobileOpen = false"
          >
            <component :is="item.icon" :size="18" />
            <span>{{ item.label }}</span>
          </RouterLink>
        </template>
      </nav>

      <div class="sidebar__account">
        <span class="avatar">{{ initials }}</span>
        <div class="account-copy"><strong>{{ auth.user?.username }}</strong><span>{{ roleLabel }}</span></div>
        <button class="icon-button icon-button--dark" type="button" title="修改密码" :disabled="auth.busy" @click="openPassword"><KeyRound :size="17" /></button>
        <button class="icon-button icon-button--dark" type="button" title="退出登录" :disabled="auth.busy" @click="logout"><LogOut :size="18" /></button>
      </div>
    </aside>

    <main class="workspace">
      <slot />
    </main>

    <ModalDialog :open="passwordOpen" title="修改密码" width="small" @close="passwordOpen = false">
      <form id="self-password" class="account-form" @submit.prevent="changePassword">
        <div class="field"><label for="current-password">当前密码</label><input id="current-password" v-model="passwordForm.current" class="input" type="password" autocomplete="current-password" required /></div>
        <div class="field"><label for="next-password">新密码</label><input id="next-password" v-model="passwordForm.next" class="input" type="password" minlength="12" autocomplete="new-password" required /></div>
        <div class="field"><label for="confirm-password">确认新密码</label><input id="confirm-password" v-model="passwordForm.confirm" class="input" type="password" minlength="12" autocomplete="new-password" required /></div>
        <div v-if="passwordError" class="inline-error">{{ passwordError }}</div>
      </form>
      <template #footer><button class="button button--secondary" type="button" @click="passwordOpen = false">取消</button><button class="button" type="submit" form="self-password" :disabled="auth.busy">{{ auth.busy ? "正在修改" : "修改并重新登录" }}</button></template>
    </ModalDialog>
  </div>
</template>

<style scoped>
.account-form { display: grid; gap: 14px; }
</style>
