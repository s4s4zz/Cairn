import { computed, ref } from "vue";
import { defineStore } from "pinia";

import { authApi } from "@/api/resources";
import { clearCsrfToken, setCsrfToken } from "@/api/client";
import type { User, UserRole } from "@/types/api";

export const useAuthStore = defineStore("auth", () => {
  const user = ref<User | null>(null);
  const expiresAt = ref<string | null>(null);
  const initialized = ref(false);
  const busy = ref(false);

  const isAuthenticated = computed(() => user.value !== null);
  const role = computed<UserRole | null>(() => user.value?.role ?? null);

  function can(roles: UserRole[]): boolean {
    return role.value !== null && roles.includes(role.value);
  }

  async function initialize(): Promise<void> {
    if (initialized.value) return;
    try {
      user.value = await authApi.me();
    } catch {
      user.value = null;
    } finally {
      initialized.value = true;
    }
  }

  async function login(username: string, password: string): Promise<void> {
    busy.value = true;
    try {
      const response = await authApi.login(username, password);
      setCsrfToken(response.csrf_token);
      user.value = response.user;
      expiresAt.value = response.expires_at;
      initialized.value = true;
    } finally {
      busy.value = false;
    }
  }

  async function logout(): Promise<void> {
    busy.value = true;
    try {
      await authApi.logout();
    } finally {
      clearSession();
      busy.value = false;
    }
  }

  async function changePassword(currentPassword: string, newPassword: string): Promise<void> {
    busy.value = true;
    try {
      await authApi.changePassword(currentPassword, newPassword);
      clearSession();
    } finally {
      busy.value = false;
    }
  }

  function clearSession(): void {
    clearCsrfToken();
    user.value = null;
    expiresAt.value = null;
    initialized.value = true;
  }

  return { user, expiresAt, initialized, busy, isAuthenticated, role, can, initialize, login, logout, changePassword, clearSession };
});
