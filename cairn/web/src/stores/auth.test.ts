import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";

const authApi = vi.hoisted(() => ({
  me: vi.fn(), login: vi.fn(), logout: vi.fn(), changePassword: vi.fn(),
}));

vi.mock("@/api/resources", () => ({ authApi }));

import { useAuthStore } from "./auth";

describe("auth store password change", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    setActivePinia(createPinia());
  });

  it("clears the local session after the backend revokes all sessions", async () => {
    authApi.changePassword.mockResolvedValue(undefined);
    const store = useAuthStore();
    store.user = { id: "user", username: "user", role: "viewer", is_active: true, created_at: "2026-01-01T00:00:00Z", last_login_at: null };

    await store.changePassword("old-password", "new-password-123");

    expect(authApi.changePassword).toHaveBeenCalledWith("old-password", "new-password-123");
    expect(store.user).toBeNull();
    expect(store.busy).toBe(false);
  });
});
