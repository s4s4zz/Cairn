import { afterEach, describe, expect, it, vi } from "vitest";

import {
  clearStaleAssetReloadMarker,
  isStaleAssetError,
  recoverFromStaleAssetError,
} from "./chunkRecovery";

describe("stale asset recovery", () => {
  afterEach(() => {
    sessionStorage.clear();
  });

  it("recognizes the dynamic-import error emitted for a removed Vite chunk", () => {
    expect(
      isStaleAssetError(
        new TypeError(
          "Failed to fetch dynamically imported module: /assets/DashboardView-old.js",
        ),
      ),
    ).toBe(true);
    expect(isStaleAssetError(new Error("API request failed"))).toBe(false);
  });

  it("reloads only once until a successful navigation clears the marker", () => {
    const reload = vi.fn();
    const error = new TypeError("Failed to fetch dynamically imported module");

    expect(recoverFromStaleAssetError(error, { reload })).toBe(true);
    expect(recoverFromStaleAssetError(error, { reload })).toBe(false);
    expect(reload).toHaveBeenCalledTimes(1);

    clearStaleAssetReloadMarker();
    expect(recoverFromStaleAssetError(error, { reload })).toBe(true);
    expect(reload).toHaveBeenCalledTimes(2);
  });
});
