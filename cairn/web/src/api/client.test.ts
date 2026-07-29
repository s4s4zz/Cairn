import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError, apiRequest, clearCsrfToken, setCsrfToken } from "./client";
import { auditRunApi, findingApi, reportApi, snapshotApi } from "./resources";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("API client", () => {
  afterEach(() => {
    clearCsrfToken();
    vi.restoreAllMocks();
  });

  it("adds credentials, JSON headers, query values and the in-memory CSRF token", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ ok: true }));
    setCsrfToken("csrf-value");

    await apiRequest("/items", {
      method: "POST",
      query: { limit: 10, empty: "" },
      json: { name: "demo" },
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/items?limit=10");
    expect(init?.credentials).toBe("include");
    expect(init?.body).toBe('{"name":"demo"}');
    const headers = init?.headers as Headers;
    expect(headers.get("Content-Type")).toBe("application/json");
    expect(headers.get("X-CSRF-Token")).toBe("csrf-value");
  });

  it("uses the service root for health endpoints", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ status: "ready" }));
    await apiRequest("/health/ready", { service: true });
    expect(fetchMock.mock.calls[0][0]).toBe("/health/ready");
  });

  it("surfaces structured API errors", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ error_code: "denied", message: "禁止访问" }, 403));
    await expect(apiRequest("/restricted")).rejects.toMatchObject({ status: 403, code: "denied", message: "禁止访问" } satisfies Partial<ApiError>);
  });

  it("matches source, reverify and report-download backend contracts", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse({ content: "class A {}" }))
      .mockResolvedValueOnce(jsonResponse({ finding: {}, review: {}, task_id: "task" }));

    await snapshotApi.source("snapshot", "src/main/java/A.java");
    await findingApi.reverify("finding", "dynamic_poc", "运行验证");

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/snapshots/snapshot/source?path=src%2Fmain%2Fjava%2FA.java");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/findings/finding/reverify");
    expect(fetchMock.mock.calls[1][1]?.body).toBe('{"method":"dynamic_poc","comment":"运行验证"}');
    expect(reportApi.downloadUrl("report", "sarif")).toBe("/api/v1/reports/report?format=sarif");
  });

  it("matches task and report-list pagination contracts", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch")
      .mockResolvedValueOnce(jsonResponse({ items: [], meta: { limit: 500, offset: 0, total: 0 } }))
      .mockResolvedValueOnce(jsonResponse({ items: [], meta: { limit: 20, offset: 0, total: 0 } }))
      .mockResolvedValueOnce(jsonResponse({ items: [], meta: { limit: 25, offset: 50, total: 0 } }));

    await auditRunApi.tasks("run");
    await snapshotApi.list("repository", { status: "ready", limit: 20 });
    await reportApi.list({ audit_run_id: "run", limit: 25, offset: 50 });

    expect(fetchMock.mock.calls[0][0]).toBe("/api/v1/audit-runs/run/tasks?limit=500");
    expect(fetchMock.mock.calls[1][0]).toBe("/api/v1/repositories/repository/snapshots?status=ready&limit=20");
    expect(fetchMock.mock.calls[2][0]).toBe("/api/v1/reports?audit_run_id=run&limit=25&offset=50");
  });
});
