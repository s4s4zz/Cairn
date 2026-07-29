import { describe, expect, it } from "vitest";

import { diffSnapshots } from "./useRunNarrative";
import type { AuditRunEventSnapshot } from "@/types/api";

function snapshot(partial: Partial<AuditRunEventSnapshot> = {}): AuditRunEventSnapshot {
  return {
    audit_run_id: "run-1",
    status: "static_scanning",
    current_stage: "static_scanning",
    progress: 40,
    warning_count: 0,
    failure_code: null,
    failure_reason: null,
    task_counts: {},
    finding_counts: {},
    coverage_warning_count: 0,
    completed_at: null,
    ...partial,
  };
}

const AT = "2026-07-29T01:20:00Z";

describe("diffSnapshots", () => {
  it("treats the first snapshot as a baseline, not as news", () => {
    expect(diffSnapshots(null, snapshot(), AT)).toEqual([]);
  });

  it("announces a stage change", () => {
    const events = diffSnapshots(
      snapshot(),
      snapshot({ status: "semantic_auditing", current_stage: "semantic_auditing" }),
      AT,
    );

    expect(events.map((event) => event.text)).toContain("进入 AI 语义审计");
  });

  it("reports new candidates and the running total", () => {
    const events = diffSnapshots(
      snapshot({ finding_counts: { candidate: 8 } }),
      snapshot({ finding_counts: { candidate: 8, validating: 3 } }),
      AT,
    );

    expect(events.map((event) => event.text)).toEqual([
      "新增 3 个候选（累计 11）",
      "3 个 Finding 进入验证",
    ]);
  });

  it("raises coverage warnings as warnings, not as neutral noise", () => {
    const [event] = diffSnapshots(snapshot(), snapshot({ coverage_warning_count: 2 }), AT);

    expect(event).toMatchObject({ tone: "warning", text: "新增 2 条覆盖警告（累计 2）" });
  });

  it("names the failure code on a terminal failure", () => {
    const events = diffSnapshots(
      snapshot(),
      snapshot({ status: "failed", failure_code: "BUILD_TIMEOUT" }),
      AT,
    );

    expect(events.at(-1)).toMatchObject({ tone: "danger", text: "运行失败：BUILD_TIMEOUT" });
  });

  it("reports finished, failed and skipped tasks separately", () => {
    const events = diffSnapshots(
      snapshot({ task_counts: { succeeded: 2 } }),
      snapshot({ task_counts: { succeeded: 3, failed: 1, skipped: 1 } }),
      AT,
    );

    expect(events.map((event) => event.text)).toEqual([
      "1 个任务完成",
      "1 个任务失败",
      "1 个任务被跳过",
    ]);
  });

  it("stays silent when nothing changed", () => {
    expect(diffSnapshots(snapshot(), snapshot(), AT)).toEqual([]);
  });
});
