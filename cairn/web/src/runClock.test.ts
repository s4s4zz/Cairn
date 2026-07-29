import { describe, expect, it } from "vitest";

import { buildRunClock, stageState } from "./runClock";
import { compactDuration } from "./taskLabels";
import type { AuditRun, AuditTask } from "./types/api";

const run: Pick<AuditRun, "status" | "current_stage" | "started_at" | "completed_at"> = {
  status: "semantic_auditing",
  current_stage: "semantic_auditing",
  started_at: "2026-07-29T01:00:00Z",
  completed_at: null,
};

function task(partial: Partial<AuditTask> & Pick<AuditTask, "id" | "type" | "scope_key">): AuditTask {
  return {
    audit_run_id: "run-1",
    scope: {},
    status: "succeeded",
    worker_name: "orchestrator",
    attempt: 1,
    max_attempts: 3,
    timeout_seconds: 900,
    error_code: null,
    error_detail: null,
    started_at: "2026-07-29T01:00:00Z",
    finished_at: "2026-07-29T01:10:00Z",
    created_at: "2026-07-29T01:00:00Z",
    ...partial,
  };
}

function clockFor(tasks: AuditTask[], toolCoverage = {}) {
  return buildRunClock({
    run,
    tasks,
    toolCoverage,
    nowMs: Date.parse("2026-07-29T01:30:00Z"),
    formatDuration: compactDuration,
  });
}

describe("buildRunClock", () => {
  it("lays serial tasks out as a staircase across one shared window", () => {
    const clock = clockFor([
      task({ id: "a", type: "build", scope_key: "deterministic:build" }),
      task({
        id: "b",
        type: "sast",
        scope_key: "deterministic:semgrep",
        started_at: "2026-07-29T01:10:00Z",
        finished_at: "2026-07-29T01:20:00Z",
      }),
    ]);

    expect(clock.totalMs).toBe(20 * 60 * 1000);
    const first = clock.bars.find((bar) => bar.key === "task:a");
    const second = clock.bars.find((bar) => bar.key === "task:b");
    expect(first?.offset).toBe(0);
    expect(first?.extent).toBeCloseTo(0.5, 5);
    // The second bar starts where the first ended: the shape is the serial engine.
    expect(second?.offset).toBeCloseTo(0.5, 5);
    expect(second?.share).toBeCloseTo(0.5, 5);
  });

  it("keeps a skipped task on the timeline instead of dropping it", () => {
    const clock = clockFor([
      task({ id: "a", type: "build", scope_key: "deterministic:build" }),
      task({
        id: "b",
        type: "sast",
        scope_key: "deterministic:findsecbugs",
        status: "skipped",
        error_code: "BYTECODE_UNAVAILABLE",
        started_at: null,
        finished_at: "2026-07-29T01:10:00Z",
      }),
    ]);

    const skipped = clock.bars.find((bar) => bar.key === "task:b");
    expect(skipped?.status).toBe("skipped");
    // Anchored at the moment it was skipped, with a readable reason.
    expect(skipped?.offset).not.toBeNull();
    expect(skipped?.note).toBe("无字节码");
  });

  it("flags a task that finished close to its own timeout", () => {
    const clock = clockFor([
      task({
        id: "a",
        type: "sast",
        scope_key: "deterministic:codeql",
        timeout_seconds: 660,
        finished_at: "2026-07-29T01:10:00Z",
      }),
    ]);

    expect(clock.bars.find((bar) => bar.key === "task:a")?.timeoutHeadroomSeconds).toBe(60);
  });

  it("leaves headroom unset for a task that finished comfortably", () => {
    const clock = clockFor([task({ id: "a", type: "build", scope_key: "deterministic:build" })]);
    expect(clock.bars.find((bar) => bar.key === "task:a")?.timeoutHeadroomSeconds).toBeNull();
  });

  it("attaches the candidate count a tool reported", () => {
    const clock = clockFor(
      [task({ id: "a", type: "sast", scope_key: "deterministic:semgrep" })],
      { semgrep: { status: "completed", candidate_count: 7 } },
    );

    expect(clock.bars.find((bar) => bar.key === "task:a")?.candidateCount).toBe(7);
  });

  it("extends a running task to the current instant", () => {
    const clock = clockFor([
      task({
        id: "a",
        type: "semantic_review",
        scope_key: "semantic:.:http:ssrf",
        status: "running",
        started_at: "2026-07-29T01:20:00Z",
        finished_at: null,
      }),
    ]);

    expect(clock.bars.find((bar) => bar.key === "task:a")?.durationMs).toBe(10 * 60 * 1000);
  });

  it("says so when no task has started rather than drawing an empty axis", () => {
    const clock = buildRunClock({
      run: { ...run, started_at: null },
      tasks: [],
      nowMs: Date.parse("2026-07-29T01:30:00Z"),
      formatDuration: compactDuration,
    });

    expect(clock.hasTiming).toBe(false);
    expect(clock.ticks).toEqual([]);
  });
});

describe("stageState", () => {
  const scanning = { status: "static_scanning", current_stage: "static_scanning" } as const;

  it("reports partial when a stage mixes success and failure", () => {
    const tasks = [
      task({ id: "a", type: "sast", scope_key: "deterministic:semgrep" }),
      task({ id: "b", type: "dependency_scan", scope_key: "deterministic:trivy", status: "failed" }),
    ];
    expect(stageState(scanning, tasks, 3)).toBe("partial");
  });

  it("reports skipped when every task of a stage was skipped", () => {
    const tasks = [task({ id: "a", type: "sast", scope_key: "deterministic:findsecbugs", status: "skipped" })];
    expect(stageState(scanning, tasks, 3)).toBe("skipped");
  });
});
