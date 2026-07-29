import { describe, expect, it } from "vitest";

import { STAGES, hasPassedStage, stageIndex, stageProgress } from "./stages";
import type { AuditRun } from "./types/api";

function run(partial: Partial<AuditRun>): Pick<AuditRun, "status" | "current_stage"> {
  return { status: "static_scanning", current_stage: "static_scanning", ...partial };
}

describe("stages", () => {
  it("orders every AuditStage exactly once", () => {
    const keys = STAGES.map((stage) => stage.key);
    expect(new Set(keys).size).toBe(keys.length);
    expect(keys[0]).toBe("ingesting");
    expect(keys.at(-1)).toBe("reporting");
  });

  it("treats a stage the run has moved past as passed", () => {
    expect(stageProgress(run({}), "preprocessing")).toBe("passed");
    expect(stageProgress(run({}), "static_scanning")).toBe("active");
    expect(stageProgress(run({}), "semantic_auditing")).toBe("pending");
  });

  // `building` and `coverage_check` exist as stages but never as run statuses,
  // so `current_stage` can never equal them; the index comparison is what makes
  // "the build already happened" answerable at all.
  it("resolves stages that are never reported as the current stage", () => {
    expect(stageIndex("building")).toBeGreaterThan(0);
    expect(hasPassedStage(run({ current_stage: "preprocessing", status: "preprocessing" }), "building")).toBe(false);
    expect(hasPassedStage(run({ current_stage: "static_scanning" }), "building")).toBe(true);
  });

  it("counts every stage as passed once the run finished successfully", () => {
    const finished = run({ status: "completed_with_warnings", current_stage: "reporting" });
    expect(hasPassedStage(finished, "ingesting")).toBe(true);
    expect(hasPassedStage(finished, "reporting")).toBe(true);
  });

  it("does not claim later stages were passed when the run failed early", () => {
    const failed = run({ status: "failed", current_stage: "preprocessing" });
    expect(hasPassedStage(failed, "building")).toBe(false);
    expect(hasPassedStage(failed, "reporting")).toBe(false);
  });
});
