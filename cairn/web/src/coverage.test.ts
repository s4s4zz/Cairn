import { describe, expect, it } from "vitest";

import { buildStatusDisplay, collectGaps, coverageMetrics } from "./coverage";
import type { AuditCoverage, AuditRun } from "./types/api";

const coverage: AuditCoverage = {
  audit_run_id: "run-1",
  modules_total: 12,
  modules_analyzed: 12,
  java_files_total: 3400,
  java_files_analyzed: 3210,
  entrypoints_total: 47,
  entrypoints_analyzed: 0,
  sensitive_sinks_total: 128,
  sensitive_sinks_analyzed: 0,
  // The constructor default, written before any build has run.
  build_status: "failed",
  static_tools_completed: {},
  skipped_paths: [],
  unsupported_components: [],
  coverage_warnings: [],
  updated_at: "2026-07-29T01:10:00Z",
};

function run(partial: Partial<AuditRun>): Pick<AuditRun, "status" | "current_stage"> {
  return { status: "static_scanning", current_stage: "static_scanning", ...partial };
}

describe("coverage tri-state", () => {
  it("does not report a failed build before the build stage was passed", () => {
    const mid = buildStatusDisplay(
      run({ status: "preprocessing", current_stage: "preprocessing" }),
      coverage,
    );

    expect(mid.label).toBe("尚未构建");
    expect(mid.known).toBe(false);
    expect(mid.tone).not.toBe("danger");
  });

  it("reports a real build failure once the stage was passed", () => {
    expect(buildStatusDisplay(run({}), coverage).label).toBe("构建失败");
  });

  it("shows a successful build as soon as it appears, since success is never a default", () => {
    const display = buildStatusDisplay(
      run({ status: "preprocessing", current_stage: "preprocessing" }),
      { ...coverage, build_status: "success" },
    );

    expect(display).toMatchObject({ label: "构建成功", known: true });
  });

  it("marks numerators produced by a later stage as not yet counted", () => {
    const metrics = coverageMetrics(run({}), coverage);
    const byKey = Object.fromEntries(metrics.map((metric) => [metric.key, metric]));

    expect(byKey.modules.state).toBe("ready");
    expect(byKey.java_files.state).toBe("ready");
    // Both are zeroed by preprocessing and only filled when semantic review ends.
    expect(byKey.entrypoints.state).toBe("counting");
    expect(byKey.sinks.state).toBe("counting");
  });

  it("counts semantic numerators once the semantic stage was passed", () => {
    const metrics = coverageMetrics(run({ status: "machine_review", current_stage: "machine_review" }), {
      ...coverage,
      entrypoints_analyzed: 40,
      sensitive_sinks_analyzed: 96,
    });

    expect(metrics.find((metric) => metric.key === "entrypoints")).toMatchObject({
      state: "ready",
      ratio: 85,
    });
  });
});

describe("collectGaps", () => {
  it("merges tools, paths, components and warnings into one list", () => {
    const gaps = collectGaps({
      ...coverage,
      static_tools_completed: {
        semgrep: { status: "completed", candidate_count: 7 },
        findsecbugs: { status: "skipped", reason_code: "BYTECODE_UNAVAILABLE" },
        codeql: { status: "failed", reason_code: "SCANNER_EXECUTION_FAILED" },
      },
      skipped_paths: ["src/test/Foo.java", "generated/Bar.java"],
      unsupported_components: [{ name: "core-kt", detail: "Kotlin 模块未纳入分析" }],
      coverage_warnings: [
        { reason_code: "SEMANTIC_BUDGET_EXHAUSTED", tool: "semantic-reviewer:ssrf", task_id: "t1" },
      ],
    });

    const titles = gaps.map((gap) => gap.title);
    expect(titles).toContain("findsecbugs 未执行");
    expect(titles).toContain("codeql 执行失败");
    expect(titles).toContain("2 个路径未纳入分析");
    expect(titles).toContain("core-kt 不受支持");
    // A completed tool is not a gap.
    expect(titles.some((title) => title.startsWith("semgrep"))).toBe(false);

    const budget = gaps.find((gap) => gap.code === "SEMANTIC_BUDGET_EXHAUSTED");
    expect(budget?.detail).toBe("模型预算耗尽，该范围未得出结论。");
    expect(gaps.find((gap) => gap.title === "codeql 执行失败")?.tone).toBe("failed");
  });

  it("never invents an explanation for an unknown reason code", () => {
    const gaps = collectGaps({
      ...coverage,
      coverage_warnings: [{ reason_code: "SOME_NEW_CODE", tool: "trivy", task_id: "t2" }],
    });

    expect(gaps[0].code).toBe("SOME_NEW_CODE");
    expect(gaps[0].detail).toBe("trivy 报告了未覆盖原因，详见原因码。");
  });

  it("reports no gaps for a clean run", () => {
    expect(collectGaps(coverage)).toEqual([]);
  });
});
