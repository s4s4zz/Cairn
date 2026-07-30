import { describe, expect, it } from "vitest";

import { buildRunSummary } from "./runSummary";
import type { AuditCoverage, AuditRun, AuditTask } from "./types/api";

const run: Pick<AuditRun, "status" | "current_stage"> = {
  status: "human_review",
  current_stage: "human_review",
};

const coverage: AuditCoverage = {
  audit_run_id: "run-1",
  modules_total: 12,
  modules_analyzed: 12,
  java_files_total: 3400,
  java_files_analyzed: 3210,
  entrypoints_total: 47,
  entrypoints_analyzed: 40,
  sensitive_sinks_total: 128,
  sensitive_sinks_analyzed: 96,
  build_status: "success",
  static_tools_completed: {},
  skipped_paths: [],
  unsupported_components: [],
  coverage_warnings: [],
  updated_at: "2026-07-29T01:10:00Z",
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

describe("buildRunSummary", () => {
  it("states the scope it covered", () => {
    const clauses = buildRunSummary({ run, tasks: [], coverage, findingCounts: {} });
    expect(clauses[0]).toBe("扫描 12 个模块、3400 个 Java 文件");
  });

  it("gives every gap with its cause rather than as a bare count", () => {
    const clauses = buildRunSummary({
      run,
      tasks: [],
      coverage: {
        ...coverage,
        static_tools_completed: {
          semgrep: { status: "completed" },
          codeql: { status: "completed" },
          findsecbugs: { status: "skipped", reason_code: "BYTECODE_UNAVAILABLE" },
        },
      },
      findingCounts: {},
    });

    expect(clauses).toContain("3 个确定性工具完成 2 个，findsecbugs 因无字节码跳过");
  });

  it("names the semantic scopes that reached no conclusion", () => {
    const clauses = buildRunSummary({
      run,
      tasks: [
        task({ id: "a", type: "semantic_review", scope_key: "semantic:.:http:authorization" }),
        task({
          id: "b",
          type: "semantic_review",
          scope_key: "semantic:.:http:ssrf",
          status: "failed",
          error_code: "SEMANTIC_BUDGET_EXHAUSTED",
        }),
      ],
      coverage,
      findingCounts: {},
    });

    expect(clauses).toContain(
      "语义审计 2 个范围，完成 1 个，服务端请求伪造（SSRF） 因预算耗尽未得出结论",
    );
  });

  it("does not mention a build that succeeded", () => {
    const clauses = buildRunSummary({ run, tasks: [], coverage, findingCounts: {} });
    expect(clauses.join("")).not.toContain("构建");
  });

  it("mentions a degraded build because it limits everything downstream", () => {
    const clauses = buildRunSummary({
      run,
      tasks: [],
      coverage: { ...coverage, build_status: "failed" },
      findingCounts: {},
    });

    expect(clauses).toContain("构建失败，字节码层分析受限");
  });

  it("puts the pending human work in the sentence", () => {
    const clauses = buildRunSummary({
      run,
      tasks: [],
      coverage,
      findingCounts: { confirmed: 4, awaiting_human_review: 2 },
    });

    expect(clauses).toContain("6 个 Finding 中 2 个待人工处置");
  });

  it("says plainly when nothing was found", () => {
    const clauses = buildRunSummary({ run, tasks: [], coverage, findingCounts: {} });
    expect(clauses).toContain("尚未产生 Finding");
  });

  it("omits scope numbers before the inventory stage was passed", () => {
    const clauses = buildRunSummary({
      run: { status: "preprocessing", current_stage: "preprocessing" },
      tasks: [],
      coverage,
      findingCounts: {},
    });

    expect(clauses.join("")).not.toContain("个模块");
  });
});
