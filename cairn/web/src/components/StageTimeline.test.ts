import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";

import type { AuditRun, AuditTask } from "@/types/api";

import StageTimeline from "./StageTimeline.vue";

const run: AuditRun = {
  id: "run-1",
  repository_id: "repository-1",
  source_request: {},
  snapshot_id: "snapshot-1",
  policy_id: "policy-1",
  policy_version: 1,
  status: "human_review",
  current_stage: "human_review",
  progress: 90,
  warning_count: 2,
  failure_code: null,
  failure_reason: null,
  created_by: "auditor",
  created_at: "2026-07-29T01:00:00Z",
  started_at: "2026-07-29T01:01:00Z",
  completed_at: null,
};

function task(
  id: string,
  type: string,
  scopeKey: string,
  status: AuditTask["status"],
  overrides: Partial<AuditTask> = {},
): AuditTask {
  return {
    id,
    audit_run_id: run.id,
    type,
    scope_key: scopeKey,
    scope: {},
    status,
    worker_name: "deterministic-orchestrator",
    attempt: 1,
    max_attempts: 3,
    timeout_seconds: 300,
    error_code: null,
    error_detail: null,
    started_at: "2026-07-29T01:02:00Z",
    finished_at: "2026-07-29T01:03:00Z",
    created_at: "2026-07-29T01:01:30Z",
    ...overrides,
  };
}

describe("StageTimeline", () => {
  it("expands partial stages and explains each concrete task failure", () => {
    const wrapper = mount(StageTimeline, {
      props: {
        run,
        tasks: [
          task(
            "semgrep",
            "sast",
            "deterministic:semgrep",
            "succeeded",
          ),
          task(
            "trivy",
            "dependency_scan",
            "deterministic:trivy",
            "failed",
            { error_code: "SCANNER_BINARY_UNAVAILABLE" },
          ),
          task(
            "semantic",
            "semantic_review",
            "semantic:module:http-endpoint:authorization",
            "failed",
            {
              error_code: "SANDBOX_PROCESS_FAILED",
              scope: {
                module: ".",
                attack_surface: "HTTP endpoint",
                category: "authorization",
                entrypoint_paths: ["Controller.java", "AdminController.java"],
              },
              timeout_seconds: 900,
            },
          ),
        ],
      },
    });

    expect(wrapper.get(".stage-group--partial details").attributes()).toHaveProperty(
      "open",
    );
    expect(wrapper.text()).toContain("静态扫描");
    expect(wrapper.text()).toContain("2 个任务 · 1 成功 · 1 失败");
    expect(wrapper.text()).toContain("Semgrep Java 安全规则扫描");
    expect(wrapper.text()).toContain(
      "当前扫描镜像尚未配置该工具的可执行文件。",
    );
    expect(wrapper.text()).toContain("AI 语义分析：越权访问");
    expect(wrapper.text()).toContain("2 个入口文件");
    expect(wrapper.text()).toContain("超时上限");
    expect(wrapper.text()).toContain("15 分钟");
  });

  it("keeps a stage the reader is looking at open once its tasks finish", async () => {
    const scanning: AuditRun = {
      ...run,
      status: "static_scanning",
      current_stage: "static_scanning",
    };
    const wrapper = mount(StageTimeline, {
      props: {
        run: scanning,
        tasks: [
          task("semgrep", "sast", "deterministic:semgrep", "running", {
            finished_at: null,
          }),
        ],
      },
    });
    const stage = () => wrapper.findAll(".stage-group")[3].get("details");

    expect(stage().attributes()).toHaveProperty("open");

    await wrapper.setProps({
      tasks: [task("semgrep", "sast", "deterministic:semgrep", "succeeded")],
    });

    expect(stage().attributes()).toHaveProperty("open");
  });

  it("respects a stage the reader closed while it is still running", async () => {
    const scanning: AuditRun = {
      ...run,
      status: "static_scanning",
      current_stage: "static_scanning",
    };
    const running = (attempt: number) =>
      task("semgrep", "sast", "deterministic:semgrep", "running", {
        attempt,
        finished_at: null,
      });
    const wrapper = mount(StageTimeline, {
      props: { run: scanning, tasks: [running(1)] },
    });
    const stage = () => wrapper.findAll(".stage-group")[3].get("details");

    (stage().element as HTMLDetailsElement).open = false;
    await stage().trigger("toggle");
    await wrapper.setProps({ tasks: [running(2)] });

    expect(stage().attributes()).not.toHaveProperty("open");
  });
});
