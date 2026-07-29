<script setup lang="ts">
import {
  AlertTriangle,
  Check,
  ChevronDown,
  Circle,
  LoaderCircle,
  Minus,
  RotateCcw,
} from "@lucide/vue";
import { computed } from "vue";

import StatusBadge from "@/components/StatusBadge.vue";
import type { AuditRun, AuditTask } from "@/types/api";
import { duration, formatDate } from "@/utils";

const props = defineProps<{ run: AuditRun; tasks: AuditTask[] }>();

type StageState =
  | "pending"
  | "running"
  | "succeeded"
  | "partial"
  | "failed"
  | "skipped";

const definitions = [
  { key: "ingesting", label: "源码接入", tasks: [] },
  { key: "preprocessing", label: "项目盘点", tasks: ["inventory"] },
  { key: "building", label: "隔离构建", tasks: ["build"] },
  {
    key: "static_scanning",
    label: "静态扫描",
    tasks: ["sast", "dependency_scan", "secret_scan", "config_scan"],
  },
  {
    key: "semantic_auditing",
    label: "AI 语义审计",
    tasks: ["semantic_review"],
  },
  {
    key: "dynamic_verifying",
    label: "动态验证",
    tasks: ["dynamic_verify"],
  },
  {
    key: "machine_review",
    label: "机器复核",
    tasks: ["independent_verify"],
  },
  { key: "human_review", label: "人工复核", tasks: [] },
  {
    key: "coverage_check",
    label: "覆盖检查",
    tasks: ["coverage_check"],
  },
  { key: "reporting", label: "生成报告", tasks: ["report"] },
] as const;

const currentIndex = computed(() =>
  definitions.findIndex((stage) => stage.key === props.run.current_stage),
);
const terminalSuccess = computed(() =>
  ["completed", "completed_with_warnings"].includes(props.run.status),
);

const taskNames: Record<string, string> = {
  inventory: "Java 项目盘点",
  build: "隔离构建",
  sast: "代码安全扫描",
  dependency_scan: "依赖漏洞扫描",
  secret_scan: "敏感信息扫描",
  config_scan: "配置安全扫描",
  semantic_review: "AI 语义分析",
  dynamic_verify: "动态验证",
  independent_verify: "独立机器复核",
  coverage_check: "覆盖率检查",
  report: "报告生成",
};

const scopeNames: Record<string, string> = {
  inventory: "项目结构、模块、入口点与敏感调用盘点",
  build: "编译源码并收集字节码与可运行制品",
  codeql: "CodeQL 数据流扫描",
  semgrep: "Semgrep Java 安全规则扫描",
  findsecbugs: "FindSecBugs 字节码扫描",
  "dependency-check": "OWASP Dependency-Check 依赖扫描",
  trivy: "Trivy 依赖与配置扫描",
  gitleaks: "Gitleaks 密钥泄漏扫描",
  "config-rules": "Spring 与部署配置规则检查",
};

const categoryNames: Record<string, string> = {
  authorization: "鉴权与越权",
  "command-execution": "命令执行",
  "sql-injection": "SQL 注入",
  ssrf: "SSRF",
  xxe: "XXE",
};

function stageTasks(taskTypes: readonly string[]): AuditTask[] {
  return props.tasks.filter((task) => taskTypes.includes(task.type));
}

function state(index: number, taskTypes: readonly string[]): StageState {
  const related = stageTasks(taskTypes);
  if (related.some((task) => ["running", "claimed"].includes(task.status))) {
    return "running";
  }
  if (related.some((task) => task.status === "failed")) {
    return related.some((task) =>
      ["succeeded", "skipped"].includes(task.status),
    )
      ? "partial"
      : "failed";
  }
  if (
    related.length &&
    related.every((task) =>
      ["succeeded", "skipped", "cancelled"].includes(task.status),
    )
  ) {
    return related.every((task) => task.status === "skipped")
      ? "skipped"
      : "succeeded";
  }
  if (terminalSuccess.value) return "succeeded";
  if (
    index === currentIndex.value &&
    !["failed", "cancelled"].includes(props.run.status)
  ) {
    return "running";
  }
  if (currentIndex.value >= 0 && index < currentIndex.value) return "succeeded";
  if (props.run.status === "failed" && index === currentIndex.value) {
    return "failed";
  }
  return "pending";
}

function stateLabel(value: StageState): string {
  return {
    pending: "等待",
    running: "执行中",
    succeeded: "完成",
    partial: "部分完成",
    failed: "失败",
    skipped: "已跳过",
  }[value];
}

function workers(taskTypes: readonly string[]): string {
  const names = [
    ...new Set(
      stageTasks(taskTypes)
        .map((task) => task.worker_name)
        .filter(Boolean),
    ),
  ];
  return names.join(", ") || "-";
}

function attempts(taskTypes: readonly string[]): string {
  const related = stageTasks(taskTypes);
  if (!related.length) return "-";
  const retries = related.reduce(
    (sum, task) => sum + Math.max(0, task.attempt - 1),
    0,
  );
  return retries ? `${retries} 次` : "无";
}

function elapsed(taskTypes: readonly string[]): string {
  const related = stageTasks(taskTypes);
  const first =
    related
      .map((task) => task.started_at)
      .filter((value): value is string => Boolean(value))
      .sort()[0] ?? null;
  const last =
    related
      .map((task) => task.finished_at)
      .filter((value): value is string => Boolean(value))
      .sort()
      .at(-1) ?? null;
  return duration(first, last);
}

function taskScopeToken(task: AuditTask): string {
  return task.scope_key.split(":").at(-1) || task.type;
}

function taskTitle(task: AuditTask): string {
  const token = taskScopeToken(task);
  if (task.type === "semantic_review") {
    return `${taskNames[task.type]}：${categoryNames[token] || token}`;
  }
  return scopeNames[token] || taskNames[task.type] || task.type;
}

function taskDescription(task: AuditTask): string {
  if (task.status === "queued") return "等待 Worker 领取";
  if (task.status === "claimed") return "Worker 已领取，正在准备沙箱";
  if (task.status === "running") {
    return task.type === "semantic_review"
      ? "模型正在按需读取相关源码并分析入口到 Sink 的调用链"
      : "沙箱正在执行该工具";
  }
  if (task.status === "succeeded") return "任务成功完成并已收集结果";
  if (task.status === "skipped") return "前置条件不满足，任务已跳过";
  if (task.status === "cancelled") return "任务已取消";
  return "任务未完成，请查看下方错误码";
}

function stageSummary(taskTypes: readonly string[]): string {
  const related = stageTasks(taskTypes);
  const active = related.find((task) =>
    ["running", "claimed"].includes(task.status),
  );
  if (active) return `正在执行：${taskTitle(active)}`;
  if (!related.length) return "该阶段没有后台子任务";
  const succeeded = related.filter((task) => task.status === "succeeded").length;
  const failed = related.filter((task) => task.status === "failed").length;
  const skipped = related.filter((task) => task.status === "skipped").length;
  return [
    `${related.length} 个任务`,
    `${succeeded} 成功`,
    failed ? `${failed} 失败` : "",
    skipped ? `${skipped} 跳过` : "",
  ]
    .filter(Boolean)
    .join(" · ");
}

function scopeMetadata(task: AuditTask): string {
  const values = [
    typeof task.scope.module === "string" ? `模块 ${task.scope.module}` : "",
    typeof task.scope.attack_surface === "string"
      ? task.scope.attack_surface
      : "",
    typeof task.scope.category === "string"
      ? categoryNames[task.scope.category] || task.scope.category
      : "",
  ].filter(Boolean);
  return values.join(" · ");
}

function opensByDefault(index: number, taskTypes: readonly string[]): boolean {
  return ["running", "partial", "failed"].includes(state(index, taskTypes));
}
</script>

<template>
  <ol class="stage-list">
    <li
      v-for="(stage, index) in definitions"
      :key="stage.key"
      class="stage-group"
      :class="`stage-group--${state(index, stage.tasks)}`"
    >
      <details :open="opensByDefault(index, stage.tasks)">
        <summary class="stage-row">
          <span class="stage-marker">
            <Check
              v-if="state(index, stage.tasks) === 'succeeded'"
              :size="14"
            />
            <LoaderCircle
              v-else-if="state(index, stage.tasks) === 'running'"
              class="spin"
              :size="14"
            />
            <AlertTriangle
              v-else-if="
                ['failed', 'partial'].includes(state(index, stage.tasks))
              "
              :size="14"
            />
            <Minus
              v-else-if="state(index, stage.tasks) === 'skipped'"
              :size="14"
            />
            <Circle v-else :size="11" />
          </span>
          <span class="stage-name">
            <strong>{{ stage.label }}</strong>
            <small>{{ stageSummary(stage.tasks) }}</small>
          </span>
          <span class="stage-state">
            {{ stateLabel(state(index, stage.tasks)) }}
          </span>
          <span class="stage-meta">
            <small>Worker</small>
            <strong :title="workers(stage.tasks)">
              {{ workers(stage.tasks) }}
            </strong>
          </span>
          <span class="stage-meta">
            <small>耗时</small>
            <strong>{{ elapsed(stage.tasks) }}</strong>
          </span>
          <span class="stage-meta">
            <small>重试</small>
            <strong>
              <RotateCcw
                v-if="attempts(stage.tasks) !== '-'"
                :size="11"
              />
              {{ attempts(stage.tasks) }}
            </strong>
          </span>
          <ChevronDown
            v-if="stageTasks(stage.tasks).length"
            class="stage-chevron"
            :size="16"
          />
        </summary>

        <div v-if="stageTasks(stage.tasks).length" class="task-list">
          <article
            v-for="task in stageTasks(stage.tasks)"
            :key="task.id"
            class="task-row"
            :class="`task-row--${task.status}`"
          >
            <div class="task-main">
              <div class="task-heading">
                <strong>{{ taskTitle(task) }}</strong>
                <StatusBadge :value="task.status" />
              </div>
              <p>{{ taskDescription(task) }}</p>
              <code>{{ task.scope_key }}</code>
              <small v-if="scopeMetadata(task)">
                {{ scopeMetadata(task) }}
              </small>
            </div>
            <dl class="task-facts">
              <div>
                <dt>尝试</dt>
                <dd>{{ task.attempt }} / {{ task.max_attempts }}</dd>
              </div>
              <div>
                <dt>Worker</dt>
                <dd :title="task.worker_name || '-'">
                  {{ task.worker_name || "-" }}
                </dd>
              </div>
              <div>
                <dt>开始</dt>
                <dd>{{ formatDate(task.started_at || task.created_at) }}</dd>
              </div>
              <div>
                <dt>耗时</dt>
                <dd>{{ duration(task.started_at, task.finished_at) }}</dd>
              </div>
            </dl>
            <div
              v-if="task.error_code || task.error_detail"
              class="task-error"
            >
              <AlertTriangle :size="14" />
              <div>
                <strong>{{ task.error_code || "TASK_FAILED" }}</strong>
                <p v-if="task.error_detail">{{ task.error_detail }}</p>
              </div>
            </div>
          </article>
        </div>
      </details>
    </li>
  </ol>
</template>

<style scoped>
.stage-list {
  margin: 0;
  padding: 0;
  list-style: none;
}
.stage-group {
  border-bottom: 1px solid var(--line);
}
.stage-group:last-child {
  border-bottom: 0;
}
.stage-group details[open] {
  background: #fbfcfc;
}
.stage-row {
  display: grid;
  min-height: 72px;
  grid-template-columns:
    28px minmax(220px, 1.5fr) 78px minmax(110px, 1fr)
    74px 58px 18px;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  cursor: pointer;
  list-style: none;
}
.stage-row::-webkit-details-marker {
  display: none;
}
.stage-marker {
  display: inline-flex;
  width: 24px;
  height: 24px;
  align-items: center;
  justify-content: center;
  color: #7a8580;
  background: #edf0ef;
  border-radius: 50%;
}
.stage-group--succeeded .stage-marker {
  color: var(--success);
  background: var(--success-soft);
}
.stage-group--running .stage-marker {
  color: var(--accent);
  background: var(--accent-soft);
}
.stage-group--failed .stage-marker {
  color: var(--danger);
  background: var(--danger-soft);
}
.stage-group--partial .stage-marker {
  color: var(--warning);
  background: var(--warning-soft);
}
.stage-group--skipped .stage-marker {
  color: #76817c;
}
.stage-name {
  display: grid;
  min-width: 0;
  gap: 4px;
}
.stage-name strong {
  color: #2d3833;
  font-size: 12px;
}
.stage-name small {
  overflow: hidden;
  color: var(--muted);
  font-size: 10px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stage-state {
  color: var(--muted);
  font-size: 10px;
  font-weight: 700;
}
.stage-group--running .stage-state {
  color: var(--accent);
}
.stage-group--failed .stage-state {
  color: var(--danger);
}
.stage-group--partial .stage-state {
  color: var(--warning);
}
.stage-meta {
  display: grid;
  min-width: 0;
  gap: 3px;
}
.stage-meta small {
  color: var(--subtle);
  font-size: 9px;
}
.stage-meta strong {
  display: flex;
  align-items: center;
  gap: 4px;
  overflow: hidden;
  color: #53605a;
  font-size: 10px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.stage-chevron {
  color: var(--subtle);
  transition: transform 0.15s ease;
}
details[open] .stage-chevron {
  transform: rotate(180deg);
}
.task-list {
  display: grid;
  gap: 8px;
  padding: 0 14px 14px 52px;
}
.task-row {
  display: grid;
  grid-template-columns: minmax(260px, 1.4fr) minmax(310px, 1fr);
  gap: 12px 18px;
  padding: 12px 14px;
  background: var(--surface);
  border: 1px solid var(--line);
  border-left: 3px solid #b8c1bd;
  border-radius: 7px;
}
.task-row--running,
.task-row--claimed {
  border-left-color: var(--accent);
}
.task-row--succeeded {
  border-left-color: var(--success);
}
.task-row--failed {
  border-left-color: var(--danger);
}
.task-row--skipped {
  border-left-color: var(--warning);
}
.task-main {
  display: grid;
  min-width: 0;
  align-content: start;
  gap: 5px;
}
.task-heading {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
}
.task-heading strong {
  color: #303b36;
  font-size: 11px;
}
.task-main p {
  margin: 0;
  color: var(--muted);
  font-size: 10px;
  line-height: 1.45;
}
.task-main code {
  overflow: hidden;
  color: #66736d;
  font-size: 9px;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-main > small {
  color: var(--subtle);
  font-size: 9px;
}
.task-facts {
  display: grid;
  grid-template-columns: 58px minmax(100px, 1fr) minmax(115px, 1fr) 70px;
  gap: 8px;
  margin: 0;
}
.task-facts div {
  min-width: 0;
}
.task-facts dt {
  margin-bottom: 4px;
  color: var(--subtle);
  font-size: 8px;
}
.task-facts dd {
  margin: 0;
  overflow: hidden;
  color: #53605a;
  font-size: 9px;
  font-weight: 600;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.task-error {
  display: flex;
  grid-column: 1 / -1;
  align-items: flex-start;
  gap: 8px;
  padding: 8px 10px;
  color: var(--danger);
  background: var(--danger-soft);
  border-radius: 5px;
}
.task-error strong {
  font-size: 9px;
}
.task-error p {
  margin: 3px 0 0;
  color: #7c3d3d;
  font-size: 9px;
  line-height: 1.45;
  overflow-wrap: anywhere;
}
@media (max-width: 960px) {
  .stage-row {
    grid-template-columns: 28px minmax(190px, 1fr) 75px 76px 18px;
  }
  .stage-meta:nth-of-type(2),
  .stage-meta:nth-of-type(3) {
    display: none;
  }
  .task-row {
    grid-template-columns: 1fr;
  }
}
@media (max-width: 620px) {
  .stage-row {
    grid-template-columns: 28px minmax(150px, 1fr) 70px 18px;
  }
  .stage-meta {
    display: none;
  }
  .task-list {
    padding-left: 14px;
  }
  .task-facts {
    grid-template-columns: 1fr 1fr;
  }
}
</style>
