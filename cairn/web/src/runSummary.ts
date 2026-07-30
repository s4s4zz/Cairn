import { buildStatusDisplay } from "@/coverage";
import { hasPassedStage } from "@/stages";
import { shortReason, taskShortTitle } from "@/taskLabels";
import type { AuditCoverage, AuditRun, AuditTask } from "@/types/api";

/**
 * The run stated as prose rather than as a grid of counters.
 *
 * Every clause is conditional on data that actually exists, and a gap is
 * always given with its cause: "findsecbugs 因无字节码跳过" is the sentence
 * this whole page exists to be able to write, and it is the same data the
 * HTML report renders.
 */
function toolClauses(coverage: AuditCoverage | null): string[] {
  if (!coverage) return [];
  const entries = Object.entries(coverage.static_tools_completed ?? {}).filter(
    ([, record]) => record && typeof record === "object" && typeof record.status === "string",
  );
  if (!entries.length) return [];

  const done = entries.filter(([, record]) => record.status === "completed");
  const missed = entries.filter(([, record]) => record.status !== "completed");
  const head = `${entries.length} 个确定性工具完成 ${done.length} 个`;
  if (!missed.length) return [head];

  const detail = missed
    .slice(0, 3)
    .map(([tool, record]) => {
      const reason = shortReason(record.reason_code ?? null);
      const verb = record.status === "failed" ? "失败" : "跳过";
      return reason ? `${tool} 因${reason}${verb}` : `${tool} ${verb}`;
    })
    .join("、");
  const rest = missed.length > 3 ? `等 ${missed.length} 项` : "";
  return [`${head}，${detail}${rest}`];
}

function semanticClauses(tasks: readonly AuditTask[]): string[] {
  const scopes = tasks.filter((task) => task.type === "semantic_review");
  if (!scopes.length) return [];
  const succeeded = scopes.filter((task) => task.status === "succeeded").length;
  const missed = scopes.filter((task) => ["failed", "skipped"].includes(task.status));
  const head = `语义审计 ${scopes.length} 个范围，完成 ${succeeded} 个`;
  if (!missed.length) return [head];

  const detail = missed
    .slice(0, 3)
    .map((task) => {
      const reason = shortReason(task.error_code);
      return reason ? `${taskShortTitle(task)} 因${reason}未得出结论` : `${taskShortTitle(task)} 未得出结论`;
    })
    .join("、");
  return [`${head}，${detail}`];
}

function verificationClauses(tasks: readonly AuditTask[]): string[] {
  const clauses: string[] = [];
  const groups: Array<{ type: string; label: string }> = [
    { type: "dynamic_verify", label: "动态验证" },
    { type: "independent_verify", label: "机器复核" },
  ];
  for (const group of groups) {
    const related = tasks.filter((task) => task.type === group.type);
    if (!related.length) continue;
    const missed = related.filter((task) => ["failed", "skipped"].includes(task.status));
    if (!missed.length) continue;
    const reason = shortReason(missed[0].error_code);
    clauses.push(reason ? `${group.label}因${reason}未完整执行` : `${group.label}未完整执行`);
  }
  return clauses;
}

function findingClause(findingCounts: Record<string, number>): string {
  const total = Object.values(findingCounts).reduce((sum, value) => sum + value, 0);
  if (!total) return "尚未产生 Finding";
  const awaiting = findingCounts.awaiting_human_review ?? 0;
  if (awaiting) return `${total} 个 Finding 中 ${awaiting} 个待人工处置`;
  return `共 ${total} 个 Finding，无待人工处置项`;
}

export function buildRunSummary(input: {
  run: Pick<AuditRun, "status" | "current_stage">;
  tasks: readonly AuditTask[];
  coverage: AuditCoverage | null;
  findingCounts: Record<string, number>;
}): string[] {
  const { run, tasks, coverage, findingCounts } = input;
  const clauses: string[] = [];

  if (coverage && hasPassedStage(run, "preprocessing") && coverage.modules_total) {
    clauses.push(
      `扫描 ${coverage.modules_total} 个模块、${coverage.java_files_total} 个 Java 文件`,
    );
  }

  if (coverage) {
    const build = buildStatusDisplay(run, coverage);
    // A successful build is not news; only a degraded one changes what the
    // rest of the run could do.
    if (build.known && build.label !== "构建成功") {
      clauses.push(`${build.label}，字节码层分析受限`);
    }
  }

  clauses.push(...toolClauses(coverage));
  clauses.push(...semanticClauses(tasks));
  clauses.push(...verificationClauses(tasks));
  clauses.push(findingClause(findingCounts));

  if (coverage?.coverage_warnings.length) {
    clauses.push(`记录 ${coverage.coverage_warnings.length} 条覆盖缺口`);
  }

  return clauses;
}
