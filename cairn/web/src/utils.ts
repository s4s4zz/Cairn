const DATE_FORMAT = new Intl.DateTimeFormat("zh-CN", {
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  hour12: false,
});

export function formatDate(value: string | null | undefined): string {
  if (!value) return "-";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : DATE_FORMAT.format(date);
}

export function formatBytes(value: number): string {
  if (!Number.isFinite(value) || value < 0) return "-";
  const units = ["B", "KB", "MB", "GB"];
  let size = value;
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size >= 10 || index === 0 ? size.toFixed(0) : size.toFixed(1)} ${units[index]}`;
}

export function shortId(value: string | null | undefined, length = 8): string {
  return value ? value.slice(0, length) : "-";
}

export function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "发生未知错误";
}

export function progressValue(value: number | string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(0, Math.min(100, parsed <= 1 ? parsed * 100 : parsed));
}

export function duration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt) return "-";
  const start = new Date(startedAt).getTime();
  const end = completedAt ? new Date(completedAt).getTime() : Date.now();
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "-";
  const totalSeconds = Math.floor((end - start) / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours) return `${hours}时 ${minutes}分`;
  if (minutes) return `${minutes}分 ${seconds}秒`;
  return `${seconds}秒`;
}

// Display labels for the enum-shaped fields the API returns as slugs. The
// stored values stay as they are — `category` in particular keys probe
// selection and scope keys on the server — so these are render-time only, and
// an unknown value falls through to the slug rather than being hidden.
const CATEGORY_LABELS: Record<string, string> = {
  "authorization": "越权访问",
  "command-execution": "命令执行",
  "command-injection": "命令注入",
  "config": "安全配置缺陷",
  "container-config": "容器配置缺陷",
  "deserialization": "不安全反序列化",
  "expression-injection": "表达式注入",
  "external-control-of-file-name": "文件名可被外部控制",
  "kubernetes": "Kubernetes 配置缺陷",
  "path-traversal": "路径穿越",
  "secret": "凭据泄露",
  "security": "安全弱点",
  "spring-config": "Spring 配置缺陷",
  "spring-security-misconfiguration": "Spring Security 配置缺陷",
  "sql-injection": "SQL 注入",
  "ssrf": "服务端请求伪造（SSRF）",
  "template-injection": "模板注入",
  "terraform": "Terraform 配置缺陷",
  "unsafe-deserialization": "不安全反序列化",
  "vulnerability": "已知组件漏洞",
  "xxe": "XML 外部实体注入（XXE）",
};

const CONFIDENCE_LABELS: Record<string, string> = {
  confirmed: "已确认",
  high: "高",
  medium: "中",
  low: "低",
};

const EVIDENCE_TYPE_LABELS: Record<string, string> = {
  code_snippet: "代码片段",
  call_trace: "调用链追踪",
  tool_result: "工具输出",
  build_log: "构建日志",
  unit_test: "单元测试",
  poc_output: "PoC 输出",
  http_exchange: "HTTP 交互",
  runtime_log: "运行日志",
};

const VERIFICATION_METHOD_LABELS: Record<string, string> = {
  static_corroboration: "静态互证",
  independent_agent: "独立盲审",
  build_test: "构建测试",
  dynamic_poc: "动态 PoC",
};

const LOCATION_ROLE_LABELS: Record<string, string> = {
  entrypoint: "入口",
  source: "污点源",
  propagation: "传播",
  sink: "Sink",
  related: "相关",
};

export function categoryLabel(value: string): string {
  return CATEGORY_LABELS[value] ?? value;
}

export function confidenceLabel(value: string): string {
  return CONFIDENCE_LABELS[value] ?? value;
}

export function evidenceTypeLabel(value: string): string {
  return EVIDENCE_TYPE_LABELS[value] ?? value;
}

export function verificationMethodLabel(value: string): string {
  return VERIFICATION_METHOD_LABELS[value] ?? value;
}

export function locationRoleLabel(value: string): string {
  return LOCATION_ROLE_LABELS[value] ?? value;
}
