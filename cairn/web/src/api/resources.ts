import { apiRequest, apiUrl } from "./client";
import type {
  AuditCoverage,
  AuditLogEntry,
  AuditPolicy,
  AuditRun,
  AuditRunStatus,
  AuditTask,
  Finding,
  FindingDetail,
  FindingSeverity,
  FindingStatus,
  HumanReview,
  LoginResponse,
  ModelProvider,
  ModelProviderStatus,
  ModelSummary,
  Page,
  Report,
  ReverifyMethod,
  Repository,
  RepositoryCreate,
  ReviewVerdict,
  ServiceHealth,
  Snapshot,
  SourceFile,
  SourceType,
  SourceUpload,
  User,
  UserRole,
} from "@/types/api";

export const authApi = {
  login: (username: string, password: string) =>
    apiRequest<LoginResponse>("/auth/login", { method: "POST", json: { username, password } }),
  me: () => apiRequest<User>("/auth/me"),
  logout: () => apiRequest<void>("/auth/logout", { method: "POST" }),
  changePassword: (currentPassword: string, newPassword: string) =>
    apiRequest<void>("/auth/password", {
      method: "POST",
      json: { current_password: currentPassword, new_password: newPassword },
    }),
};

export const repositoryApi = {
  list: (query: { source_type?: SourceType; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<Repository>>("/repositories", { query }),
  get: (id: string) => apiRequest<Repository>(`/repositories/${id}`),
  create: (payload: RepositoryCreate) => apiRequest<Repository>("/repositories", { method: "POST", json: payload }),
  remove: (id: string) => apiRequest<void>(`/repositories/${id}`, { method: "DELETE" }),
  upload: (file: File, sourceType: Exclude<SourceType, "git"> = "zip") => {
    const safeFilename = file.name.replace(/[^\x20-\x7e]/g, "_");
    return apiRequest<SourceUpload>("/uploads", {
      method: "POST",
      query: { source_type: sourceType },
      headers: { "Content-Type": file.type || "application/zip", "X-Filename": safeFilename },
      body: file,
    });
  },
  createUploadSnapshot: (repositoryId: string, uploadId: string) =>
    apiRequest<Snapshot>(`/repositories/${repositoryId}/snapshots`, {
      method: "POST",
      json: { type: "upload", upload_id: uploadId },
    }),
  createGitSnapshot: (repositoryId: string, ref: string) =>
    apiRequest<Snapshot>(`/repositories/${repositoryId}/snapshots`, {
      method: "POST",
      json: { type: "git_ref", ref },
    }),
};

export const snapshotApi = {
  list: (repositoryId: string, query: { status?: Snapshot["status"]; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<Snapshot>>(`/repositories/${repositoryId}/snapshots`, { query }),
  get: (id: string) => apiRequest<Snapshot>(`/snapshots/${id}`),
  source: (id: string, filePath: string, startLine?: number, endLine?: number) =>
    apiRequest<SourceFile>(`/snapshots/${id}/source`, {
      query: { path: filePath, start_line: startLine, end_line: endLine },
    }),
};

export const policyApi = {
  list: (query: { name?: string; active?: boolean; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<AuditPolicy>>("/audit-policies", { query }),
  create: (payload: {
    name: string;
    include_paths: string[];
    exclude_paths: string[];
    enabled_scanners: string[];
    dynamic_verification: AuditPolicy["dynamic_verification"];
    severity_thresholds: Record<string, unknown>;
    resource_budget: Record<string, unknown>;
    active: boolean;
  }) => apiRequest<AuditPolicy>("/audit-policies", { method: "POST", json: payload }),
};

export const auditRunApi = {
  list: (query: { repository_id?: string; status?: AuditRunStatus; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<AuditRun>>("/audit-runs", { query }),
  get: (id: string) => apiRequest<AuditRun>(`/audit-runs/${id}`),
  create: (payload: {
    repository_id: string;
    policy_id: string;
    source_request: Record<string, unknown>;
  }) => apiRequest<AuditRun>("/audit-runs", { method: "POST", json: payload }),
  cancel: (id: string) => apiRequest<AuditRun>(`/audit-runs/${id}/cancel`, { method: "POST" }),
  retry: (id: string) => apiRequest<AuditRun>(`/audit-runs/${id}/retry`, { method: "POST" }),
  remove: (id: string) => apiRequest<void>(`/audit-runs/${id}`, { method: "DELETE" }),
  tasks: (id: string) => apiRequest<Page<AuditTask>>(`/audit-runs/${id}/tasks`, { query: { limit: 500 } }),
  coverage: (id: string) => apiRequest<AuditCoverage>(`/audit-runs/${id}/coverage`),
  eventsUrl: (id: string) => apiUrl(`/audit-runs/${id}/events`),
};

export const findingApi = {
  list: (query: {
    audit_run_id?: string;
    cwe_id?: string;
    severity?: FindingSeverity;
    status?: FindingStatus;
    limit?: number;
    offset?: number;
  } = {}) => apiRequest<Page<Finding>>("/findings", { query }),
  get: (id: string) => apiRequest<FindingDetail>(`/findings/${id}`),
  review: (
    id: string,
    payload: { verdict: Exclude<ReviewVerdict, "reverify">; final_severity: FindingSeverity; comment: string },
  ) => apiRequest<FindingDetail>(`/findings/${id}/review`, { method: "POST", json: payload }),
  reverify: (id: string, method: ReverifyMethod, comment: string) =>
    apiRequest<{ finding: Finding; review: HumanReview; task_id: string }>(
      `/findings/${id}/reverify`,
      { method: "POST", json: { method, comment } },
    ),
};

export const reportApi = {
  list: (query: { audit_run_id?: string; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<Report>>("/reports", { query }),
  generate: (runId: string) => apiRequest<Report>(`/audit-runs/${runId}/reports`, { method: "POST" }),
  downloadUrl: (reportId: string, format: "html" | "json" | "sarif") =>
    apiUrl(`/reports/${reportId}`, { format }),
  artifactUrl: (artifactId: string) => apiUrl(`/artifacts/${artifactId}`),
};

export const userApi = {
  list: (query: { role?: UserRole; is_active?: boolean; limit?: number; offset?: number } = {}) =>
    apiRequest<Page<User>>("/users", { query }),
  create: (payload: { username: string; password: string; role: UserRole }) =>
    apiRequest<User>("/users", { method: "POST", json: payload }),
  update: (id: string, payload: { role?: UserRole; is_active?: boolean }) =>
    apiRequest<User>(`/users/${id}`, { method: "PATCH", json: payload }),
  setPassword: (id: string, newPassword: string) =>
    apiRequest<void>(`/users/${id}/password`, { method: "POST", json: { new_password: newPassword } }),
};

export const auditLogApi = {
  list: (query: {
    action?: string;
    actor_username?: string;
    target_type?: string;
    target_id?: string;
    limit?: number;
    offset?: number;
  } = {}) => apiRequest<Page<AuditLogEntry>>("/audit-logs", { query }),
};

export const healthApi = {
  ready: () => apiRequest<ServiceHealth>("/health/ready", { service: true }),
};

export const modelProviderApi = {
  get: () => apiRequest<ModelProviderStatus>("/model-provider"),
  update: (payload: { provider: ModelProvider; base_url: string; model: string; api_key?: string }) =>
    apiRequest<ModelProviderStatus>("/model-provider", { method: "PUT", json: payload }),
  models: (payload: { provider: ModelProvider; base_url: string; api_key?: string }) =>
    apiRequest<{ models: ModelSummary[] }>("/model-provider/models", { method: "POST", json: payload }),
};
