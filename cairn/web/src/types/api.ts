export type UserRole = "admin" | "auditor" | "reviewer" | "viewer";
export type SourceType = "git" | "zip" | "local_upload";
export type AuditRunStatus =
  | "created"
  | "ingesting"
  | "preprocessing"
  | "static_scanning"
  | "semantic_auditing"
  | "dynamic_verifying"
  | "machine_review"
  | "human_review"
  | "reporting"
  | "completed"
  | "completed_with_warnings"
  | "cancelling"
  | "cancelled"
  | "failed";
export type AuditStage =
  | "ingesting"
  | "preprocessing"
  | "building"
  | "static_scanning"
  | "semantic_auditing"
  | "dynamic_verifying"
  | "machine_review"
  | "human_review"
  | "coverage_check"
  | "reporting";
export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";
export type FindingStatus =
  | "candidate"
  | "validating"
  | "machine_confirmed"
  | "awaiting_human_review"
  | "confirmed"
  | "rejected"
  | "accepted_risk";
export type ReviewVerdict = "confirmed" | "rejected" | "accepted_risk" | "reverify";
export type ReverifyMethod = "independent_agent" | "dynamic_poc";
export type ModelProvider = "openai" | "anthropic" | "anthropic-key";

export interface PageMeta {
  limit: number;
  offset: number;
  total: number;
}

export interface Page<T> {
  items: T[];
  meta: PageMeta;
}

export interface User {
  id: string;
  username: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login_at: string | null;
}

export interface LoginResponse {
  user: User;
  csrf_token: string;
  expires_at: string;
}

export interface Repository {
  id: string;
  name: string;
  source_type: SourceType;
  remote_url: string | null;
  credential_ref: string | null;
  default_branch: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface RepositoryCreate {
  name: string;
  source_type: SourceType;
  remote_url?: string;
  credential_ref?: string;
  default_branch?: string;
}

export interface SourceUpload {
  id: string;
  artifact_id: string;
  repository_id: string | null;
  source_type: SourceType;
  original_filename: string;
  status: "ready" | "rejected" | "expired";
  failure_code: string | null;
  created_by: string;
  created_at: string;
  expires_at: string | null;
}

export interface Snapshot {
  id: string;
  repository_id: string;
  commit_sha: string | null;
  content_sha256: string;
  branch_or_tag: string | null;
  artifact_id: string;
  file_count: number;
  total_bytes: number;
  java_file_count: number;
  java_version: string | null;
  build_system: "maven" | "gradle" | "mixed" | "unknown";
  status: "creating" | "ready" | "rejected" | "failed";
  failure_code: string | null;
  created_at: string;
}

export interface AuditPolicy {
  id: string;
  name: string;
  version: number;
  include_paths: string[];
  exclude_paths: string[];
  enabled_scanners: string[];
  dynamic_verification: "required" | "preferred" | "disabled";
  severity_thresholds: Record<string, unknown>;
  resource_budget: Record<string, unknown>;
  active: boolean;
  created_at: string;
}

export interface AuditRun {
  id: string;
  repository_id: string;
  source_request: Record<string, unknown>;
  snapshot_id: string | null;
  policy_id: string;
  policy_version: number;
  status: AuditRunStatus;
  current_stage: AuditStage | null;
  progress: number | string;
  warning_count: number;
  failure_code: string | null;
  failure_reason: string | null;
  created_by: string;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface AuditTask {
  id: string;
  audit_run_id: string;
  type: string;
  scope_key: string;
  scope: Record<string, unknown>;
  status: "queued" | "claimed" | "running" | "succeeded" | "failed" | "cancelled" | "skipped";
  worker_name: string | null;
  attempt: number;
  max_attempts: number;
  timeout_seconds: number;
  error_code: string | null;
  error_detail: string | null;
  started_at: string | null;
  finished_at: string | null;
  output_artifact_ids?: string[];
  created_at: string;
}

export interface AuditRunStageEvent {
  stage: AuditStage;
  entered_at: string;
  /** Null while the stage is the current one and the run is still live. */
  exited_at: string | null;
}

export interface ToolCoverageRecord {
  status?: string;
  version?: string | null;
  task_id?: string;
  artifact_ids?: string[];
  reason_code?: string | null;
  candidate_count?: number;
}

export interface AuditCoverage {
  audit_run_id: string;
  modules_total: number;
  modules_analyzed: number;
  java_files_total: number;
  java_files_analyzed: number;
  entrypoints_total: number;
  entrypoints_analyzed: number;
  sensitive_sinks_total: number;
  sensitive_sinks_analyzed: number;
  build_status: "success" | "partial" | "failed";
  static_tools_completed: Record<string, ToolCoverageRecord>;
  skipped_paths: string[];
  unsupported_components: Array<Record<string, unknown>>;
  coverage_warnings: Array<{ code?: string; message?: string; scope?: string } & Record<string, unknown>>;
  updated_at: string;
}

export interface Finding {
  id: string;
  audit_run_id: string;
  fingerprint: string;
  title: string;
  description: string;
  category: string;
  cwe_id: string;
  owasp_category: string | null;
  severity: FindingSeverity;
  confidence: "confirmed" | "high" | "medium" | "low";
  status: FindingStatus;
  attack_preconditions: string;
  impact: string;
  remediation: string;
  runtime_verification: "verified" | "unverified" | "not_applicable";
  discovered_by: string;
  first_seen_at: string;
  updated_at: string;
}

export interface FindingLocation {
  id: string;
  role: "entrypoint" | "source" | "propagation" | "sink" | "related";
  origin_kind: "source" | "bytecode" | "config" | "decompiled";
  file_path: string | null;
  source_path: string | null;
  start_line: number | null;
  end_line: number | null;
  symbol: string | null;
  code_snippet: string | null;
  container_path: string | null;
  entry_path: string | null;
  class_name: string | null;
  method_name: string | null;
  method_descriptor: string | null;
  bytecode_offset: number | null;
  decompiled_artifact_id: string | null;
  decompiled_start_line: number | null;
  decompiled_end_line: number | null;
  snapshot_sha: string;
  ordinal: number;
}

export interface Evidence {
  id: string;
  type: string;
  artifact_id: string | null;
  summary: string;
  sha256: string | null;
  produced_by_task_id: string;
  created_at: string;
}

export interface Verification {
  id: string;
  method: string;
  verdict: "confirmed" | "rejected" | "inconclusive";
  verifier: string;
  evidence_ids: string[];
  reasoning: string;
  created_at: string;
}

export interface HumanReview {
  id: string;
  verdict: ReviewVerdict;
  original_severity: FindingSeverity;
  final_severity: FindingSeverity;
  reviewer_id: string;
  comment: string;
  reviewed_at: string;
}

export interface FindingDetail extends Finding {
  locations: FindingLocation[];
  evidence: Evidence[];
  verifications: Verification[];
  human_reviews: HumanReview[];
}

export interface Report {
  id: string;
  audit_run_id: string;
  version: number;
  summary_json: Record<string, unknown>;
  html_artifact_id: string;
  json_artifact_id: string;
  sarif_artifact_id: string;
  generated_at: string;
}

export interface AuditLogEntry {
  id: string;
  actor_username: string;
  actor_role: string | null;
  action: string;
  target_type: string | null;
  target_id: string | null;
  outcome: string;
  http_status: number | null;
  request_id: string | null;
  client_ip: string | null;
  detail: Record<string, unknown>;
  created_at: string;
}

export interface SourceFile {
  snapshot_id: string;
  snapshot_sha: string;
  path: string;
  start_line: number;
  end_line: number;
  total_lines: number;
  content: string;
  truncated: boolean;
}

export interface AuditRunEventSnapshot {
  audit_run_id: string;
  status: AuditRunStatus;
  current_stage: AuditStage | null;
  progress: number;
  warning_count: number;
  failure_code: string | null;
  failure_reason: string | null;
  task_counts: Record<string, number>;
  finding_counts: Record<string, number>;
  coverage_warning_count: number;
  completed_at: string | null;
}

export interface ServiceHealth {
  status: "ok" | "ready" | "degraded" | "down" | "unknown";
  database?: string;
  services?: Record<string, { status: string; detail?: string }>;
}

export interface ModelProviderStatus {
  configured: boolean;
  provider: ModelProvider | null;
  base_url: string | null;
  model: string | null;
  api_key_configured: boolean;
  updated_at: string | null;
}

export interface ModelSummary {
  id: string;
  display_name: string | null;
}
