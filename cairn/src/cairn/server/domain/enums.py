from enum import StrEnum


class SourceType(StrEnum):
    GIT = "git"
    ZIP = "zip"
    LOCAL_UPLOAD = "local_upload"
    BINARY_UPLOAD = "binary_upload"


class SnapshotInputKind(StrEnum):
    SOURCE = "source"
    BYTECODE = "bytecode"
    HYBRID = "hybrid"


class SourceUploadStatus(StrEnum):
    READY = "ready"
    REJECTED = "rejected"
    EXPIRED = "expired"


class GitCredentialKind(StrEnum):
    HTTPS_TOKEN = "https_token"
    SSH_KEY = "ssh_key"


class SnapshotStatus(StrEnum):
    CREATING = "creating"
    READY = "ready"
    REJECTED = "rejected"
    FAILED = "failed"


class BuildSystem(StrEnum):
    MAVEN = "maven"
    GRADLE = "gradle"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class DynamicVerificationMode(StrEnum):
    REQUIRED = "required"
    PREFERRED = "preferred"
    DISABLED = "disabled"


class AuditRunStatus(StrEnum):
    CREATED = "created"
    INGESTING = "ingesting"
    PREPROCESSING = "preprocessing"
    STATIC_SCANNING = "static_scanning"
    SEMANTIC_AUDITING = "semantic_auditing"
    DYNAMIC_VERIFYING = "dynamic_verifying"
    MACHINE_REVIEW = "machine_review"
    HUMAN_REVIEW = "human_review"
    REPORTING = "reporting"
    COMPLETED = "completed"
    COMPLETED_WITH_WARNINGS = "completed_with_warnings"
    CANCELLING = "cancelling"
    CANCELLED = "cancelled"
    FAILED = "failed"


class AuditStage(StrEnum):
    INGESTING = "ingesting"
    PREPROCESSING = "preprocessing"
    STATIC_SCANNING = "static_scanning"
    SEMANTIC_AUDITING = "semantic_auditing"
    DYNAMIC_VERIFYING = "dynamic_verifying"
    MACHINE_REVIEW = "machine_review"
    HUMAN_REVIEW = "human_review"
    REPORTING = "reporting"


class AuditTaskType(StrEnum):
    INVENTORY = "inventory"
    BUILD = "build"
    SAST = "sast"
    DEPENDENCY_SCAN = "dependency_scan"
    SECRET_SCAN = "secret_scan"
    CONFIG_SCAN = "config_scan"
    SEMANTIC_REVIEW = "semantic_review"
    DYNAMIC_VERIFY = "dynamic_verify"
    INDEPENDENT_VERIFY = "independent_verify"
    COVERAGE_CHECK = "coverage_check"
    REPORT = "report"


class AuditTaskStatus(StrEnum):
    QUEUED = "queued"
    CLAIMED = "claimed"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingConfidence(StrEnum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FindingStatus(StrEnum):
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    MACHINE_CONFIRMED = "machine_confirmed"
    AWAITING_HUMAN_REVIEW = "awaiting_human_review"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    ACCEPTED_RISK = "accepted_risk"


class RuntimeVerificationStatus(StrEnum):
    VERIFIED = "verified"
    UNVERIFIED = "unverified"
    NOT_APPLICABLE = "not_applicable"


class LocationRole(StrEnum):
    ENTRYPOINT = "entrypoint"
    SOURCE = "source"
    PROPAGATION = "propagation"
    SINK = "sink"
    RELATED = "related"


class LocationOriginKind(StrEnum):
    SOURCE = "source"
    BYTECODE = "bytecode"
    CONFIG = "config"
    DECOMPILED = "decompiled"


class ArtifactKind(StrEnum):
    SOURCE_UPLOAD = "source_upload"
    SOURCE_SNAPSHOT = "source_snapshot"
    SCAN_RESULT = "scan_result"
    BUILD_LOG = "build_log"
    RUNTIME_LOG = "runtime_log"
    POC = "poc"
    REPORT = "report"
    OTHER = "other"


class ArtifactAccessLevel(StrEnum):
    NORMAL = "normal"
    SENSITIVE = "sensitive"


class EvidenceType(StrEnum):
    CODE_SNIPPET = "code_snippet"
    CALL_TRACE = "call_trace"
    TOOL_RESULT = "tool_result"
    BUILD_LOG = "build_log"
    UNIT_TEST = "unit_test"
    POC_OUTPUT = "poc_output"
    HTTP_EXCHANGE = "http_exchange"
    RUNTIME_LOG = "runtime_log"


class VerificationMethod(StrEnum):
    STATIC_CORROBORATION = "static_corroboration"
    INDEPENDENT_AGENT = "independent_agent"
    BUILD_TEST = "build_test"
    DYNAMIC_POC = "dynamic_poc"


class VerificationVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"


class BuildStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


class ReviewVerdict(StrEnum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"
    ACCEPTED_RISK = "accepted_risk"
    REVERIFY = "reverify"


class AuditFactKind(StrEnum):
    ARCHITECTURE = "architecture"
    ENTRYPOINT = "entrypoint"
    TRUST_BOUNDARY = "trust_boundary"
    SOURCE = "source"
    SINK = "sink"
    CANDIDATE_FINDING = "candidate_finding"
    VERIFICATION_RESULT = "verification_result"


class AuditIntentStatus(StrEnum):
    PENDING = "pending"
    CLAIMED = "claimed"
    CONCLUDED = "concluded"
    CANCELLED = "cancelled"


class UserRole(StrEnum):
    """The four single-tenant roles of §9.8.

    Ordered from most to least privileged, but the order is documentation
    only: authorisation is a membership test against an explicit set per
    endpoint, never a comparison, so a new role cannot silently inherit
    permissions by being inserted at the right position.
    """

    ADMIN = "admin"
    AUDITOR = "auditor"
    REVIEWER = "reviewer"
    VIEWER = "viewer"


class AuditLogAction(StrEnum):
    """The operations §9.8 requires in the operator audit log.

    Deliberately not a database CHECK constraint: the set grows with every
    feature that touches a sensitive resource, and a constraint would turn each
    addition into a migration. The single writer is ``AuditLogService.record``,
    which takes this enum, so the column cannot receive a free-form string.
    """

    LOGIN_SUCCEEDED = "login_succeeded"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    ACCESS_DENIED = "access_denied"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_PASSWORD_CHANGED = "user_password_changed"
    REPOSITORY_CREATED = "repository_created"
    REPOSITORY_DELETED = "repository_deleted"
    CREDENTIAL_CREATED = "credential_created"
    CREDENTIAL_DELETED = "credential_deleted"
    MODEL_PROVIDER_UPDATED = "model_provider_updated"
    UPLOAD_CREATED = "upload_created"
    SNAPSHOT_CREATED = "snapshot_created"
    POLICY_CREATED = "policy_created"
    AUDIT_RUN_CREATED = "audit_run_created"
    AUDIT_RUN_CANCELLED = "audit_run_cancelled"
    AUDIT_RUN_RETRIED = "audit_run_retried"
    AUDIT_RUN_DELETED = "audit_run_deleted"
    FINDING_REVIEWED = "finding_reviewed"
    FINDING_REVERIFY_REQUESTED = "finding_reverify_requested"
    ARTIFACT_DOWNLOADED = "artifact_downloaded"
    REPORT_GENERATED = "report_generated"
    REPORT_DOWNLOADED = "report_downloaded"
