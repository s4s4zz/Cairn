from enum import StrEnum


class SourceType(StrEnum):
    GIT = "git"
    ZIP = "zip"
    LOCAL_UPLOAD = "local_upload"


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


class ArtifactKind(StrEnum):
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
