from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)


from cairn.sandbox.services import ServiceKind

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
StorageKey = Annotated[
    str,
    StringConstraints(pattern=r"^sha256/[0-9a-f]{2}/[0-9a-f]{64}$"),
]
# base64url(payload).base64url(mac), as minted by cairn.gateway.tokens.
GrantToken = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z0-9_-]{1,4096}\.[A-Za-z0-9_-]{1,256}$"),
]
# A snapshot-relative POSIX path. Kept deliberately narrow: these are index
# hints rendered into an operator-channel message, not paths the Manager opens.
RelativePath = Annotated[
    str,
    StringConstraints(pattern=r"^[^/\\][^\\]{0,1023}$"),
]
# Re-declared locally rather than imported from `cairn.analysis.contracts`, for
# the same reason as `SnapshotArtifact`: the Sandbox Manager depends on no
# analysis or semantic module.
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]{0,5}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SandboxTemplateName(StrEnum):
    ANALYSIS = "analysis"
    BUILD = "build"
    VALIDATION = "validation"
    SEMANTIC = "semantic"


class SandboxOperation(StrEnum):
    DEFAULT = "default"
    INVENTORY = "inventory"
    BINARY_INVENTORY = "binary-inventory"
    BYTECODE_INDEX = "bytecode-index"
    BUILD = "build"
    CODEQL = "codeql"
    SEMGREP = "semgrep"
    FINDSECBUGS = "findsecbugs"
    DEPENDENCY_CHECK = "dependency-check"
    TRIVY = "trivy"
    GITLEAKS = "gitleaks"
    CONFIG_RULES = "config-rules"
    SEMANTIC = "semantic"
    INDEPENDENT_VERIFY = "independent-verify"
    AUTHOR_POC = "author-poc"


class SandboxStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    RESOURCE_EXCEEDED = "resource_exceeded"


ACTIVE_SANDBOX_STATUSES = frozenset(
    {
        SandboxStatus.CREATED,
        SandboxStatus.RUNNING,
    }
)
TERMINAL_SANDBOX_STATUSES = frozenset(set(SandboxStatus) - ACTIVE_SANDBOX_STATUSES)


class SnapshotArtifact(StrictModel):
    storage_key: StorageKey
    sha256: Sha256
    size_bytes: int = Field(gt=0, le=4 * 1024 * 1024 * 1024)

    @model_validator(mode="after")
    def validate_content_address(self) -> "SnapshotArtifact":
        expected = f"sha256/{self.sha256[:2]}/{self.sha256}"
        if self.storage_key != expected:
            raise ValueError("storage_key must address the declared SHA-256")
        return self


class SandboxLimitsOverride(StrictModel):
    cpu_millis: int | None = Field(default=None, ge=100, le=16_000)
    memory_bytes: int | None = Field(
        default=None,
        ge=64 * 1024 * 1024,
        le=32 * 1024 * 1024 * 1024,
    )
    pids: int | None = Field(default=None, ge=16, le=4096)
    disk_bytes: int | None = Field(
        default=None,
        ge=16 * 1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
    )
    output_bytes: int | None = Field(
        default=None,
        ge=1024 * 1024,
        le=16 * 1024 * 1024 * 1024,
    )
    tmpfs_bytes: int | None = Field(
        default=None,
        ge=1024 * 1024,
        le=4 * 1024 * 1024 * 1024,
    )
    timeout_seconds: int | None = Field(default=None, ge=1, le=24 * 60 * 60)


class SandboxLimits(StrictModel):
    cpu_millis: int = Field(ge=100, le=16_000)
    memory_bytes: int = Field(
        ge=64 * 1024 * 1024,
        le=32 * 1024 * 1024 * 1024,
    )
    pids: int = Field(ge=16, le=4096)
    disk_bytes: int = Field(
        ge=16 * 1024 * 1024,
        le=64 * 1024 * 1024 * 1024,
    )
    output_bytes: int = Field(
        ge=1024 * 1024,
        le=16 * 1024 * 1024 * 1024,
    )
    tmpfs_bytes: int = Field(
        ge=1024 * 1024,
        le=4 * 1024 * 1024 * 1024,
    )
    timeout_seconds: int = Field(ge=1, le=24 * 60 * 60)

    @model_validator(mode="after")
    def validate_related_limits(self) -> "SandboxLimits":
        if self.output_bytes > self.disk_bytes:
            raise ValueError("output_bytes must not exceed disk_bytes")
        if self.tmpfs_bytes > self.memory_bytes:
            raise ValueError("tmpfs_bytes must not exceed memory_bytes")
        return self


class SemanticScopeSpec(StrictModel):
    """One semantic review assignment, as it crosses the Sandbox API.

    Deliberately a local wire type rather than an import of
    ``cairn.semantic.findings.ReviewScope``: this package re-declares every
    shape it accepts (see :class:`SnapshotArtifact`) so the Sandbox Manager
    stays independent of the analysis and semantic packages. The in-container
    runner parses the file back into a real ``ReviewScope``.
    """

    module: str = Field(min_length=1, max_length=1024)
    attack_surface: str = Field(min_length=1, max_length=255)
    category: str = Field(min_length=1, max_length=255)
    scope_key: str = Field(min_length=1, max_length=128)
    entrypoint_paths: list[RelativePath] = Field(default_factory=list, max_length=64)

    @field_validator("entrypoint_paths")
    @classmethod
    def reject_traversal(cls, value: list[str]) -> list[str]:
        # These are never opened here, only rendered into the assignment the
        # reviewer reads. A hint that reads `../../etc/passwd` is not something
        # the index produces, so accepting one would only launder an
        # attacker-supplied string into a platform-authored message.
        for path in value:
            if any(part in {"", ".", ".."} for part in path.split("/")):
                raise ValueError("entrypoint hints must be plain relative paths")
        return value


class VerifyLocationSpec(StrictModel):
    """One reported code location, as the blind reviewer is allowed to see it."""

    path: RelativePath
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str | None = Field(default=None, max_length=1024)
    role: Literal["entrypoint", "source", "propagation", "sink", "related"]

    @model_validator(mode="after")
    def validate_range(self) -> "VerifyLocationSpec":
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if any(part in {"", ".", ".."} for part in self.path.split("/")):
            raise ValueError("location path must be a plain relative path")
        return self


class VerifyCandidateSpec(StrictModel):
    """The candidate an Independent Reviewer is given (§7.8).

    §7.8 says the independent worker "只获得候选类别、源码位置和必要上下文，并
    自行重建调用链" — it receives the category, the code locations and the
    necessary context, and rebuilds the call chain itself. It must not read the
    reporting worker's free-form reasoning.

    That rule is enforced by this shape rather than by the caller's discipline.
    ``StrictModel`` forbids extra fields, and there is no field here for
    ``message``, ``controllability``, ``call_chain``, ``attack_preconditions``,
    ``impact`` or ``existing_defenses``. A request carrying any of them is a
    validation error, so the blindness cannot be lost by someone filling in one
    more field that looked helpful.
    """

    root_cause_key: Sha256
    module: str = Field(min_length=1, max_length=1024)
    category: str = Field(min_length=1, max_length=255)
    cwe_ids: list[CweId] = Field(default_factory=list, max_length=16)
    sink: str | None = Field(default=None, max_length=1024)
    locations: list[VerifyLocationSpec] = Field(min_length=1, max_length=64)


class PocAssignmentSpec(StrictModel):
    """The Finding a PoC Author is asked to demonstrate (§7.7).

    Unlike :class:`VerifyCandidateSpec`, this is not blind: the author reads the
    source and writes a request, so it carries the entrypoint route the request
    must address. It still carries no free-form analysis — the author derives
    its own from the code — and its shape is fixed here rather than left to the
    caller.
    """

    finding_id: str = Field(min_length=1, max_length=64)
    module: str = Field(min_length=1, max_length=1024)
    category: str = Field(min_length=1, max_length=255)
    cwe_ids: list[CweId] = Field(default_factory=list, max_length=16)
    sink: str | None = Field(default=None, max_length=1024)
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    route: str | None = Field(default=None, max_length=1024)
    route_prefixes: list[str] = Field(default_factory=list, max_length=8)
    locations: list[VerifyLocationSpec] = Field(default_factory=list, max_length=64)


class SemanticSandboxSpec(StrictModel):
    """The credential and assignment a model-backed review needs to run.

    This is the *only* way anything caller-supplied reaches the container
    environment. It is a closed, typed block rather than a free-form
    environment mapping, so the request schema keeps refusing caller-chosen
    variables (design spec §9.7).

    Exactly one assignment is carried: a ``scope`` for the Semantic Reviewer, a
    ``candidate`` for the Independent Reviewer, or a ``poc`` for the PoC Author.
    Which one is required is decided by :class:`SandboxCreateRequest`, which
    knows the operation.
    """

    grant_token: GrantToken
    gateway_url: str = Field(min_length=1, max_length=2048)
    scope: SemanticScopeSpec | None = None
    candidate: VerifyCandidateSpec | None = None
    poc: PocAssignmentSpec | None = None

    @model_validator(mode="after")
    def validate_spec(self) -> "SemanticSandboxSpec":
        present = sum(
            assignment is not None
            for assignment in (self.scope, self.candidate, self.poc)
        )
        if present != 1:
            raise ValueError(
                "a semantic block carries exactly one of scope, candidate or poc"
            )
        parsed = urlsplit(self.gateway_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("gateway_url must be an HTTP(S) service origin")
        return self


class DynamicTargetSpec(StrictModel):
    """One Finding the dynamic verifier should try to exercise.

    Like :class:`VerifyCandidateSpec`, this carries only what the probe needs
    to construct a request — never the analysis behind the Finding. The probes
    are platform-authored and category-driven, so no prose is required and none
    can travel.
    """

    finding_id: UUID
    category: str = Field(min_length=1, max_length=255)
    # Route metadata as the deterministic index recorded it. `route` may be a
    # method-level suffix, because the index does not resolve class-level
    # @RequestMapping prefixes; `route_prefixes` carries the candidates the
    # probe should try in order before giving up as inconclusive.
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    route: str | None = Field(default=None, max_length=1024)
    route_prefixes: list[str] = Field(default_factory=list, max_length=8)
    parameter: str | None = Field(default=None, max_length=255)


class PocRequestSpec(StrictModel):
    """A model-authored request template, as it crosses the Sandbox API.

    Re-declared locally rather than imported from ``cairn.poc.contracts`` for
    the same reason as every other wire type here: the Sandbox Manager depends
    on no analysis, semantic or poc module. The in-container executor parses it
    back into a real ``PocPlan`` and re-validates it, so the platform-side gate
    runs on both sides of the boundary.
    """

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    path: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(default=None, max_length=8192)


class PocInjectionSpec(StrictModel):
    location: Literal["query", "path", "header", "body_field"]
    name: str = Field(min_length=1, max_length=255)
    benign: str = Field(max_length=2048)
    payload: str = Field(max_length=2048)


class PocCriterionSpec(StrictModel):
    kind: Literal[
        "contains_text",
        "status_code_is",
        "status_code_differs",
        "elapsed_exceeds_ms",
        "echo_nonce_observed",
    ]
    match_text: str | None = Field(default=None, max_length=256)
    status_code: int | None = Field(default=None, ge=100, le=599)
    elapsed_ms: int | None = Field(default=None, ge=250, le=60_000)


class PocPlanSpec(StrictModel):
    """A validated PoC the executor should run. Shape mirrors ``PocPlan``."""

    finding_id: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=255)
    request: PocRequestSpec
    injection: PocInjectionSpec
    criterion: PocCriterionSpec
    rationale: str = Field(min_length=1, max_length=4096)


class DynamicSandboxSpec(StrictModel):
    """Everything a validation Sandbox needs, as a closed typed block.

    The caller names service *kinds*, never images; the runnable artifact is an
    Artifact descriptor, never a host path; and both the probe plan and the
    authored PoCs are fixed shapes. Subproject three's property survives the
    arrival of dependency containers.
    """

    build_output: SnapshotArtifact
    app_jar: RelativePath
    app_port: int = Field(default=8080, ge=1, le=65535)
    services: list[ServiceKind] = Field(default_factory=list, max_length=8)
    targets: list[DynamicTargetSpec] = Field(default_factory=list, max_length=256)
    poc_plans: list[PocPlanSpec] = Field(default_factory=list, max_length=256)

    @model_validator(mode="after")
    def validate_services(self) -> "DynamicSandboxSpec":
        if len(set(self.services)) != len(self.services):
            raise ValueError("dependency services must be unique")
        return self


class SandboxCreateRequest(StrictModel):
    template: SandboxTemplateName
    operation: SandboxOperation = SandboxOperation.DEFAULT
    snapshot: SnapshotArtifact
    task_id: UUID | None = None
    limits: SandboxLimitsOverride = Field(default_factory=SandboxLimitsOverride)
    semantic: SemanticSandboxSpec | None = None
    dynamic: DynamicSandboxSpec | None = None

    @model_validator(mode="after")
    def validate_dynamic_block(self) -> "SandboxCreateRequest":
        # Required for the validation template and refused for every other one,
        # so no other template can start dependency containers.
        wants_dynamic = self.template is SandboxTemplateName.VALIDATION
        if wants_dynamic and self.dynamic is None:
            raise ValueError("the validation template requires a dynamic block")
        if not wants_dynamic and self.dynamic is not None:
            raise ValueError("only the validation template accepts a dynamic block")
        return self

    @model_validator(mode="after")
    def validate_semantic_block(self) -> "SandboxCreateRequest":
        # Required for the semantic template and refused for every other one,
        # so no other template can be handed a model credential.
        wants_semantic = self.template is SandboxTemplateName.SEMANTIC
        if wants_semantic and self.semantic is None:
            raise ValueError("the semantic template requires a semantic block")
        if not wants_semantic and self.semantic is not None:
            raise ValueError("only the semantic template accepts a semantic block")
        if self.semantic is None:
            return self
        # The assignment has to match the operation, so no worker is handed the
        # wrong kind of task: a verify candidate audited as a scope, a scope
        # given to a reviewer with nothing to verify, or a PoC author with no
        # finding to demonstrate.
        if self.operation is SandboxOperation.INDEPENDENT_VERIFY:
            if self.semantic.candidate is None:
                raise ValueError("independent-verify requires a candidate assignment")
        elif self.operation is SandboxOperation.AUTHOR_POC:
            if self.semantic.poc is None:
                raise ValueError("author-poc requires a poc assignment")
        elif self.semantic.scope is None:
            raise ValueError("a semantic review requires a scope assignment")
        return self


class SandboxWaitRequest(StrictModel):
    timeout_seconds: float = Field(default=0, ge=0, le=30)


class SandboxArtifact(StrictModel):
    storage_key: StorageKey
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    media_type: str = Field(min_length=1, max_length=255)


class SandboxRecord(StrictModel):
    id: UUID
    task_id: UUID | None = None
    template: SandboxTemplateName
    operation: SandboxOperation = SandboxOperation.DEFAULT
    snapshot: SnapshotArtifact
    limits: SandboxLimits
    status: SandboxStatus
    created_at: datetime
    deadline_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    exit_code: int | None = None
    failure_code: str | None = Field(default=None, max_length=128)
    artifacts: list[SandboxArtifact] = Field(default_factory=list)
    resources_destroyed: bool = False
