from __future__ import annotations

import unicodedata
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    AfterValidator,
    StringConstraints,
    field_validator,
    model_validator,
)


def _validate_relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError("path must be a normalized relative POSIX path")
    return value


RelativePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=1024),
    AfterValidator(_validate_relative_path),
]


def _validate_code_path(value: str) -> str:
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("path must be NFC-normalized")
    if any(unicodedata.category(character) == "Cc" for character in value):
        raise ValueError("path must not contain control characters")
    segments = value.split("!/")
    if any(not segment for segment in segments):
        raise ValueError("path must not contain an empty archive segment")
    for segment in segments:
        path = PurePosixPath(segment)
        if (
            segment.startswith("/")
            or "\\" in segment
            or any(part in {"", ".", ".."} for part in path.parts)
            or (path.parts and ":" in path.parts[0])
            or path.as_posix() != segment
        ):
            raise ValueError("path must be a normalized relative POSIX path")
    if len(value.encode("utf-8")) > 4096:
        raise ValueError("path exceeds the encoded length limit")
    return value


CodePath = Annotated[
    str,
    StringConstraints(min_length=1, max_length=4096),
    AfterValidator(_validate_code_path),
]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]{0,5}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AnalysisOperation(StrEnum):
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


SCANNER_OPERATIONS = frozenset(
    {
        AnalysisOperation.CODEQL,
        AnalysisOperation.SEMGREP,
        AnalysisOperation.FINDSECBUGS,
        AnalysisOperation.DEPENDENCY_CHECK,
        AnalysisOperation.TRIVY,
        AnalysisOperation.GITLEAKS,
        AnalysisOperation.CONFIG_RULES,
    }
)
BYTECODE_SCANNERS = frozenset(
    {
        AnalysisOperation.CODEQL,
        AnalysisOperation.FINDSECBUGS,
    }
)


class ToolStatus(StrEnum):
    COMPLETED = "completed"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    SKIPPED = "skipped"


class CandidateSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CandidateConfidence(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CandidateLocation(StrictModel):
    path: RelativePath
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, max_length=1024)
    role: Literal["source", "sink", "related"] = "related"

    @model_validator(mode="after")
    def validate_range(self) -> "CandidateLocation":
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        if (
            self.start_column is not None
            and self.end_column is not None
            and self.end_line == self.start_line
            and self.end_column < self.start_column
        ):
            raise ValueError("end_column must not precede start_column")
        return self


class CallChainStep(StrictModel):
    path: RelativePath
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    symbol: str = Field(min_length=1, max_length=1024)
    role: Literal["entrypoint", "source", "propagation", "sink"]
    note: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def validate_range(self) -> "CallChainStep":
        if self.end_line < self.start_line:
            raise ValueError("end_line must not precede start_line")
        return self


class CodeLocationV2(StrictModel):
    """A source-independent location anchored to immutable snapshot evidence."""

    origin_kind: Literal["source", "bytecode", "config", "decompiled"]
    container_path: CodePath | None = None
    entry_path: CodePath | None = None
    class_name: str | None = Field(default=None, max_length=2048)
    method_name: str | None = Field(default=None, max_length=1024)
    method_descriptor: str | None = Field(default=None, max_length=4096)
    bytecode_offset: int | None = Field(default=None, ge=0)
    source_path: CodePath | None = None
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    decompiled_artifact_id: UUID | None = None
    decompiled_start_line: int | None = Field(default=None, ge=1)
    decompiled_end_line: int | None = Field(default=None, ge=1)
    symbol: str | None = Field(default=None, max_length=1024)
    role: Literal["entrypoint", "source", "propagation", "sink", "related"] = (
        "related"
    )

    @model_validator(mode="after")
    def validate_evidence_shape(self) -> "CodeLocationV2":
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("source line range must be wholly present or absent")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line must not precede start_line")
        if (self.decompiled_start_line is None) != (
            self.decompiled_end_line is None
        ):
            raise ValueError(
                "decompiled line range must be wholly present or absent"
            )
        if (
            self.decompiled_start_line is not None
            and self.decompiled_end_line is not None
            and self.decompiled_end_line < self.decompiled_start_line
        ):
            raise ValueError(
                "decompiled_end_line must not precede decompiled_start_line"
            )
        if (self.method_name is None) != (self.method_descriptor is None):
            raise ValueError("method name and descriptor must be provided together")
        if self.bytecode_offset is not None and self.method_name is None:
            raise ValueError("bytecode offset requires a method identity")
        if self.origin_kind in {"bytecode", "decompiled"}:
            if self.entry_path is None or self.class_name is None:
                raise ValueError(
                    "bytecode locations require entry_path and class_name"
                )
        if self.origin_kind == "source":
            if self.source_path is None or self.start_line is None:
                raise ValueError("source locations require a path and line range")
        if self.origin_kind == "config" and not (
            self.source_path or self.entry_path
        ):
            raise ValueError("config locations require a source or archive path")
        if self.origin_kind == "decompiled" and self.decompiled_artifact_id is None:
            raise ValueError("decompiled locations require their Artifact")
        if (
            self.decompiled_start_line is not None
            and self.decompiled_artifact_id is None
        ):
            raise ValueError("decompiled line range requires its Artifact")
        return self


class CodeCallChainStepV2(CodeLocationV2):
    role: Literal["entrypoint", "source", "propagation", "sink"]
    note: str | None = Field(default=None, max_length=2048)

    @model_validator(mode="after")
    def validate_method_location(self) -> "CodeCallChainStepV2":
        if self.origin_kind in {"bytecode", "decompiled"} and self.method_name is None:
            raise ValueError("bytecode call-chain steps require a method identity")
        return self


class ExistingDefense(StrictModel):
    mechanism: str = Field(min_length=1, max_length=512)
    effective: bool
    reasoning: str = Field(min_length=1, max_length=4096)


class CandidateFinding(StrictModel):
    rule_id: str = Field(min_length=1, max_length=512)
    cwe_ids: list[CweId] = Field(default_factory=list)
    category: str = Field(min_length=1, max_length=255)
    severity: CandidateSeverity
    confidence: CandidateConfidence
    message: str = Field(min_length=1, max_length=16_384)
    locations: list[CandidateLocation | CodeLocationV2] = Field(
        min_length=1,
        max_length=128,
    )
    sink: str | None = Field(default=None, max_length=1024)
    fingerprint: Sha256
    root_cause_key: Sha256
    discovered_by: list[str] = Field(min_length=1, max_length=16)
    source_rules: list[str] = Field(min_length=1, max_length=64)
    call_chain: list[CallChainStep | CodeCallChainStepV2] = Field(
        default_factory=list,
        max_length=64,
    )
    controllability: str | None = Field(default=None, max_length=8192)
    existing_defenses: list[ExistingDefense] = Field(
        default_factory=list,
        max_length=32,
    )
    attack_preconditions: str | None = Field(default=None, max_length=8192)
    impact: str | None = Field(default=None, max_length=8192)
    recommended_verification: str | None = Field(default=None, max_length=8192)
    severity_conflict: list[dict[str, object]] = Field(
        default_factory=list,
        max_length=32,
    )

    @field_validator("cwe_ids")
    @classmethod
    def unique_numeric_sorted_cwe_ids(cls, values: list[str]) -> list[str]:
        # CWE ids are canonically ordered by numeric id, matching
        # `normalize_cwe_ids`. Ordering them as plain strings would place
        # CWE-611 before CWE-89 and reject every candidate that mixes two- and
        # three-digit weaknesses.
        if len(set(values)) != len(values):
            raise ValueError("values must be sorted and unique")
        if values != sorted(values, key=lambda value: int(value.split("-", 1)[1])):
            raise ValueError("values must be sorted and unique")
        return values

    @field_validator("discovered_by", "source_rules")
    @classmethod
    def unique_sorted_values(cls, values: list[str]) -> list[str]:
        if values != sorted(set(values)):
            raise ValueError("values must be sorted and unique")
        return values


class ModuleRecord(StrictModel):
    path: str = Field(min_length=1, max_length=1024)
    name: str = Field(min_length=1, max_length=512)
    build_system: Literal["maven", "gradle", "unknown"]
    descriptor: RelativePath | None = None
    parent_path: str | None = Field(default=None, max_length=1024)
    java_versions: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)


class ModuleDependency(StrictModel):
    source: str = Field(min_length=1, max_length=1024)
    target: str = Field(min_length=1, max_length=1024)
    kind: Literal["maven", "gradle"]


class BuildStep(StrictModel):
    module_path: str = Field(min_length=1, max_length=1024)
    build_system: Literal["maven", "gradle"]
    runner: Literal["maven-wrapper", "maven", "gradle-wrapper", "gradle"]
    argv: list[str] = Field(min_length=1, max_length=32)


class SymbolRecord(StrictModel):
    path: RelativePath
    line: int = Field(ge=1)
    kind: Literal["package", "type", "method", "annotation"]
    name: str = Field(min_length=1, max_length=1024)
    container: str | None = Field(default=None, max_length=1024)


class EntrypointRecord(StrictModel):
    path: RelativePath
    line: int = Field(ge=1)
    kind: str = Field(min_length=1, max_length=64)
    symbol: str = Field(min_length=1, max_length=1024)
    route: str | None = Field(default=None, max_length=2048)
    annotations: list[str] = Field(default_factory=list)


class PermissionRecord(StrictModel):
    path: RelativePath
    line: int = Field(ge=1)
    kind: str = Field(min_length=1, max_length=64)
    symbol: str | None = Field(default=None, max_length=1024)
    expression: str | None = Field(default=None, max_length=4096)


class InterceptorRecord(StrictModel):
    """One member of the request pipeline that can gate an entrypoint (图二).

    A servlet ``Filter``, a Spring ``HandlerInterceptor``, or a member of a
    Spring Security filter chain — whatever the container runs before the
    handler. ``enforces_auth`` is the deterministic topology's conservative
    read of whether this interceptor performs authentication/authorization at
    all; whether its logic is *correct* is a semantic question, never decided
    here.
    """

    kind: Literal["servlet-filter", "spring-interceptor", "security-chain", "custom"]
    class_name: str = Field(min_length=1, max_length=2048)
    url_patterns: list[str] = Field(default_factory=list, max_length=256)
    dispatcher_types: list[str] = Field(default_factory=list, max_length=8)
    order: int | None = None
    enforces_auth: bool = False
    source: Literal["web.xml", "annotation", "java-config", "xml-config"]
    path: RelativePath
    line: int = Field(ge=1)


class AuthBinding(StrictModel):
    """How the deterministic topology sees one entrypoint's authorization (图二).

    ``covered_by`` lists the ``class_name`` of every auth-enforcing interceptor
    whose URL patterns match this entrypoint's route; ``declared_auth`` carries
    method/class-level annotation expressions (e.g. ``hasRole('ADMIN')``).
    ``unprotected`` is set only for a *structural* gap — no matching auth
    interceptor and no auth annotation — which is exactly the deterministic
    bypass the platform is entitled to claim without reading any handler body.
    """

    entrypoint_path: RelativePath
    entrypoint_line: int = Field(ge=1)
    entrypoint_symbol: str | None = Field(default=None, max_length=1024)
    route: str | None = Field(default=None, max_length=2048)
    covered_by: list[str] = Field(default_factory=list, max_length=64)
    declared_auth: list[str] = Field(default_factory=list, max_length=32)
    unprotected: bool = False
    reason: str | None = Field(default=None, max_length=512)


class DataFlowRecord(StrictModel):
    path: RelativePath
    line: int = Field(ge=1)
    kind: str = Field(min_length=1, max_length=128)
    symbol: str | None = Field(default=None, max_length=1024)
    cwe_ids: list[CweId] = Field(default_factory=list)


class PathClassification(StrictModel):
    path: RelativePath
    kind: str = Field(min_length=1, max_length=64)


class RuntimePlan(StrictModel):
    """What the application needs at runtime, for dynamic verification (§7.7).

    Distinct from ``build_plan``, which is the sequence of build commands.
    ``services`` names members of the closed dependency set the Sandbox Manager
    is willing to start; an unrecognised datasource yields nothing rather than
    a guess, which downgrades verification to inconclusive.
    """

    services: list[Literal["postgres", "mysql", "redis", "echo"]] = Field(
        default_factory=list,
        max_length=8,
    )
    app_port: int = Field(default=8080, ge=1, le=65535)
    config_paths: list[RelativePath] = Field(default_factory=list, max_length=32)


class InventoryResult(StrictModel):
    build_system: Literal["maven", "gradle", "mixed", "unknown"]
    java_versions: list[str] = Field(default_factory=list)
    modules: list[ModuleRecord]
    module_dependencies: list[ModuleDependency]
    build_plan: list[BuildStep]
    runtime_plan: RuntimePlan = Field(default_factory=RuntimePlan)
    symbols: list[SymbolRecord]
    entrypoints: list[EntrypointRecord]
    permissions: list[PermissionRecord]
    interceptors: list[InterceptorRecord] = Field(default_factory=list)
    auth_bindings: list[AuthBinding] = Field(default_factory=list)
    sources: list[DataFlowRecord]
    sinks: list[DataFlowRecord]
    classified_paths: list[PathClassification]
    java_files_total: int = Field(ge=0)
    skipped_paths: list[str] = Field(default_factory=list)
    unsupported_components: list[dict[str, object]] = Field(default_factory=list)


class BinaryComponent(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    depth: int = Field(ge=0, le=32)
    kind: Literal["jar", "war", "ear", "zip"]
    manifest: dict[str, str] = Field(default_factory=dict)
    coordinates: list[dict[str, str]] = Field(default_factory=list, max_length=256)
    signature_metadata_present: bool
    signature_verified: Literal[False]
    multi_release: bool


class BinaryInventoryEntry(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    kind: Literal["class", "archive", "resource"]
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    archive_depth: int = Field(ge=0, le=32)
    classfile_major: int | None = Field(default=None, ge=45, le=100)
    classfile_minor: int | None = Field(default=None, ge=0, le=65535)
    constant_pool_count: int | None = Field(default=None, ge=1, le=65535)
    validation: Literal["header-only"] | None = None
    multi_release_version: int | None = Field(default=None, ge=9, le=100)
    selected: bool | None = None
    resource_kind: str | None = Field(default=None, max_length=128)

    @model_validator(mode="after")
    def validate_kind_fields(self) -> "BinaryInventoryEntry":
        class_fields = (
            self.classfile_major,
            self.classfile_minor,
            self.constant_pool_count,
            self.validation,
            self.selected,
        )
        if self.kind == "class" and any(value is None for value in class_fields):
            raise ValueError("class entry requires its header validation fields")
        if self.kind != "class" and any(value is not None for value in class_fields):
            raise ValueError("non-class entry cannot carry class header fields")
        if self.kind == "resource" and self.resource_kind is None:
            raise ValueError("resource entry requires resource_kind")
        if self.kind != "resource" and self.resource_kind is not None:
            raise ValueError("non-resource entry cannot carry resource_kind")
        return self


class BinaryResource(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str = Field(min_length=1, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    kind: str = Field(min_length=1, max_length=128)
    sha256: Sha256
    size_bytes: int = Field(ge=0)
    # Deployment descriptors (web.xml) and Spring Security XML keep their text
    # for the bytecode authorization topology (图二 v2); other resources do not.
    content: str | None = Field(default=None, max_length=262_144)


class BinaryCoverageGap(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    reason_code: str = Field(min_length=1, max_length=128)
    detail: str = Field(min_length=1, max_length=4096)


class BinaryInventoryResult(StrictModel):
    contract: Literal["cairn-binary-inventory-v1"]
    target_java_version: int = Field(ge=5, le=100)
    components: list[BinaryComponent] = Field(max_length=100_000)
    entries: list[BinaryInventoryEntry] = Field(max_length=100_000)
    resources: list[BinaryResource] = Field(max_length=100_000)
    coverage_gaps: list[BinaryCoverageGap] = Field(max_length=100_000)
    archive_count: int = Field(ge=0)
    class_entry_count: int = Field(ge=0)
    selected_class_count: int = Field(ge=0)
    expanded_entry_count: int = Field(ge=0)
    expanded_bytes: int = Field(ge=0)
    sbom: dict[str, object]

    @model_validator(mode="after")
    def validate_counts(self) -> "BinaryInventoryResult":
        if self.archive_count != len(self.components):
            raise ValueError("archive_count must match components")
        class_entries = [entry for entry in self.entries if entry.kind == "class"]
        if self.class_entry_count != len(class_entries):
            raise ValueError("class_entry_count must match entries")
        if self.selected_class_count != sum(entry.selected is True for entry in class_entries):
            raise ValueError("selected_class_count must match selected class entries")
        return self


class AnnotationDetail(StrictModel):
    """One annotation with its string-valued members (图二 v2).

    The values the ASM indexer captured from a bytecode annotation — enough for
    route, urlPatterns, @Order and authorization expressions. Values are
    stringified; an array member becomes a list. Nested annotations are skipped.
    """

    descriptor: str = Field(min_length=1, max_length=2048)
    members: dict[str, str | list[str]] = Field(default_factory=dict)


class BytecodeClassRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    super_name: str | None = Field(default=None, max_length=2048)
    interfaces: list[str] = Field(default_factory=list, max_length=1024)
    access: int = Field(ge=0)
    classfile_major: int = Field(ge=45, le=100)
    signature: str | None = Field(default=None, max_length=8192)
    source_file: str | None = Field(default=None, max_length=1024)
    annotations: list[str] = Field(default_factory=list, max_length=4096)
    annotation_details: list[AnnotationDetail] = Field(
        default_factory=list, max_length=4096
    )


class BytecodeMethodRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    method_name: str = Field(min_length=1, max_length=1024)
    method_descriptor: str = Field(min_length=1, max_length=4096)
    access: int = Field(ge=0)
    signature: str | None = Field(default=None, max_length=8192)
    exceptions: list[str] = Field(default_factory=list, max_length=1024)
    annotations: list[str] = Field(default_factory=list, max_length=4096)
    annotation_details: list[AnnotationDetail] = Field(
        default_factory=list, max_length=4096
    )
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    first_bytecode_offset: int | None = Field(default=None, ge=0)
    last_bytecode_offset: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_ranges(self) -> "BytecodeMethodRecord":
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("method source line range must be wholly present or absent")
        if self.start_line is not None and self.end_line < self.start_line:
            raise ValueError("method source line range is invalid")
        if (self.first_bytecode_offset is None) != (
            self.last_bytecode_offset is None
        ):
            raise ValueError("method bytecode range must be wholly present or absent")
        if (
            self.first_bytecode_offset is not None
            and self.last_bytecode_offset < self.first_bytecode_offset
        ):
            raise ValueError("method bytecode range is invalid")
        return self


class BytecodeFieldRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    name: str = Field(min_length=1, max_length=1024)
    descriptor: str = Field(min_length=1, max_length=4096)
    signature: str | None = Field(default=None, max_length=8192)
    access: int = Field(ge=0)


class BytecodeCallRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    method_name: str = Field(min_length=1, max_length=1024)
    method_descriptor: str = Field(min_length=1, max_length=4096)
    bytecode_offset: int = Field(ge=0)
    source_line: int | None = Field(default=None, ge=1)
    opcode: int = Field(ge=0, le=255)
    edge_kind: Literal["exact", "resolved", "inferred", "runtime"]
    target_owner: str | None = Field(default=None, min_length=1, max_length=2048)
    target_name: str | None = Field(default=None, min_length=1, max_length=1024)
    target_descriptor: str | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )
    interface: bool
    callsite_name: str | None = Field(default=None, min_length=1, max_length=1024)
    callsite_descriptor: str | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )
    bootstrap_owner: str | None = Field(default=None, min_length=1, max_length=2048)
    bootstrap_name: str | None = Field(default=None, max_length=1024)
    bootstrap_descriptor: str | None = Field(default=None, max_length=4096)

    @model_validator(mode="after")
    def validate_call_target(self) -> "BytecodeCallRecord":
        dynamic = self.opcode == 186
        target = (self.target_owner, self.target_name, self.target_descriptor)
        callsite = (self.callsite_name, self.callsite_descriptor)
        bootstrap = (
            self.bootstrap_owner,
            self.bootstrap_name,
            self.bootstrap_descriptor,
        )
        if dynamic:
            if any(value is not None for value in target):
                raise ValueError("invokedynamic cannot claim a resolved target")
            if any(value is None for value in callsite + bootstrap):
                raise ValueError("invokedynamic requires callsite and bootstrap metadata")
            if self.edge_kind != "inferred":
                raise ValueError("invokedynamic edge must remain inferred")
        else:
            if any(value is None for value in target):
                raise ValueError("method invocation requires a symbolic target")
            if any(value is not None for value in callsite + bootstrap):
                raise ValueError("ordinary invocation cannot carry dynamic metadata")
        return self


class BytecodeFieldAccessRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    container_path: str | None = Field(default=None, max_length=4096)
    entry_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    method_name: str = Field(min_length=1, max_length=1024)
    method_descriptor: str = Field(min_length=1, max_length=4096)
    bytecode_offset: int = Field(ge=0)
    source_line: int | None = Field(default=None, ge=1)
    opcode: int = Field(ge=0, le=255)
    target_owner: str = Field(min_length=1, max_length=2048)
    target_name: str = Field(min_length=1, max_length=1024)
    target_descriptor: str = Field(min_length=1, max_length=4096)


class BytecodeIndexGap(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256 | None = None
    reason_code: str = Field(min_length=1, max_length=128)
    detail: str = Field(min_length=1, max_length=4096)


class DecompiledViewRecord(StrictModel):
    logical_path: str = Field(min_length=1, max_length=4096)
    class_sha256: Sha256
    class_name: str = Field(min_length=1, max_length=2048)
    artifact_path: RelativePath
    decompiler: Literal["cfr"]
    decompiler_version: str = Field(min_length=1, max_length=64)


class ProgramIndexV2(StrictModel):
    contract: Literal["cairn-program-index-v2"]
    asm_version: str = Field(min_length=1, max_length=64)
    target_java_version: int = Field(ge=5, le=100)
    components: list[BinaryComponent] = Field(max_length=100_000)
    resources: list[BinaryResource] = Field(max_length=100_000)
    classes: list[BytecodeClassRecord] = Field(max_length=100_000)
    methods: list[BytecodeMethodRecord] = Field(max_length=2_000_000)
    fields: list[BytecodeFieldRecord] = Field(max_length=2_000_000)
    calls: list[BytecodeCallRecord] = Field(max_length=10_000_000)
    field_accesses: list[BytecodeFieldAccessRecord] = Field(max_length=10_000_000)
    decompiled_views: list[DecompiledViewRecord] = Field(max_length=100_000)
    coverage_gaps: list[BytecodeIndexGap] = Field(max_length=100_000)
    classes_total: int = Field(ge=0)
    classes_parsed: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_class_counts(self) -> "ProgramIndexV2":
        if self.classes_parsed != len(self.classes):
            raise ValueError("classes_parsed must match classes")
        if self.classes_parsed > self.classes_total:
            raise ValueError("classes_parsed cannot exceed classes_total")
        return self


class BinaryInventorySummary(StrictModel):
    contract: Literal["cairn-binary-inventory-summary-v1"]
    archive_count: int = Field(ge=0)
    class_entry_count: int = Field(ge=0)
    selected_class_count: int = Field(ge=0)
    expanded_entry_count: int = Field(ge=0)
    expanded_bytes: int = Field(ge=0)
    coverage_gap_count: int = Field(ge=0)


class ProgramIndexSummary(StrictModel):
    contract: Literal["cairn-program-index-summary-v1"]
    classes_total: int = Field(ge=0)
    classes_parsed: int = Field(ge=0)
    component_count: int = Field(ge=0)
    resource_count: int = Field(ge=0)
    method_count: int = Field(ge=0)
    call_count: int = Field(ge=0)
    field_access_count: int = Field(ge=0)
    decompiled_view_count: int = Field(ge=0)
    coverage_gap_count: int = Field(ge=0)


class CandidateResult(StrictModel):
    contract: Literal["cairn-candidate-result-v1"]
    candidates: list[CandidateFinding] = Field(max_length=100_000)


class BuildStepResult(StrictModel):
    module_path: str = Field(min_length=1, max_length=1024)
    build_system: Literal["maven", "gradle"]
    runner: Literal["maven-wrapper", "maven", "gradle-wrapper", "gradle"]
    status: ToolStatus
    exit_code: int | None = None
    log_path: RelativePath | None = None
    reason_code: str | None = Field(default=None, max_length=128)


class RunnableArtifact(StrictModel):
    """A build output the dynamic verifier can actually start (§7.7).

    Recorded per module so a multi-module repository can name which archive is
    the application rather than leaving the verifier to guess among several.
    """

    module_path: str = Field(min_length=1, max_length=1024)
    path: RelativePath
    build_system: Literal["maven", "gradle"]
    size_bytes: int = Field(ge=0)


class BuildResult(StrictModel):
    status: Literal["success", "partial", "failed"]
    steps: list[BuildStepResult]
    # Empty when the build failed or produced no archive, which is exactly the
    # §7.3 case where dynamic verification is marked unavailable rather than
    # attempted.
    runnable_artifacts: list[RunnableArtifact] = Field(
        default_factory=list,
        max_length=64,
    )


class AnalysisManifest(StrictModel):
    contract: Literal["cairn-deterministic-result-v1"]
    operation: AnalysisOperation
    status: ToolStatus
    tool_name: str = Field(min_length=1, max_length=128)
    tool_version: str | None = Field(default=None, max_length=255)
    reason_code: str | None = Field(default=None, max_length=128)
    warnings: list[dict[str, object]] = Field(default_factory=list)
    raw_result_paths: list[RelativePath] = Field(default_factory=list)
    inventory: InventoryResult | None = None
    binary_inventory: BinaryInventoryResult | None = None
    binary_inventory_path: RelativePath | None = None
    binary_inventory_summary: BinaryInventorySummary | None = None
    bytecode_index: ProgramIndexV2 | None = None
    bytecode_index_path: RelativePath | None = None
    bytecode_index_summary: ProgramIndexSummary | None = None
    build: BuildResult | None = None
    candidates: list[CandidateFinding] = Field(default_factory=list, max_length=100_000)
    candidates_path: RelativePath | None = None
    candidate_count: int | None = Field(default=None, ge=0, le=100_000)

    @model_validator(mode="after")
    def validate_operation_payload(self) -> "AnalysisManifest":
        if self.operation is AnalysisOperation.INVENTORY:
            if self.status is ToolStatus.COMPLETED and self.inventory is None:
                raise ValueError("completed inventory result requires inventory")
            if (
                self.binary_inventory is not None
                or self.binary_inventory_path is not None
                or self.binary_inventory_summary is not None
                or self.bytecode_index is not None
                or self.bytecode_index_path is not None
                or self.bytecode_index_summary is not None
                or self.build is not None
                or self.candidates
                or self.candidates_path is not None
            ):
                raise ValueError("inventory result contains an unrelated payload")
        elif self.operation is AnalysisOperation.BINARY_INVENTORY:
            referenced = (
                self.binary_inventory_path is not None
                and self.binary_inventory_summary is not None
            )
            if self.status is ToolStatus.COMPLETED and not (
                self.binary_inventory is not None or referenced
            ):
                raise ValueError(
                    "completed binary inventory result requires binary_inventory"
                )
            if (self.binary_inventory_path is None) != (
                self.binary_inventory_summary is None
            ):
                raise ValueError("binary inventory reference is incomplete")
            if (
                self.inventory is not None
                or self.bytecode_index is not None
                or self.bytecode_index_path is not None
                or self.bytecode_index_summary is not None
                or self.build is not None
                or self.candidates
                or self.candidates_path is not None
            ):
                raise ValueError("binary inventory result contains an unrelated payload")
        elif self.operation is AnalysisOperation.BYTECODE_INDEX:
            referenced = (
                self.bytecode_index_path is not None
                and self.bytecode_index_summary is not None
            )
            if self.status is ToolStatus.COMPLETED and not (
                self.bytecode_index is not None or referenced
            ):
                raise ValueError(
                    "completed bytecode index result requires bytecode_index"
                )
            if (self.bytecode_index_path is None) != (
                self.bytecode_index_summary is None
            ):
                raise ValueError("bytecode index reference is incomplete")
            if (self.candidates_path is None) != (self.candidate_count is None):
                raise ValueError("candidate result reference is incomplete")
            if (
                self.inventory is not None
                or self.binary_inventory is not None
                or self.binary_inventory_path is not None
                or self.binary_inventory_summary is not None
                or self.build is not None
            ):
                raise ValueError("bytecode index result contains an unrelated payload")
        elif self.operation is AnalysisOperation.BUILD:
            if self.status is ToolStatus.COMPLETED and self.build is None:
                raise ValueError("completed build result requires build")
            if (
                self.inventory is not None
                or self.binary_inventory is not None
                or self.binary_inventory_path is not None
                or self.binary_inventory_summary is not None
                or self.bytecode_index is not None
                or self.bytecode_index_path is not None
                or self.bytecode_index_summary is not None
                or self.candidates
                or self.candidates_path is not None
            ):
                raise ValueError("build result contains an unrelated payload")
        elif self.operation in SCANNER_OPERATIONS:
            if (
                self.inventory is not None
                or self.binary_inventory is not None
                or self.binary_inventory_path is not None
                or self.binary_inventory_summary is not None
                or self.bytecode_index is not None
                or self.bytecode_index_path is not None
                or self.bytecode_index_summary is not None
                or self.build is not None
            ):
                raise ValueError("scanner result contains an unrelated payload")
        elif any(
            (
                self.inventory,
                self.binary_inventory,
                self.binary_inventory_path,
                self.binary_inventory_summary,
                self.bytecode_index,
                self.bytecode_index_path,
                self.bytecode_index_summary,
                self.build,
                self.candidates,
                self.candidates_path,
            )
        ):
            raise ValueError("default probe cannot contain analysis payload")
        if self.status is ToolStatus.COMPLETED and self.reason_code is not None:
            raise ValueError("completed result cannot contain reason_code")
        if self.status is not ToolStatus.COMPLETED and not self.reason_code:
            raise ValueError("non-completed result requires reason_code")
        if self.raw_result_paths != sorted(set(self.raw_result_paths)):
            raise ValueError("raw_result_paths must be sorted and unique")
        referenced_paths = {
            path
            for path in (
                self.binary_inventory_path,
                self.bytecode_index_path,
                self.candidates_path,
            )
            if path is not None
        }
        if not referenced_paths.issubset(self.raw_result_paths):
            raise ValueError("result references must be declared as raw results")
        return self
