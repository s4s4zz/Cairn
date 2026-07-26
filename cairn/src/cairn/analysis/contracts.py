from __future__ import annotations

from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Literal

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
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
CweId = Annotated[str, StringConstraints(pattern=r"^CWE-[1-9][0-9]{0,5}$")]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class AnalysisOperation(StrEnum):
    DEFAULT = "default"
    INVENTORY = "inventory"
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


class CandidateFinding(StrictModel):
    rule_id: str = Field(min_length=1, max_length=512)
    cwe_ids: list[CweId] = Field(default_factory=list)
    category: str = Field(min_length=1, max_length=255)
    severity: CandidateSeverity
    confidence: CandidateConfidence
    message: str = Field(min_length=1, max_length=16_384)
    locations: list[CandidateLocation] = Field(min_length=1, max_length=128)
    sink: str | None = Field(default=None, max_length=1024)
    fingerprint: Sha256
    root_cause_key: Sha256
    discovered_by: list[str] = Field(min_length=1, max_length=16)
    source_rules: list[str] = Field(min_length=1, max_length=64)

    @field_validator("cwe_ids", "discovered_by", "source_rules")
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


class DataFlowRecord(StrictModel):
    path: RelativePath
    line: int = Field(ge=1)
    kind: str = Field(min_length=1, max_length=128)
    symbol: str | None = Field(default=None, max_length=1024)
    cwe_ids: list[CweId] = Field(default_factory=list)


class PathClassification(StrictModel):
    path: RelativePath
    kind: str = Field(min_length=1, max_length=64)


class InventoryResult(StrictModel):
    build_system: Literal["maven", "gradle", "mixed", "unknown"]
    java_versions: list[str] = Field(default_factory=list)
    modules: list[ModuleRecord]
    module_dependencies: list[ModuleDependency]
    build_plan: list[BuildStep]
    symbols: list[SymbolRecord]
    entrypoints: list[EntrypointRecord]
    permissions: list[PermissionRecord]
    sources: list[DataFlowRecord]
    sinks: list[DataFlowRecord]
    classified_paths: list[PathClassification]
    java_files_total: int = Field(ge=0)
    skipped_paths: list[str] = Field(default_factory=list)
    unsupported_components: list[dict[str, object]] = Field(default_factory=list)


class BuildStepResult(StrictModel):
    module_path: str = Field(min_length=1, max_length=1024)
    build_system: Literal["maven", "gradle"]
    runner: Literal["maven-wrapper", "maven", "gradle-wrapper", "gradle"]
    status: ToolStatus
    exit_code: int | None = None
    log_path: RelativePath | None = None
    reason_code: str | None = Field(default=None, max_length=128)


class BuildResult(StrictModel):
    status: Literal["success", "partial", "failed"]
    steps: list[BuildStepResult]


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
    build: BuildResult | None = None
    candidates: list[CandidateFinding] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_operation_payload(self) -> "AnalysisManifest":
        if self.operation is AnalysisOperation.INVENTORY:
            if self.status is ToolStatus.COMPLETED and self.inventory is None:
                raise ValueError("completed inventory result requires inventory")
            if self.build is not None or self.candidates:
                raise ValueError("inventory result contains an unrelated payload")
        elif self.operation is AnalysisOperation.BUILD:
            if self.status is ToolStatus.COMPLETED and self.build is None:
                raise ValueError("completed build result requires build")
            if self.inventory is not None or self.candidates:
                raise ValueError("build result contains an unrelated payload")
        elif self.operation in SCANNER_OPERATIONS:
            if self.inventory is not None or self.build is not None:
                raise ValueError("scanner result contains an unrelated payload")
        elif any((self.inventory, self.build, self.candidates)):
            raise ValueError("default probe cannot contain analysis payload")
        if self.status is ToolStatus.COMPLETED and self.reason_code is not None:
            raise ValueError("completed result cannot contain reason_code")
        if self.status is not ToolStatus.COMPLETED and not self.reason_code:
            raise ValueError("non-completed result requires reason_code")
        if self.raw_result_paths != sorted(set(self.raw_result_paths)):
            raise ValueError("raw_result_paths must be sorted and unique")
        return self
