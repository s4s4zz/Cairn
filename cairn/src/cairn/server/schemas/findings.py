import unicodedata
from datetime import datetime
from pathlib import PurePosixPath
from typing import Literal, Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from cairn.server.domain.enums import (
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    LocationOriginKind,
    LocationRole,
    ReviewVerdict,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.schemas.common import Page, StrictModel


class CandidateLocation(StrictModel):
    role: LocationRole
    origin_kind: LocationOriginKind = LocationOriginKind.SOURCE
    file_path: str | None = Field(default=None, min_length=1, max_length=4096)
    source_path: str | None = Field(default=None, min_length=1, max_length=4096)
    start_line: int | None = Field(default=None, gt=0)
    end_line: int | None = Field(default=None, gt=0)
    symbol: str | None = Field(default=None, max_length=2048)
    code_snippet: str | None = Field(default=None, min_length=1)
    container_path: str | None = Field(default=None, min_length=1, max_length=4096)
    entry_path: str | None = Field(default=None, min_length=1, max_length=4096)
    class_name: str | None = Field(default=None, min_length=1, max_length=2048)
    method_name: str | None = Field(default=None, min_length=1, max_length=1024)
    method_descriptor: str | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
    )
    bytecode_offset: int | None = Field(default=None, ge=0)
    decompiled_artifact_id: UUID | None = None
    decompiled_start_line: int | None = Field(default=None, gt=0)
    decompiled_end_line: int | None = Field(default=None, gt=0)
    snapshot_sha: str = Field(pattern=r"^[0-9a-f]{64}$")
    ordinal: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        if (self.start_line is None) != (self.end_line is None):
            raise ValueError("source line range must be wholly present or absent")
        if (
            self.start_line is not None
            and self.end_line is not None
            and self.end_line < self.start_line
        ):
            raise ValueError("end_line must be greater than or equal to start_line")
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
                "decompiled_end_line must be greater than or equal to "
                "decompiled_start_line"
            )

        file_path = _normalized_code_path(self.file_path, allow_archive=False)
        source_path = _normalized_code_path(self.source_path, allow_archive=False)
        if (
            file_path is not None
            and source_path is not None
            and file_path != source_path
        ):
            raise ValueError("file_path and source_path must name the same source")
        resolved_source = source_path or file_path
        self.file_path = resolved_source
        self.source_path = resolved_source
        self.container_path = _normalized_code_path(
            self.container_path,
            allow_archive=False,
        )
        self.entry_path = _normalized_code_path(self.entry_path, allow_archive=True)

        if (self.method_name is None) != (self.method_descriptor is None):
            raise ValueError("method name and descriptor must be provided together")
        if self.bytecode_offset is not None and self.method_name is None:
            raise ValueError("bytecode offset requires a method identity")
        if self.origin_kind in {
            LocationOriginKind.BYTECODE,
            LocationOriginKind.DECOMPILED,
        } and (self.entry_path is None or self.class_name is None):
            raise ValueError("bytecode locations require entry_path and class_name")
        if self.origin_kind is LocationOriginKind.SOURCE and (
            self.file_path is None
            or self.start_line is None
            or self.code_snippet is None
        ):
            raise ValueError("source locations require a path, lines, and snippet")
        if self.origin_kind is LocationOriginKind.CONFIG and not (
            self.file_path or self.entry_path
        ):
            raise ValueError("config locations require a source or archive path")
        if (
            self.origin_kind is LocationOriginKind.DECOMPILED
            and self.decompiled_artifact_id is None
        ):
            raise ValueError("decompiled locations require their Artifact")
        if (
            self.decompiled_start_line is not None
            and self.decompiled_artifact_id is None
        ):
            raise ValueError("decompiled line range requires its Artifact")
        return self


def _normalized_code_path(value: str | None, *, allow_archive: bool) -> str | None:
    if value is None:
        return None
    rendered = value.replace("\\", "/")
    if unicodedata.normalize("NFC", rendered) != rendered:
        raise ValueError("location paths must be NFC-normalized")
    if any(unicodedata.category(character) == "Cc" for character in rendered):
        raise ValueError("location paths must not contain control characters")
    segments = rendered.split("!/") if allow_archive else [rendered]
    if any(not segment for segment in segments):
        raise ValueError("location path contains an empty archive segment")
    for segment in segments:
        path = PurePosixPath(segment)
        if (
            segment.startswith("/")
            or any(part in {"", ".", ".."} for part in path.parts)
            or (path.parts and ":" in path.parts[0])
            or path.as_posix() != segment
        ):
            raise ValueError("location paths must be normalized and relative")
    if len(rendered.encode("utf-8")) > 4096:
        raise ValueError("location path exceeds the encoded length limit")
    return rendered


class CandidateFindingCommand(StrictModel):
    audit_run_id: UUID
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1)
    category: str = Field(min_length=1, max_length=255)
    cwe_id: str = Field(pattern=r"^CWE-[0-9]+$")
    owasp_category: str | None = Field(default=None, max_length=128)
    severity: FindingSeverity
    confidence: FindingConfidence
    attack_preconditions: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    remediation: str = Field(min_length=1)
    discovered_by: str = Field(min_length=1, max_length=255)
    locations: list[CandidateLocation] = Field(min_length=1)

    @field_validator("confidence")
    @classmethod
    def reject_confirmed_candidate(
        cls,
        value: FindingConfidence,
    ) -> FindingConfidence:
        if value is FindingConfidence.CONFIRMED:
            raise ValueError("candidate confidence cannot be confirmed")
        return value

    @model_validator(mode="after")
    def validate_location_ordinals(self) -> Self:
        ordinals = [location.ordinal for location in self.locations]
        if len(ordinals) != len(set(ordinals)):
            raise ValueError("location ordinals must be unique")
        return self


class FindingLocationResponse(StrictModel):
    id: UUID
    role: LocationRole
    origin_kind: LocationOriginKind
    file_path: str | None
    source_path: str | None
    start_line: int | None
    end_line: int | None
    symbol: str | None
    code_snippet: str | None
    container_path: str | None
    entry_path: str | None
    class_name: str | None
    method_name: str | None
    method_descriptor: str | None
    bytecode_offset: int | None
    decompiled_artifact_id: UUID | None
    decompiled_start_line: int | None
    decompiled_end_line: int | None
    snapshot_sha: str
    ordinal: int


class EvidenceSummary(StrictModel):
    id: UUID
    type: EvidenceType
    artifact_id: UUID | None
    summary: str
    sha256: str | None
    produced_by_task_id: UUID
    created_at: datetime


class VerificationSummary(StrictModel):
    id: UUID
    method: VerificationMethod
    verdict: VerificationVerdict
    verifier: str
    evidence_ids: list[UUID]
    reasoning: str
    created_at: datetime


class HumanReviewSummary(StrictModel):
    id: UUID
    verdict: ReviewVerdict
    original_severity: FindingSeverity
    final_severity: FindingSeverity
    reviewer_id: str
    comment: str
    reviewed_at: datetime


class FindingResponse(StrictModel):
    id: UUID
    audit_run_id: UUID
    fingerprint: str
    title: str
    description: str
    category: str
    cwe_id: str
    owasp_category: str | None
    severity: FindingSeverity
    confidence: FindingConfidence
    status: FindingStatus
    attack_preconditions: str
    impact: str
    remediation: str
    runtime_verification: RuntimeVerificationStatus
    discovered_by: str
    first_seen_at: datetime
    updated_at: datetime


class FindingDetail(FindingResponse):
    locations: list[FindingLocationResponse]
    evidence: list[EvidenceSummary]
    verifications: list[VerificationSummary]
    human_reviews: list[HumanReviewSummary]


class FindingReviewRequest(StrictModel):
    verdict: Literal["confirmed", "rejected", "accepted_risk"]
    final_severity: FindingSeverity | None = None
    comment: str = Field(default="", max_length=4000)

    @model_validator(mode="after")
    def require_decision_reason(self) -> Self:
        if self.verdict in {"rejected", "accepted_risk"} and not self.comment:
            raise ValueError("rejected and accepted-risk reviews require a comment")
        return self


class FindingReverifyRequest(StrictModel):
    method: Literal["independent_agent", "dynamic_poc"] = "independent_agent"
    comment: str = Field(min_length=1, max_length=4000)


class FindingReverifyResponse(StrictModel):
    finding: FindingResponse
    review: HumanReviewSummary
    task_id: UUID


class FindingFilters(StrictModel):
    audit_run_id: UUID | None = None
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


FindingPage = Page[FindingResponse]
