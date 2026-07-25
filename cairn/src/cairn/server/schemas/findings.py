from datetime import datetime
from typing import Self
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from cairn.server.domain.enums import (
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    LocationRole,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.schemas.common import Page, StrictModel


class CandidateLocation(StrictModel):
    role: LocationRole
    file_path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(gt=0)
    end_line: int = Field(gt=0)
    symbol: str | None = Field(default=None, max_length=2048)
    code_snippet: str = Field(min_length=1)
    snapshot_sha: str = Field(pattern=r"^[0-9a-f]{40,128}$")
    ordinal: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_line_range(self) -> Self:
        if self.end_line < self.start_line:
            raise ValueError("end_line must be greater than or equal to start_line")
        return self


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


class FindingLocationResponse(StrictModel):
    id: UUID
    role: LocationRole
    file_path: str
    start_line: int
    end_line: int
    symbol: str | None
    code_snippet: str
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
    reasoning: str
    created_at: datetime


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


class FindingFilters(StrictModel):
    audit_run_id: UUID | None = None
    cwe_id: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")
    severity: FindingSeverity | None = None
    status: FindingStatus | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


FindingPage = Page[FindingResponse]
