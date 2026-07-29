from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StringConstraints,
    field_validator,
    model_validator,
)


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
Identifier = Annotated[
    str,
    StringConstraints(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}$"),
]
RecordReference = Annotated[
    str,
    StringConstraints(
        max_length=520,
        pattern=(
            r"^record://[a-zA-Z0-9][a-zA-Z0-9._-]*"
            r"(?:/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$"
        ),
    ),
]
ArtifactReference = Annotated[
    str,
    StringConstraints(
        max_length=520,
        pattern=(
            r"^(?:fixture|secret)://[a-zA-Z0-9][a-zA-Z0-9._-]*"
            r"(?:/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$"
        ),
    ),
]
KeyReference = Annotated[
    str,
    StringConstraints(
        max_length=520,
        pattern=(
            r"^key://[a-zA-Z0-9][a-zA-Z0-9._-]*"
            r"(?:/[a-zA-Z0-9][a-zA-Z0-9._-]*)*$"
        ),
    ),
]


class StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class DatasetVisibility(StrEnum):
    SYNTHETIC = "synthetic"
    PRIVATE = "private"


class LabelStatus(StrEnum):
    PROVISIONAL = "provisional"
    HUMAN_ADJUDICATED = "human-adjudicated"


class ArtifactKind(StrEnum):
    JAR = "jar"
    WAR = "war"
    EAR = "ear"
    CLASS_DIRECTORY = "class-directory"
    HYBRID = "hybrid"


class FindingSeverity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceKind(StrEnum):
    ENTRYPOINT = "entrypoint"
    INPUT = "input"
    GUARD = "guard"
    CALL_CHAIN = "call-chain"
    SINK = "sink"
    RUNTIME = "runtime"


class AuthorizationRecord(StrictContract):
    authorization_ref: RecordReference
    scope_sha256: Sha256
    permits_static_analysis: StrictBool
    permits_decompilation: StrictBool
    permits_dynamic_execution: StrictBool


class AnnotationProtocol(StrictContract):
    reviewer_refs: list[RecordReference] = Field(min_length=2, max_length=2)
    adjudicator_ref: RecordReference
    instructions_sha256: Sha256

    @field_validator("reviewer_refs")
    @classmethod
    def require_two_independent_reviewers(cls, values: list[str]) -> list[str]:
        if len(set(values)) != 2:
            raise ValueError("reviewer_refs must identify two independent reviewers")
        return sorted(values)

    @model_validator(mode="after")
    def require_independent_adjudicator(self) -> Self:
        if self.adjudicator_ref in self.reviewer_refs:
            raise ValueError("adjudicator_ref must differ from reviewer_refs")
        return self


class ProvenanceRecord(StrictContract):
    custody_record_ref: RecordReference
    custody_record_sha256: Sha256
    acquisition_record_ref: RecordReference
    acquisition_record_sha256: Sha256


class SampleArtifact(StrictContract):
    sha256: Sha256
    kind: ArtifactKind
    artifact_ref: ArtifactReference
    decryption_key_ref: KeyReference | None = None
    provenance: ProvenanceRecord


class LabelEvidence(StrictContract):
    sha256: Sha256
    evidence_ref: ArtifactReference
    decryption_key_ref: KeyReference | None = None


class GoldEntrypoint(StrictContract):
    fingerprint: Sha256
    evidence: list[LabelEvidence] = Field(min_length=1, max_length=32)

    @field_validator("evidence")
    @classmethod
    def sort_unique_evidence(cls, values: list[LabelEvidence]) -> list[LabelEvidence]:
        if len({item.sha256 for item in values}) != len(values):
            raise ValueError("evidence sha256 values must be unique")
        return sorted(values, key=lambda item: item.sha256)


class GoldFinding(StrictContract):
    fingerprint: Sha256
    severity: FindingSeverity
    required_evidence: list[EvidenceKind] = Field(min_length=1, max_length=6)
    dynamic_reproducible: StrictBool
    evidence: list[LabelEvidence] = Field(min_length=1, max_length=32)

    @field_validator("required_evidence")
    @classmethod
    def sort_unique_required_evidence(
        cls,
        values: list[EvidenceKind],
    ) -> list[EvidenceKind]:
        if len(set(values)) != len(values):
            raise ValueError("required_evidence values must be unique")
        return sorted(values, key=str)

    @field_validator("evidence")
    @classmethod
    def sort_unique_evidence(cls, values: list[LabelEvidence]) -> list[LabelEvidence]:
        if len({item.sha256 for item in values}) != len(values):
            raise ValueError("evidence sha256 values must be unique")
        return sorted(values, key=lambda item: item.sha256)


class GoldCoverageUnit(StrictContract):
    fingerprint: Sha256
    evidence: list[LabelEvidence] = Field(min_length=1, max_length=32)

    @field_validator("evidence")
    @classmethod
    def sort_unique_evidence(cls, values: list[LabelEvidence]) -> list[LabelEvidence]:
        if len({item.sha256 for item in values}) != len(values):
            raise ValueError("evidence sha256 values must be unique")
        return sorted(values, key=lambda item: item.sha256)


class GoldSample(StrictContract):
    sample_id: Identifier
    artifact: SampleArtifact
    entrypoints: list[GoldEntrypoint] = Field(max_length=100_000)
    findings: list[GoldFinding] = Field(max_length=100_000)
    coverage_units: list[GoldCoverageUnit] = Field(max_length=100_000)

    @field_validator("entrypoints")
    @classmethod
    def sort_unique_entrypoints(
        cls,
        values: list[GoldEntrypoint],
    ) -> list[GoldEntrypoint]:
        return _sort_unique_fingerprints(values, "entrypoints")

    @field_validator("findings")
    @classmethod
    def sort_unique_findings(cls, values: list[GoldFinding]) -> list[GoldFinding]:
        return _sort_unique_fingerprints(values, "findings")

    @field_validator("coverage_units")
    @classmethod
    def sort_unique_coverage_units(
        cls,
        values: list[GoldCoverageUnit],
    ) -> list[GoldCoverageUnit]:
        return _sort_unique_fingerprints(values, "coverage_units")


class ClosedPlatformGoldManifest(StrictContract):
    schema_version: Literal["closed-platform-gold-v1"]
    benchmark_id: Identifier
    visibility: DatasetVisibility
    label_status: LabelStatus
    authorization: AuthorizationRecord
    annotation_protocol: AnnotationProtocol
    samples: list[GoldSample] = Field(min_length=1, max_length=10_000)

    @field_validator("samples")
    @classmethod
    def sort_unique_samples(cls, values: list[GoldSample]) -> list[GoldSample]:
        sample_ids = [sample.sample_id for sample in values]
        sample_hashes = [sample.artifact.sha256 for sample in values]
        if len(set(sample_ids)) != len(values):
            raise ValueError("sample_id values must be unique")
        if len(set(sample_hashes)) != len(values):
            raise ValueError("sample artifact hashes must be unique")
        return sorted(values, key=lambda sample: sample.sample_id)

    @model_validator(mode="after")
    def enforce_reference_policy(self) -> Self:
        if not self.authorization.permits_static_analysis:
            raise ValueError("benchmark authorization must permit static analysis")
        if (
            self.visibility is DatasetVisibility.PRIVATE
            and self.label_status is not LabelStatus.HUMAN_ADJUDICATED
        ):
            raise ValueError("private gold labels must be human-adjudicated")
        for sample in self.samples:
            references = [sample.artifact, *_all_label_evidence(sample)]
            for reference in references:
                reference_uri = _reference_uri(reference)
                if self.visibility is DatasetVisibility.PRIVATE:
                    if not reference_uri.startswith("secret://"):
                        raise ValueError("private data must use secret:// references")
                    if reference.decryption_key_ref is None:
                        raise ValueError("private data must include decryption_key_ref")
                else:
                    if not reference_uri.startswith("fixture://"):
                        raise ValueError("synthetic data must use fixture:// references")
                    if reference.decryption_key_ref is not None:
                        raise ValueError("synthetic data must not include key references")
            if (
                not self.authorization.permits_dynamic_execution
                and any(finding.dynamic_reproducible for finding in sample.findings)
            ):
                raise ValueError(
                    "dynamic gold labels require dynamic-execution authorization"
                )
        return self


class ExportedEntrypoint(StrictContract):
    fingerprint: Sha256


class ExportedFinding(StrictContract):
    fingerprint: Sha256
    severity: FindingSeverity
    evidence: list[EvidenceKind] = Field(max_length=6)
    dynamic_reproduced: StrictBool

    @field_validator("evidence")
    @classmethod
    def sort_unique_evidence(cls, values: list[EvidenceKind]) -> list[EvidenceKind]:
        if len(set(values)) != len(values):
            raise ValueError("evidence values must be unique")
        return sorted(values, key=str)


class CoverageStatus(StrEnum):
    COVERED = "covered"
    GAP = "gap"


class ExportedCoverageUnit(StrictContract):
    fingerprint: Sha256
    status: CoverageStatus
    reason_code: Identifier | None = None

    @model_validator(mode="after")
    def require_reason_for_gap_only(self) -> Self:
        if self.status is CoverageStatus.GAP and self.reason_code is None:
            raise ValueError("gap coverage units require reason_code")
        if self.status is CoverageStatus.COVERED and self.reason_code is not None:
            raise ValueError("covered units must not include reason_code")
        return self


class AuditRunExport(StrictContract):
    schema_version: Literal["audit-run-export-v1"]
    audit_run_id: Identifier
    sample_sha256: Sha256
    entrypoints: list[ExportedEntrypoint] = Field(max_length=100_000)
    findings: list[ExportedFinding] = Field(max_length=100_000)
    coverage_units: list[ExportedCoverageUnit] = Field(max_length=100_000)

    @field_validator("entrypoints")
    @classmethod
    def sort_unique_entrypoints(
        cls,
        values: list[ExportedEntrypoint],
    ) -> list[ExportedEntrypoint]:
        return _sort_unique_fingerprints(values, "entrypoints")

    @field_validator("findings")
    @classmethod
    def sort_unique_findings(
        cls,
        values: list[ExportedFinding],
    ) -> list[ExportedFinding]:
        return _sort_unique_fingerprints(values, "findings")

    @field_validator("coverage_units")
    @classmethod
    def sort_unique_coverage_units(
        cls,
        values: list[ExportedCoverageUnit],
    ) -> list[ExportedCoverageUnit]:
        return _sort_unique_fingerprints(values, "coverage_units")


class MetricValue(StrictContract):
    numerator: StrictInt = Field(ge=0)
    denominator: StrictInt = Field(ge=0)
    value: float | None = Field(ge=0.0, le=1.0)

    @field_validator("value", mode="before")
    @classmethod
    def reject_non_numeric_ratio(cls, value: object) -> object:
        if value is not None and (
            isinstance(value, bool) or not isinstance(value, (int, float))
        ):
            raise ValueError("value must be a JSON number or null")
        return value

    @model_validator(mode="after")
    def validate_ratio(self) -> Self:
        if self.numerator > self.denominator:
            raise ValueError("numerator must not exceed denominator")
        if self.denominator == 0 and self.value is not None:
            raise ValueError("zero-denominator metrics must have a null value")
        if self.denominator > 0:
            expected = round(self.numerator / self.denominator, 6)
            if self.value != expected:
                raise ValueError("value must be the six-decimal numerator ratio")
        return self


class BenchmarkMetrics(StrictContract):
    entrypoint_recall: MetricValue
    critical_high_recall: MetricValue
    precision: MetricValue
    evidence_completeness: MetricValue
    dynamic_reproduction: MetricValue
    coverage_gap: MetricValue


class BenchmarkResult(StrictContract):
    schema_version: Literal["benchmark-result-v1"]
    benchmark_id: Identifier
    dataset_visibility: DatasetVisibility
    label_status: LabelStatus
    gold_manifest_sha256: Sha256
    audit_run_export_sha256: Sha256
    audit_run_id: Identifier
    sample_sha256: Sha256
    metrics: BenchmarkMetrics


FingerprintItem = (
    GoldEntrypoint
    | GoldFinding
    | GoldCoverageUnit
    | ExportedEntrypoint
    | ExportedFinding
    | ExportedCoverageUnit
)


def _sort_unique_fingerprints(
    values: list[FingerprintItem],
    field_name: str,
) -> list[FingerprintItem]:
    fingerprints = [item.fingerprint for item in values]
    if len(set(fingerprints)) != len(values):
        raise ValueError(f"{field_name} fingerprints must be unique")
    return sorted(values, key=lambda item: item.fingerprint)


def _all_label_evidence(sample: GoldSample) -> list[LabelEvidence]:
    evidence: list[LabelEvidence] = []
    for item in [*sample.entrypoints, *sample.findings, *sample.coverage_units]:
        evidence.extend(item.evidence)
    return evidence


def _reference_uri(reference: SampleArtifact | LabelEvidence) -> str:
    if isinstance(reference, SampleArtifact):
        return reference.artifact_ref
    return reference.evidence_ref
