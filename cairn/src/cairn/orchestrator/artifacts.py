from __future__ import annotations

from pathlib import PurePosixPath
import tarfile

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import (
    AnalysisManifest,
    AnalysisOperation,
    BinaryInventoryResult,
    BinaryInventorySummary,
    CandidateResult,
    ProgramIndexSummary,
    ProgramIndexV2,
)
from cairn.sandbox.contracts import SandboxArtifact
from cairn.semantic.contracts import SemanticReviewResult
from cairn.dynamic.contracts import DynamicResult
from cairn.poc.contracts import PocResult
from cairn.verify.contracts import VerifyResult
from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import ArtifactAccessLevel, ArtifactKind
from cairn.server.persistence.models import Artifact, AuditTask
from cairn.orchestrator.errors import OrchestratorError


_MAX_OUTPUT_ENTRIES = 100_000
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
_MAX_BINARY_INVENTORY_BYTES = 256 * 1024 * 1024
_MAX_PROGRAM_INDEX_BYTES = 256 * 1024 * 1024
_MAX_CANDIDATE_RESULT_BYTES = 128 * 1024 * 1024
_MAX_OUTPUT_BYTES = 4 * 1024 * 1024 * 1024


class SandboxArtifactRegistrar:
    def __init__(self, session: Session, artifact_store: ArtifactStore) -> None:
        self.session = session
        self.artifact_store = artifact_store

    def register(
        self,
        task: AuditTask,
        descriptor: SandboxArtifact,
        *,
        kind: ArtifactKind,
    ) -> Artifact:
        if descriptor.media_type != "application/x-tar":
            raise OrchestratorError(
                "SANDBOX_ARTIFACT_INVALID",
                "Sandbox output Artifact has an invalid media type",
            )
        try:
            self.artifact_store.resolve(
                descriptor.storage_key,
                expected_sha256=descriptor.sha256,
                expected_size=descriptor.size_bytes,
            )
        except Exception as exc:
            raise OrchestratorError(
                "SANDBOX_ARTIFACT_INVALID",
                "Sandbox output Artifact failed integrity verification",
                retryable=True,
            ) from exc
        existing = self.session.scalar(
            select(Artifact).where(
                Artifact.produced_by_task_id == task.id,
                Artifact.sha256 == descriptor.sha256,
                Artifact.kind == kind.value,
            )
        )
        if existing is not None:
            return existing
        artifact = Artifact(
            audit_run_id=task.audit_run_id,
            kind=kind.value,
            storage_key=descriptor.storage_key,
            sha256=descriptor.sha256,
            size_bytes=descriptor.size_bytes,
            media_type=descriptor.media_type,
            access_level=ArtifactAccessLevel.SENSITIVE.value,
            produced_by_task_id=task.id,
        )
        self.session.add(artifact)
        self.session.flush()
        output_ids = list(task.output_artifact_ids)
        rendered_id = str(artifact.id)
        if rendered_id not in output_ids:
            output_ids.append(rendered_id)
            task.output_artifact_ids = output_ids
        return artifact

    def load_manifest(
        self,
        artifact: Artifact,
        *,
        expected_operation: AnalysisOperation,
    ) -> AnalysisManifest:
        manifest_bytes, seen = self._read_output_member(
            artifact,
            "manifest.json",
            missing_code="ANALYSIS_MANIFEST_MISSING",
            invalid_code="ANALYSIS_MANIFEST_INVALID",
        )
        try:
            manifest = AnalysisManifest.model_validate_json(manifest_bytes)
        except ValidationError as exc:
            raise OrchestratorError(
                "ANALYSIS_MANIFEST_INVALID",
                "Analysis manifest failed contract validation",
            ) from exc
        if manifest.operation is not expected_operation:
            raise OrchestratorError(
                "ANALYSIS_OPERATION_MISMATCH",
                "Analysis manifest does not match its AuditTask",
            )
        if not set(manifest.raw_result_paths).issubset(seen):
            raise OrchestratorError(
                "ANALYSIS_MANIFEST_INVALID",
                "Analysis manifest references a missing raw result",
            )
        return self._hydrate_analysis_results(artifact, manifest, seen)

    def _hydrate_analysis_results(
        self,
        artifact: Artifact,
        manifest: AnalysisManifest,
        seen: set[str],
    ) -> AnalysisManifest:
        updates: dict[str, object] = {}
        if manifest.binary_inventory_path is not None:
            payload, _ = self._read_output_member(
                artifact,
                manifest.binary_inventory_path,
                missing_code="BINARY_INVENTORY_RESULT_MISSING",
                invalid_code="BINARY_INVENTORY_RESULT_INVALID",
                max_member_bytes=_MAX_BINARY_INVENTORY_BYTES,
            )
            try:
                result = BinaryInventoryResult.model_validate_json(payload)
            except ValidationError as exc:
                raise OrchestratorError(
                    "BINARY_INVENTORY_RESULT_INVALID",
                    "Binary inventory failed contract validation",
                ) from exc
            summary = BinaryInventorySummary(
                contract="cairn-binary-inventory-summary-v1",
                archive_count=result.archive_count,
                class_entry_count=result.class_entry_count,
                selected_class_count=result.selected_class_count,
                expanded_entry_count=result.expanded_entry_count,
                expanded_bytes=result.expanded_bytes,
                coverage_gap_count=len(result.coverage_gaps),
            )
            if summary != manifest.binary_inventory_summary:
                raise OrchestratorError(
                    "BINARY_INVENTORY_RESULT_INVALID",
                    "Binary inventory does not match its manifest summary",
                )
            updates["binary_inventory"] = result

        if manifest.bytecode_index_path is not None:
            payload, _ = self._read_output_member(
                artifact,
                manifest.bytecode_index_path,
                missing_code="PROGRAM_INDEX_RESULT_MISSING",
                invalid_code="PROGRAM_INDEX_RESULT_INVALID",
                max_member_bytes=_MAX_PROGRAM_INDEX_BYTES,
            )
            try:
                result = ProgramIndexV2.model_validate_json(payload)
            except ValidationError as exc:
                raise OrchestratorError(
                    "PROGRAM_INDEX_RESULT_INVALID",
                    "Program index failed contract validation",
                ) from exc
            summary = ProgramIndexSummary(
                contract="cairn-program-index-summary-v1",
                classes_total=result.classes_total,
                classes_parsed=result.classes_parsed,
                component_count=len(result.components),
                resource_count=len(result.resources),
                method_count=len(result.methods),
                call_count=len(result.calls),
                field_access_count=len(result.field_accesses),
                decompiled_view_count=len(result.decompiled_views),
                coverage_gap_count=len(result.coverage_gaps),
            )
            if summary != manifest.bytecode_index_summary:
                raise OrchestratorError(
                    "PROGRAM_INDEX_RESULT_INVALID",
                    "Program index does not match its manifest summary",
                )
            view_paths = {view.artifact_path for view in result.decompiled_views}
            if not view_paths.issubset(seen):
                raise OrchestratorError(
                    "PROGRAM_INDEX_RESULT_INVALID",
                    "Program index references a missing decompiled view",
                )
            updates["bytecode_index"] = result

        if manifest.candidates_path is not None:
            payload, _ = self._read_output_member(
                artifact,
                manifest.candidates_path,
                missing_code="CANDIDATE_RESULT_MISSING",
                invalid_code="CANDIDATE_RESULT_INVALID",
                max_member_bytes=_MAX_CANDIDATE_RESULT_BYTES,
            )
            try:
                result = CandidateResult.model_validate_json(payload)
            except ValidationError as exc:
                raise OrchestratorError(
                    "CANDIDATE_RESULT_INVALID",
                    "Candidate result failed contract validation",
                ) from exc
            if len(result.candidates) != manifest.candidate_count:
                raise OrchestratorError(
                    "CANDIDATE_RESULT_INVALID",
                    "Candidate result does not match its manifest count",
                )
            updates["candidates"] = result.candidates

        return manifest.model_copy(update=updates)

    def load_semantic_result(
        self,
        artifact: Artifact,
        *,
        expected_scope_key: str,
    ) -> SemanticReviewResult:
        """Read a `cairn-semantic-result-v1` out of a collected output TAR.

        Shares the hardened member walk with `load_manifest`: the reviewer's
        output is no more trusted than a scanner's, so the same entry-count,
        path-safety and size limits apply.
        """

        payload, _seen = self._read_output_member(
            artifact,
            "semantic-result.json",
            missing_code="SEMANTIC_RESULT_MISSING",
            invalid_code="SEMANTIC_RESULT_INVALID",
        )
        try:
            result = SemanticReviewResult.model_validate_json(payload)
        except ValidationError as exc:
            raise OrchestratorError(
                "SEMANTIC_RESULT_INVALID",
                "Semantic result failed contract validation",
            ) from exc
        if result.scope_key != expected_scope_key:
            raise OrchestratorError(
                "SEMANTIC_SCOPE_MISMATCH",
                "Semantic result does not match its AuditTask",
            )
        return result

    def load_verify_result(
        self,
        artifact: Artifact,
        *,
        expected_root_cause_key: str,
    ) -> VerifyResult:
        """Read a `cairn-verify-result-v1` out of a collected output TAR.

        Same hardened member walk as the other loaders: the blind reviewer's
        output is model-derived and no more trusted than a scanner's.
        """

        payload, _seen = self._read_output_member(
            artifact,
            "verify-result.json",
            missing_code="VERIFY_RESULT_MISSING",
            invalid_code="VERIFY_RESULT_INVALID",
        )
        try:
            result = VerifyResult.model_validate_json(payload)
        except ValidationError as exc:
            raise OrchestratorError(
                "VERIFY_RESULT_INVALID",
                "Verification result failed contract validation",
            ) from exc
        if result.root_cause_key != expected_root_cause_key:
            raise OrchestratorError(
                "VERIFY_CANDIDATE_MISMATCH",
                "Verification result does not match its AuditTask",
            )
        return result

    def load_dynamic_result(self, artifact: Artifact) -> DynamicResult:
        """Read a `cairn-dynamic-result-v1` out of a collected output TAR.

        Same hardened member walk as the other loaders. This one carries
        response excerpts from an application built out of repository code, so
        it is the least trusted output the Orchestrator reads.
        """

        payload, _seen = self._read_output_member(
            artifact,
            "dynamic-result.json",
            missing_code="DYNAMIC_RESULT_MISSING",
            invalid_code="DYNAMIC_RESULT_INVALID",
        )
        try:
            return DynamicResult.model_validate_json(payload)
        except ValidationError as exc:
            raise OrchestratorError(
                "DYNAMIC_RESULT_INVALID",
                "Dynamic verification result failed contract validation",
            ) from exc

    def load_poc_result(
        self,
        artifact: Artifact,
        *,
        expected_finding_id: str,
    ) -> PocResult:
        """Read a `cairn-poc-plan-v1` out of a collected output TAR.

        Same hardened member walk as the other loaders. The plan is
        re-validated by `PocResult` here and again by the executor's contract
        before it runs, so the platform-side gate applies on both sides.
        """

        payload, _seen = self._read_output_member(
            artifact,
            "poc-result.json",
            missing_code="POC_RESULT_MISSING",
            invalid_code="POC_RESULT_INVALID",
        )
        try:
            result = PocResult.model_validate_json(payload)
        except ValidationError as exc:
            raise OrchestratorError(
                "POC_RESULT_INVALID",
                "PoC result failed contract validation",
            ) from exc
        if result.finding_id != expected_finding_id:
            raise OrchestratorError(
                "POC_FINDING_MISMATCH",
                "PoC result does not match its AuditTask",
            )
        return result

    def _read_output_member(
        self,
        artifact: Artifact,
        member_name: str,
        *,
        missing_code: str,
        invalid_code: str,
        max_member_bytes: int = _MAX_MANIFEST_BYTES,
    ) -> tuple[bytes, set[str]]:
        try:
            archive_path = self.artifact_store.resolve(
                artifact.storage_key,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size_bytes,
            )
            with tarfile.open(archive_path, mode="r:") as archive:
                found: bytes | None = None
                seen: set[str] = set()
                entries = 0
                total_bytes = 0
                for member in archive:
                    entries += 1
                    if entries > _MAX_OUTPUT_ENTRIES:
                        raise OrchestratorError(
                            "ANALYSIS_OUTPUT_INVALID",
                            "Analysis output contains too many entries",
                        )
                    path = PurePosixPath(member.name)
                    if (
                        path.is_absolute()
                        or any(part in {"", ".", ".."} for part in path.parts)
                        or "\\" in member.name
                        or member.name in seen
                        or not member.isreg()
                    ):
                        raise OrchestratorError(
                            "ANALYSIS_OUTPUT_INVALID",
                            "Analysis output contains an unsafe member",
                        )
                    seen.add(member.name)
                    total_bytes += member.size
                    if total_bytes > _MAX_OUTPUT_BYTES:
                        raise OrchestratorError(
                            "ANALYSIS_OUTPUT_INVALID",
                            "Analysis output exceeds the read limit",
                        )
                    if member.name == member_name:
                        if member.size > max_member_bytes:
                            raise OrchestratorError(
                                invalid_code,
                                "Sandbox result exceeds the read limit",
                            )
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise OrchestratorError(
                                invalid_code,
                                "Sandbox result cannot be read",
                            )
                        found = stream.read(max_member_bytes + 1)
                if found is None:
                    raise OrchestratorError(
                        missing_code,
                        "Sandbox output does not contain the expected result",
                    )
        except OrchestratorError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise OrchestratorError(
                "ANALYSIS_OUTPUT_INVALID",
                "Analysis output is not a valid TAR Artifact",
            ) from exc
        return found, seen
