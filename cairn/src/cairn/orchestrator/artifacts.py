from __future__ import annotations

from pathlib import PurePosixPath
import tarfile

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import AnalysisManifest, AnalysisOperation
from cairn.sandbox.contracts import SandboxArtifact
from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import ArtifactAccessLevel, ArtifactKind
from cairn.server.persistence.models import Artifact, AuditTask
from cairn.orchestrator.errors import OrchestratorError


_MAX_OUTPUT_ENTRIES = 100_000
_MAX_MANIFEST_BYTES = 32 * 1024 * 1024
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
        try:
            archive_path = self.artifact_store.resolve(
                artifact.storage_key,
                expected_sha256=artifact.sha256,
                expected_size=artifact.size_bytes,
            )
            with tarfile.open(archive_path, mode="r:") as archive:
                manifest_bytes: bytes | None = None
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
                    if member.name == "manifest.json":
                        if member.size > _MAX_MANIFEST_BYTES:
                            raise OrchestratorError(
                                "ANALYSIS_MANIFEST_INVALID",
                                "Analysis manifest exceeds the read limit",
                            )
                        stream = archive.extractfile(member)
                        if stream is None:
                            raise OrchestratorError(
                                "ANALYSIS_MANIFEST_INVALID",
                                "Analysis manifest cannot be read",
                            )
                        manifest_bytes = stream.read(_MAX_MANIFEST_BYTES + 1)
                if manifest_bytes is None:
                    raise OrchestratorError(
                        "ANALYSIS_MANIFEST_MISSING",
                        "Analysis output does not contain a manifest",
                    )
        except OrchestratorError:
            raise
        except (OSError, tarfile.TarError) as exc:
            raise OrchestratorError(
                "ANALYSIS_OUTPUT_INVALID",
                "Analysis output is not a valid TAR Artifact",
            ) from exc
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
        return manifest
