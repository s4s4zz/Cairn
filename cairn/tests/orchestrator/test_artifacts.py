from io import BytesIO
import json
from pathlib import Path
import tarfile

import pytest
from sqlalchemy.orm import Session

from cairn.analysis.contracts import AnalysisOperation
from cairn.orchestrator.artifacts import SandboxArtifactRegistrar
from cairn.orchestrator.errors import OrchestratorError
from cairn.sandbox.contracts import SandboxArtifact
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    ArtifactKind,
    AuditRunStatus,
    AuditTaskStatus,
    AuditTaskType,
    DynamicVerificationMode,
    SourceType,
)
from cairn.server.persistence.models import (
    AuditPolicy,
    AuditRun,
    AuditTask,
    Repository,
)


def create_task(session: Session) -> AuditTask:
    repository = Repository(
        name="registrar",
        source_type=SourceType.ZIP.value,
        created_by="system",
    )
    policy = AuditPolicy(
        name="registrar",
        version=1,
        include_paths=["**"],
        exclude_paths=[],
        enabled_scanners=["semgrep"],
        dynamic_verification=DynamicVerificationMode.REQUIRED.value,
        severity_thresholds={},
        resource_budget={},
        active=True,
    )
    session.add_all([repository, policy])
    session.flush()
    audit_run = AuditRun(
        repository_id=repository.id,
        source_request={"type": "snapshot", "snapshot_id": "pending"},
        policy_id=policy.id,
        policy_version=1,
        status=AuditRunStatus.PREPROCESSING.value,
        progress=0,
        warning_count=0,
        created_by="system",
    )
    session.add(audit_run)
    session.flush()
    task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.INVENTORY.value,
        scope_key="deterministic:inventory",
        scope={"operation": "inventory", "template": "analysis"},
        required_capabilities=["deterministic:inventory"],
        status=AuditTaskStatus.RUNNING.value,
        attempt=1,
        max_attempts=3,
        timeout_seconds=900,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()
    return task


def manifest_payload(*, raw_paths: list[str] | None = None) -> dict[str, object]:
    return {
        "contract": "cairn-deterministic-result-v1",
        "operation": "inventory",
        "status": "completed",
        "tool_name": "cairn-java-inventory",
        "tool_version": "1.0.0",
        "reason_code": None,
        "warnings": [],
        "raw_result_paths": raw_paths or [],
        "inventory": {
            "build_system": "unknown",
            "java_versions": [],
            "modules": [
                {
                    "path": ".",
                    "name": "fixture",
                    "build_system": "unknown",
                    "descriptor": None,
                    "parent_path": None,
                    "java_versions": [],
                    "frameworks": [],
                }
            ],
            "module_dependencies": [],
            "build_plan": [],
            "symbols": [],
            "entrypoints": [],
            "permissions": [],
            "sources": [],
            "sinks": [],
            "classified_paths": [],
            "java_files_total": 1,
            "skipped_paths": [],
            "unsupported_components": [],
        },
        "build": None,
        "candidates": [],
    }


def store_tar(
    store: LocalArtifactStore,
    tmp_path: Path,
    manifest: dict[str, object],
    *,
    symlink: bool = False,
) -> SandboxArtifact:
    archive_path = tmp_path / "output.tar"
    encoded = json.dumps(manifest).encode()
    with tarfile.open(archive_path, mode="w") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(encoded)
        archive.addfile(info, BytesIO(encoded))
        if symlink:
            link = tarfile.TarInfo("escape")
            link.type = tarfile.SYMTYPE
            link.linkname = "/etc/passwd"
            archive.addfile(link)
    stored = store.put_file(archive_path)
    return SandboxArtifact(
        storage_key=stored.storage_key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type="application/x-tar",
    )


def test_register_is_idempotent_and_manifest_is_strict(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    task = create_task(db_session)
    descriptor = store_tar(store, tmp_path, manifest_payload())
    registrar = SandboxArtifactRegistrar(db_session, store)

    first = registrar.register(task, descriptor, kind=ArtifactKind.SCAN_RESULT)
    second = registrar.register(task, descriptor, kind=ArtifactKind.SCAN_RESULT)
    manifest = registrar.load_manifest(
        first,
        expected_operation=AnalysisOperation.INVENTORY,
    )

    assert second.id == first.id
    assert task.output_artifact_ids == [str(first.id)]
    assert first.audit_run_id == task.audit_run_id
    assert first.produced_by_task_id == task.id
    assert manifest.inventory is not None


def test_manifest_cannot_reference_absent_raw_result(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    task = create_task(db_session)
    descriptor = store_tar(
        store,
        tmp_path,
        manifest_payload(raw_paths=["scanner/raw.json"]),
    )
    registrar = SandboxArtifactRegistrar(db_session, store)
    artifact = registrar.register(task, descriptor, kind=ArtifactKind.SCAN_RESULT)

    with pytest.raises(OrchestratorError) as captured:
        registrar.load_manifest(
            artifact,
            expected_operation=AnalysisOperation.INVENTORY,
        )

    assert captured.value.error_code == "ANALYSIS_MANIFEST_INVALID"


def test_output_tar_is_revalidated_at_orchestrator_boundary(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    task = create_task(db_session)
    descriptor = store_tar(
        store,
        tmp_path,
        manifest_payload(),
        symlink=True,
    )
    registrar = SandboxArtifactRegistrar(db_session, store)
    artifact = registrar.register(task, descriptor, kind=ArtifactKind.SCAN_RESULT)

    with pytest.raises(OrchestratorError) as captured:
        registrar.load_manifest(
            artifact,
            expected_operation=AnalysisOperation.INVENTORY,
        )

    assert captured.value.error_code == "ANALYSIS_OUTPUT_INVALID"
