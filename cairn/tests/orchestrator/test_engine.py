from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
from uuid import UUID, uuid4
import zipfile

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis import runner as analysis_runner
from cairn.analysis.bytecode_index import (
    BytecodeToolchain,
    build_bytecode_index as build_real_bytecode_index,
)
from cairn.analysis.config_rules import scan_config
from cairn.analysis.indexer import build_inventory
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.engine import DeterministicOrchestrator
from cairn.orchestrator.errors import OrchestratorError
from cairn.sandbox.contracts import (
    SandboxArtifact,
    SandboxCreateRequest,
    SandboxLimits,
    SandboxRecord,
    SandboxStatus,
)
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditFactKind,
    AuditRunStatus,
    AuditTaskStatus,
    AuditTaskType,
    BuildSystem,
    DynamicVerificationMode,
    SnapshotInputKind,
    SnapshotStatus,
    SourceType,
)
from cairn.server.ingestion import IngestionLimits, collect_snapshot_tree, write_snapshot_archive
from cairn.server.persistence.models import (
    Artifact,
    AuditCoverage,
    AuditFact,
    AuditPolicy,
    AuditRun,
    AuditTask,
    Repository,
    SourceSnapshot,
)
from cairn.server.services.findings import FindingService
from cairn.server.services.snapshots import SnapshotService
from cairn.server.services.uploads import UploadService


FIXTURE = Path(__file__).parents[1] / "analysis/fixtures/maven-multi"


def _manifest(
    operation: str,
    *,
    status: str = "completed",
    version: str | None = "1.0.0",
    reason: str | None = None,
    inventory: dict[str, object] | None = None,
    build: dict[str, object] | None = None,
    candidates: list[dict[str, object]] | None = None,
    raw_paths: list[str] | None = None,
) -> dict[str, object]:
    return {
        "contract": "cairn-deterministic-result-v1",
        "operation": operation,
        "status": status,
        "tool_name": operation,
        "tool_version": version,
        "reason_code": reason,
        "warnings": [],
        "raw_result_paths": raw_paths or [],
        "inventory": inventory,
        "build": build,
        "candidates": candidates or [],
    }


class FakeSandbox:
    def __init__(
        self,
        store: LocalArtifactStore,
        tmp_path: Path,
        manifests: dict[
            str,
            dict[str, object] | list[dict[str, object]],
        ],
        raw_results: dict[str, dict[str, object | bytes]] | None = None,
    ) -> None:
        self.store = store
        self.tmp_path = tmp_path
        self.manifests = manifests
        self.raw_results = raw_results or {}
        self.records: dict[UUID, SandboxRecord] = {}
        self.requests: list[SandboxCreateRequest] = []

    @staticmethod
    def _limits() -> SandboxLimits:
        return SandboxLimits(
            cpu_millis=1000,
            memory_bytes=512 * 1024 * 1024,
            pids=128,
            disk_bytes=1024 * 1024 * 1024,
            output_bytes=256 * 1024 * 1024,
            tmpfs_bytes=64 * 1024 * 1024,
            timeout_seconds=900,
        )

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        self.requests.append(request)
        now = datetime.now(UTC)
        record = SandboxRecord(
            id=uuid4(),
            task_id=request.task_id,
            template=request.template,
            operation=request.operation,
            snapshot=request.snapshot,
            limits=self._limits().model_copy(
                update={
                    "timeout_seconds": request.limits.timeout_seconds or 900,
                }
            ),
            status=SandboxStatus.CREATED,
            created_at=now,
            deadline_at=now + timedelta(seconds=900),
        )
        self.records[record.id] = record
        return record

    def get(self, sandbox_id: UUID) -> SandboxRecord:
        return self.records[sandbox_id]

    def start(self, sandbox_id: UUID) -> SandboxRecord:
        record = self.records[sandbox_id].model_copy(
            update={
                "status": SandboxStatus.RUNNING,
                "started_at": datetime.now(UTC),
            }
        )
        self.records[sandbox_id] = record
        return record
    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        del timeout_seconds
        record = self.records[sandbox_id]
        operation = record.operation.value
        configured = self.manifests[operation]
        manifest = configured.pop(0) if isinstance(configured, list) else configured
        archive_path = self.tmp_path / f"{sandbox_id}.tar"
        encoded = json.dumps(manifest).encode()
        with tarfile.open(archive_path, mode="w") as archive:
            info = tarfile.TarInfo("manifest.json")
            info.size = len(encoded)
            archive.addfile(info, BytesIO(encoded))
            for raw_path in manifest["raw_result_paths"]:
                configured_raw = self.raw_results.get(operation, {}).get(raw_path)
                raw = (
                    configured_raw
                    if isinstance(configured_raw, bytes)
                    else (
                        json.dumps(configured_raw).encode()
                        if configured_raw is not None
                        else b"fixture raw output\n"
                    )
                )
                raw_info = tarfile.TarInfo(raw_path)
                raw_info.size = len(raw)
                archive.addfile(raw_info, BytesIO(raw))
        stored = self.store.put_file(archive_path)
        artifact = SandboxArtifact(
            storage_key=stored.storage_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type="application/x-tar",
        )
        completed = record.model_copy(
            update={
                "status": SandboxStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "exit_code": 0,
                "artifacts": [artifact],
                "resources_destroyed": True,
            }
        )
        self.records[sandbox_id] = completed
        return completed

    def cancel(self, sandbox_id: UUID) -> SandboxRecord:
        record = self.records[sandbox_id].model_copy(
            update={
                "status": SandboxStatus.CANCELLED,
                "finished_at": datetime.now(UTC),
                "resources_destroyed": True,
            }
        )
        self.records[sandbox_id] = record
        return record

    def collect(self, sandbox_id: UUID) -> SandboxRecord:
        return self.records[sandbox_id]

    def destroy(self, sandbox_id: UUID) -> SandboxRecord:
        record = self.records[sandbox_id].model_copy(
            update={"resources_destroyed": True}
        )
        self.records[sandbox_id] = record
        return record


class FailingStartSandbox(FakeSandbox):
    def __init__(self, store: LocalArtifactStore, tmp_path: Path) -> None:
        super().__init__(store, tmp_path, {})
        self.destroyed: list[UUID] = []

    def start(self, sandbox_id: UUID) -> SandboxRecord:
        raise OrchestratorError(
            "SANDBOX_API_UNAVAILABLE",
            "Sandbox start response was unavailable",
            retryable=True,
        )

    def destroy(self, sandbox_id: UUID) -> SandboxRecord:
        self.destroyed.append(sandbox_id)
        return super().destroy(sandbox_id)


def _ingestion_limits() -> IngestionLimits:
    return IngestionLimits(
        upload_max_bytes=100 * 1024 * 1024,
        max_files=10_000,
        max_total_bytes=100 * 1024 * 1024,
        max_file_bytes=10 * 1024 * 1024,
        max_compression_ratio=200,
        max_path_length=1024,
        max_path_depth=64,
    )


def create_run(
    session: Session,
    store: LocalArtifactStore,
    tmp_path: Path,
    *,
    input_kind: SnapshotInputKind = SnapshotInputKind.SOURCE,
) -> AuditRun:
    tree = collect_snapshot_tree(FIXTURE, _ingestion_limits())
    archive_path = tmp_path / "snapshot.tar"
    write_snapshot_archive(tree, archive_path)
    stored = store.put_file(archive_path)
    repository = Repository(
        name="orchestrated",
        source_type=SourceType.ZIP.value,
        created_by="system",
    )
    policy = AuditPolicy(
        name="comprehensive",
        version=1,
        include_paths=["**"],
        exclude_paths=[],
        enabled_scanners=[
            "codeql",
            "config-rules",
            "dependency-check",
            "findsecbugs",
            "gitleaks",
            "semgrep",
            "trivy",
        ],
        dynamic_verification=DynamicVerificationMode.REQUIRED.value,
        severity_thresholds={},
        resource_budget={},
        active=True,
    )
    session.add_all([repository, policy])
    session.flush()
    artifact = Artifact(
        audit_run_id=None,
        kind=ArtifactKind.SOURCE_SNAPSHOT.value,
        storage_key=stored.storage_key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type="application/x-tar",
        access_level=ArtifactAccessLevel.SENSITIVE.value,
    )
    snapshot = SourceSnapshot(
        repository_id=repository.id,
        content_sha256=tree.content_sha256,
        artifact=artifact,
        file_count=tree.file_count,
        total_bytes=tree.total_bytes,
        java_file_count=tree.java_file_count,
        jvm_artifact_count=(1 if input_kind is SnapshotInputKind.BYTECODE else 0),
        input_kind=input_kind.value,
        java_version=None,
        build_system=BuildSystem.MAVEN.value,
        status=SnapshotStatus.READY.value,
    )
    session.add(snapshot)
    session.flush()
    audit_run = AuditRun(
        repository_id=repository.id,
        source_request={"type": "snapshot", "snapshot_id": str(snapshot.id)},
        snapshot_id=snapshot.id,
        policy_id=policy.id,
        policy_version=policy.version,
        status=AuditRunStatus.CREATED.value,
        current_stage=None,
        progress=0,
        warning_count=0,
        created_by="system",
    )
    session.add(audit_run)
    session.commit()
    return audit_run


def test_binary_preprocess_hydrates_index_persists_candidate_and_skips_build(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(
        db_session,
        store,
        tmp_path,
        input_kind=SnapshotInputKind.BYTECODE,
    )
    audit_run.status = AuditRunStatus.PREPROCESSING.value
    db_session.commit()
    binary_inventory = {
        "contract": "cairn-binary-inventory-v1",
        "target_java_version": 17,
        "components": [],
        "entries": [
            {
                "logical_path": "Action.class",
                "container_path": None,
                "entry_path": "Action.class",
                "kind": "class",
                "sha256": "a" * 64,
                "size_bytes": 128,
                "archive_depth": 0,
                "classfile_major": 61,
                "classfile_minor": 0,
                "constant_pool_count": 10,
                "validation": "header-only",
                "multi_release_version": None,
                "selected": True,
                "resource_kind": None,
            }
        ],
        "resources": [],
        "coverage_gaps": [],
        "archive_count": 0,
        "class_entry_count": 1,
        "selected_class_count": 1,
        "expanded_entry_count": 0,
        "expanded_bytes": 0,
        "sbom": {"bomFormat": "CycloneDX"},
    }
    program_index = {
        "contract": "cairn-program-index-v2",
        "asm_version": "9.8",
        "target_java_version": 17,
        "components": [],
        "resources": [],
        "classes": [
            {
                "logical_path": "Action.class",
                "container_path": None,
                "entry_path": "Action.class",
                "class_sha256": "a" * 64,
                "class_name": "fixture.Action",
                "super_name": "java.lang.Object",
                "interfaces": [],
                "access": 1,
                "classfile_major": 61,
                "signature": None,
                "source_file": None,
                "annotations": [],
            }
        ],
        "methods": [
            {
                "logical_path": "Action.class",
                "container_path": None,
                "entry_path": "Action.class",
                "class_sha256": "a" * 64,
                "class_name": "fixture.Action",
                "method_name": "lookup",
                "method_descriptor": "()V",
                "access": 1,
                "signature": None,
                "exceptions": [],
                "annotations": [],
                "start_line": None,
                "end_line": None,
                "first_bytecode_offset": 0,
                "last_bytecode_offset": 8,
            }
        ],
        "fields": [],
        "calls": [
            {
                "logical_path": "Action.class",
                "container_path": None,
                "entry_path": "Action.class",
                "class_sha256": "a" * 64,
                "class_name": "fixture.Action",
                "method_name": "lookup",
                "method_descriptor": "()V",
                "bytecode_offset": 7,
                "source_line": None,
                "opcode": 185,
                "edge_kind": "inferred",
                "target_owner": "java.sql.Statement",
                "target_name": "executeQuery",
                "target_descriptor": "(Ljava/lang/String;)V",
                "interface": True,
                "callsite_name": None,
                "callsite_descriptor": None,
                "bootstrap_owner": None,
                "bootstrap_name": None,
                "bootstrap_descriptor": None,
            }
        ],
        "field_accesses": [],
        "decompiled_views": [
            {
                "logical_path": "Action.class",
                "class_sha256": "a" * 64,
                "class_name": "fixture.Action",
                "artifact_path": f"decompiled/cfr-0.152/{'a' * 64}.java",
                "decompiler": "cfr",
                "decompiler_version": "0.152",
            }
        ],
        "coverage_gaps": [],
        "classes_total": 1,
        "classes_parsed": 1,
    }
    candidate = {
        "rule_id": "jvm-bytecode-sql-execution",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "severity": "high",
        "confidence": "low",
        "message": "A symbolic JDBC call requires reachability review.",
        "locations": [
            {
                "origin_kind": "bytecode",
                "container_path": None,
                "entry_path": "Action.class",
                "class_name": "fixture.Action",
                "method_name": "lookup",
                "method_descriptor": "()V",
                "bytecode_offset": 7,
                "source_path": None,
                "start_line": None,
                "end_line": None,
                "decompiled_artifact_id": None,
                "decompiled_start_line": None,
                "decompiled_end_line": None,
                "symbol": "fixture.Action.lookup()V",
                "role": "sink",
            }
        ],
        "sink": "java.sql.Statement.executeQuery(Ljava/lang/String;)V",
        "fingerprint": "b" * 64,
        "root_cause_key": "c" * 64,
        "discovered_by": ["bytecode-sinks"],
        "source_rules": ["jvm-bytecode-sql-execution"],
        "call_chain": [],
        "controllability": None,
        "existing_defenses": [],
        "attack_preconditions": "Not established.",
        "impact": "Potential SQL injection.",
        "recommended_verification": "Trace callers and arguments.",
        "severity_conflict": [],
    }
    view_path = program_index["decompiled_views"][0]["artifact_path"]
    manifests = {
        "binary-inventory": {
            "contract": "cairn-deterministic-result-v1",
            "operation": "binary-inventory",
            "status": "completed",
            "tool_name": "cairn-binary-inventory",
            "tool_version": "1.0.0",
            "reason_code": None,
            "warnings": [],
            "raw_result_paths": ["binary-inventory.json", "sbom.cdx.json"],
            "binary_inventory_path": "binary-inventory.json",
            "binary_inventory_summary": {
                "contract": "cairn-binary-inventory-summary-v1",
                "archive_count": 0,
                "class_entry_count": 1,
                "selected_class_count": 1,
                "expanded_entry_count": 0,
                "expanded_bytes": 0,
                "coverage_gap_count": 0,
            },
        },
        "bytecode-index": {
            "contract": "cairn-deterministic-result-v1",
            "operation": "bytecode-index",
            "status": "completed",
            "tool_name": "cairn-bytecode-indexer",
            "tool_version": "1.0.0+asm-9.8",
            "reason_code": None,
            "warnings": [],
            "raw_result_paths": [
                "bytecode-candidates.json",
                str(view_path),
                "program-index-v2.json",
            ],
            "bytecode_index_path": "program-index-v2.json",
            "bytecode_index_summary": {
                "contract": "cairn-program-index-summary-v1",
                "classes_total": 1,
                "classes_parsed": 1,
                "component_count": 0,
                "resource_count": 0,
                "method_count": 1,
                "call_count": 1,
                "field_access_count": 0,
                "decompiled_view_count": 1,
                "coverage_gap_count": 0,
            },
            "candidates_path": "bytecode-candidates.json",
            "candidate_count": 1,
        },
    }
    raw_results = {
        "binary-inventory": {
            "binary-inventory.json": binary_inventory,
            "sbom.cdx.json": binary_inventory["sbom"],
        },
        "bytecode-index": {
            "bytecode-candidates.json": {
                "contract": "cairn-candidate-result-v1",
                "candidates": [candidate],
            },
            "program-index-v2.json": program_index,
            str(view_path): b"public final class Action {}\n",
        },
    }
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, manifests, raw_results)
    orchestrator = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    )

    orchestrator._preprocess(audit_run)

    db_session.refresh(audit_run)
    coverage = db_session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    assert audit_run.status == AuditRunStatus.STATIC_SCANNING.value
    assert coverage.java_files_total == coverage.java_files_analyzed == 1
    assert coverage.sensitive_sinks_total == 1
    assert {request.operation.value for request in sandbox.requests} == {
        "binary-inventory",
        "bytecode-index",
    }
    tasks = list(
        db_session.scalars(
            select(AuditTask).where(AuditTask.audit_run_id == audit_run.id)
        )
    )
    assert all(task.type != AuditTaskType.BUILD.value for task in tasks)
    fact = db_session.scalar(
        select(AuditFact).where(
            AuditFact.audit_run_id == audit_run.id,
            AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
        )
    )
    assert fact is not None
    location = fact.structured_payload["candidate"]["locations"][0]
    assert UUID(location["decompiled_artifact_id"])
    findings = orchestrator._promote_findings(
        audit_run,
        coverage,
        FindingService(db_session),
    )
    assert len(findings) == 1
    persisted = findings[0].locations[0]
    assert persisted.file_path is None
    assert persisted.entry_path == "Action.class"
    assert persisted.method_descriptor == "()V"
    assert persisted.bytecode_offset == 7
    with pytest.raises(OrchestratorError) as captured:
        orchestrator._verify_candidate(findings[0], "c" * 64)
    assert captured.value.error_code == "VERIFY_SOURCE_LOCATION_UNAVAILABLE"


def test_real_war_upload_reaches_asm_cfr_finding_and_coverage(
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise the CP1/CP2 vertical slice with no committed binary fixture."""

    javac = shutil.which("javac")
    java = shutil.which("java")
    asm_jar = Path(os.environ.get("CAIRN_TEST_ASM_JAR", ""))
    cfr_jar = Path(os.environ.get("CAIRN_TEST_CFR_JAR", ""))
    if (
        javac is None
        or java is None
        or not asm_jar.is_file()
        or not cfr_jar.is_file()
    ):
        pytest.skip("javac/java and pinned ASM/CFR JARs are required")

    compiled = tmp_path / "compiled"
    compiled.mkdir()
    sink_source = tmp_path / "BinaryAction.java"
    sink_source.write_text(
        """package fixture;
import java.sql.Statement;
public final class BinaryAction {
    public void lookup(String value, Statement statement) throws Exception {
        statement.execute("select * from users where name = " + value);
    }
}
""",
        encoding="utf-8",
    )
    subprocess.run(
        [javac, "--release", "17", "-g:none", "-d", str(compiled), str(sink_source)],
        check=True,
        capture_output=True,
        timeout=30,
    )

    war_path = tmp_path / "sample.war"
    timestamp = (2020, 1, 1, 0, 0, 0)
    with zipfile.ZipFile(war_path, "w", compression=zipfile.ZIP_DEFLATED) as war:
        for name, payload in (
            ("WEB-INF/web.xml", b"<web-app/>\n"),
            (
                "WEB-INF/classes/fixture/BinaryAction.class",
                (compiled / "fixture/BinaryAction.class").read_bytes(),
            ),
        ):
            info = zipfile.ZipInfo(name, timestamp)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100444 << 16)
            war.writestr(info, payload)

    helper_classes = tmp_path / "helper-classes"
    helper_classes.mkdir()
    helper_source = (
        Path(__file__).parents[3]
        / "sandbox-images/java/dev/cairn/bytecode/BytecodeIndexer.java"
    )
    subprocess.run(
        [
            javac,
            "--release",
            "17",
            "-encoding",
            "UTF-8",
            "-cp",
            str(asm_jar),
            "-d",
            str(helper_classes),
            str(helper_source),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    helper_jar = tmp_path / "cairn-bytecode-indexer.jar"
    with zipfile.ZipFile(helper_jar, "w", compression=zipfile.ZIP_DEFLATED) as jar:
        for class_file in sorted(helper_classes.rglob("*.class")):
            jar.write(class_file, class_file.relative_to(helper_classes).as_posix())
    toolchain = BytecodeToolchain(
        java=java,
        asm_jar=asm_jar,
        helper_jar=helper_jar,
        cfr_jar=cfr_jar,
    )

    def pinned_index(source: Path, scratch: Path, output: Path):
        return build_real_bytecode_index(
            source,
            scratch,
            output,
            toolchain=toolchain,
        )

    monkeypatch.setattr(analysis_runner, "build_bytecode_index", pinned_index)

    store = LocalArtifactStore(tmp_path / "artifacts")
    repository = Repository(
        name="real-binary-war",
        source_type=SourceType.BINARY_UPLOAD.value,
        created_by="fixture",
    )
    policy = AuditPolicy(
        name="real-binary-policy",
        version=1,
        include_paths=["**"],
        exclude_paths=[],
        enabled_scanners=[],
        dynamic_verification=DynamicVerificationMode.DISABLED.value,
        severity_thresholds={},
        resource_budget={},
        active=True,
    )
    db_session.add_all([repository, policy])
    db_session.flush()
    upload = UploadService(db_session, store).create(
        war_path,
        source_type=SourceType.BINARY_UPLOAD,
        original_filename="sample.war",
        actor="fixture",
        limits=_ingestion_limits(),
    )
    db_session.commit()
    snapshot = SnapshotService(
        db_session,
        store,
        _ingestion_limits(),
        work_root=tmp_path,
    ).create_from_upload(repository.id, upload.id)
    db_session.commit()
    assert snapshot.input_kind == SnapshotInputKind.BYTECODE.value
    assert snapshot.java_file_count == 0
    assert snapshot.jvm_artifact_count == 1

    snapshot_tar = store.resolve(
        snapshot.artifact.storage_key,
        expected_sha256=snapshot.artifact.sha256,
        expected_size=snapshot.artifact.size_bytes,
    )
    analysis_source = tmp_path / "analysis-source"
    analysis_source.mkdir()
    with tarfile.open(snapshot_tar, mode="r:") as archive:
        assert archive.getnames() == ["sample.war"]
        archive.extractall(analysis_source, filter="data")

    operation_outputs: dict[str, Path] = {}
    manifests: dict[str, dict[str, object]] = {}
    for operation in ("binary-inventory", "bytecode-index"):
        scratch = tmp_path / f"real-{operation}-scratch"
        output = tmp_path / f"real-{operation}-output"
        output.mkdir()
        manifests[operation] = analysis_runner.run_operation(
            operation,
            source=analysis_source,
            scratch=scratch,
            output=output,
        )
        operation_outputs[operation] = output
        assert manifests[operation]["status"] == "completed"

    assert manifests["binary-inventory"]["binary_inventory"] is None
    assert manifests["binary-inventory"]["binary_inventory_path"] == (
        "binary-inventory.json"
    )
    assert manifests["bytecode-index"]["bytecode_index"] is None
    assert manifests["bytecode-index"]["candidate_count"] == 1
    raw_results = {
        operation: {
            path.relative_to(output).as_posix(): path.read_bytes()
            for path in output.rglob("*")
            if path.is_file()
        }
        for operation, output in operation_outputs.items()
    }

    audit_run = AuditRun(
        repository_id=repository.id,
        source_request={"type": "snapshot", "snapshot_id": str(snapshot.id)},
        snapshot_id=snapshot.id,
        policy_id=policy.id,
        policy_version=policy.version,
        status=AuditRunStatus.PREPROCESSING.value,
        current_stage=AuditRunStatus.PREPROCESSING.value,
        progress=0,
        warning_count=0,
        created_by="fixture",
    )
    db_session.add(audit_run)
    db_session.commit()
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40, encoding="utf-8")
    sandbox = FakeSandbox(store, tmp_path, manifests, raw_results)
    orchestrator = DeterministicOrchestrator(
        db_session,
        OrchestratorSettings(
            database_url="sqlite+pysqlite:///:memory:",
            artifact_root=tmp_path / "artifacts",
            ingestion_work_root=tmp_path / "ingestion",
            sandbox_auth_token_file=token_file,
        ),
        store,
        sandbox,
    )

    orchestrator._preprocess(audit_run)
    coverage = db_session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    findings = orchestrator._promote_findings(
        audit_run,
        coverage,
        FindingService(db_session),
    )

    assert len(findings) == 1
    location = findings[0].locations[0]
    assert location.origin_kind == "bytecode"
    assert location.file_path is None
    assert location.start_line is None
    assert location.container_path == "sample.war"
    assert location.entry_path == "WEB-INF/classes/fixture/BinaryAction.class"
    assert location.class_name == "fixture.BinaryAction"
    assert location.method_name == "lookup"
    assert location.bytecode_offset is not None
    assert location.decompiled_artifact_id is not None
    assert coverage.modules_total == coverage.modules_analyzed == 1
    assert coverage.java_files_total == coverage.java_files_analyzed == 1
    assert coverage.sensitive_sinks_total == 1
    assert coverage.skipped_paths == []
    assert coverage.unsupported_components == []
    assert coverage.static_tools_completed["bytecode-index"]["candidate_count"] == 1
    assert {
        warning["reason_code"] for warning in coverage.coverage_warnings
    } == {"SOURCE_BUILD_NOT_APPLICABLE"}
    tasks = list(
        db_session.scalars(
            select(AuditTask).where(AuditTask.audit_run_id == audit_run.id)
        )
    )
    assert all(task.type != AuditTaskType.BUILD.value for task in tasks)


def test_build_failure_continues_source_scans_and_records_coverage(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    inventory = build_inventory(FIXTURE)
    candidates = scan_config(
        FIXTURE,
        snapshot_sha256=audit_run.snapshot.content_sha256,
    )
    semgrep_candidate = {
        **candidates[0],
        "rule_id": "fixture.semgrep.stacktrace",
        "fingerprint": "b" * 64,
        "discovered_by": ["semgrep"],
        "source_rules": ["fixture.semgrep.stacktrace"],
    }
    manifests = {
        "inventory": _manifest("inventory", inventory=inventory),
        "build": _manifest(
            "build",
            build={
                "status": "failed",
                "steps": [
                    {
                        "module_path": ".",
                        "build_system": "maven",
                        "runner": "maven-wrapper",
                        "status": "failed",
                        "exit_code": 1,
                        "log_path": "build/000-maven.log",
                        "reason_code": "PROJECT_BUILD_FAILED",
                    }
                ],
            },
            raw_paths=["build/000-maven.log"],
        ),
        "semgrep": _manifest(
            "semgrep",
            version="1.130.0",
            candidates=[semgrep_candidate],
            raw_paths=["scanners/semgrep.json"],
        ),
        "dependency-check": _manifest(
            "dependency-check",
            status="unavailable",
            version=None,
            reason="SCANNER_ASSET_UNAVAILABLE",
        ),
        "trivy": _manifest(
            "trivy",
            status="unavailable",
            version=None,
            reason="SCANNER_ASSET_UNAVAILABLE",
        ),
        "gitleaks": _manifest(
            "gitleaks",
            status="unavailable",
            version=None,
            reason="SCANNER_BINARY_UNAVAILABLE",
        ),
        "config-rules": _manifest(
            "config-rules",
            version="1.0.0",
            candidates=candidates,
        ),
    }
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, manifests)

    result = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    ).process_run(audit_run.id)

    # 6a carries the run through promotion, dynamic verification and machine
    # review in one pass; it parks at human_review, which subproject 7 owns.
    assert result.status == AuditRunStatus.HUMAN_REVIEW.value
    assert result.progress == 90
    coverage = db_session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    assert coverage.build_status == "failed"
    assert coverage.modules_total == 3
    assert coverage.java_files_total == 2
    assert coverage.entrypoints_total == 2
    assert coverage.sensitive_sinks_total == 1
    tools = coverage.static_tools_completed
    assert tools["codeql"]["status"] == "skipped"
    assert tools["findsecbugs"]["status"] == "skipped"
    assert tools["semgrep"]["status"] == "completed"
    assert tools["semgrep"]["version"] == "1.130.0"
    assert tools["config-rules"]["status"] == "completed"
    assert tools["dependency-check"]["status"] == "unavailable"
    assert tools["trivy"]["reason_code"] == "SCANNER_ASSET_UNAVAILABLE"
    assert tools["gitleaks"]["reason_code"] == "SCANNER_BINARY_UNAVAILABLE"
    # The seventh is the semantic stage: this fixture has real entrypoints,
    # so a review is planned, and with no LLM grant signing key configured
    # it fails closed and is reported as a coverage gap rather than skipped.
    # The last two are the dynamic stage reporting, per §7.7, that the build
    # produced nothing runnable and so no runtime environment existed — an
    # inconclusive verdict, never a rejection.
    assert result.warning_count == len(coverage.coverage_warnings) == 9
    assert {
        warning["reason_code"] for warning in coverage.coverage_warnings
    } >= {"DYNAMIC_BUILD_ARTIFACT_MISSING", "DYNAMIC_ENVIRONMENT_UNAVAILABLE"}
    assert {
        warning["reason_code"] for warning in coverage.coverage_warnings
    } >= {"SEMANTIC_GRANT_KEY_UNAVAILABLE"}

    tasks = list(
        db_session.scalars(
            select(AuditTask)
            .where(AuditTask.audit_run_id == audit_run.id)
            .order_by(AuditTask.scope_key)
        )
    )
    # Nine deterministic profiles plus one planned semantic review.
    assert len(tasks) == 10
    assert sum(
        task.type == AuditTaskType.SEMANTIC_REVIEW.value for task in tasks
    ) == 1
    assert sum(task.status == AuditTaskStatus.SKIPPED.value for task in tasks) == 2
    assert {
        request.operation.value for request in sandbox.requests
    } == {
        "inventory",
        "build",
        "semgrep",
        "dependency-check",
        "trivy",
        "gitleaks",
        "config-rules",
    }
    output_artifacts = list(
        db_session.scalars(
            select(Artifact).where(Artifact.audit_run_id == audit_run.id)
        )
    )
    assert len(output_artifacts) == 7
    assert all(artifact.produced_by_task_id is not None for artifact in output_artifacts)

    facts = list(
        db_session.scalars(
            select(AuditFact).where(AuditFact.audit_run_id == audit_run.id)
        )
    )
    assert {fact.kind for fact in facts} >= {
        AuditFactKind.ARCHITECTURE.value,
        AuditFactKind.ENTRYPOINT.value,
        AuditFactKind.SOURCE.value,
        AuditFactKind.SINK.value,
        AuditFactKind.CANDIDATE_FINDING.value,
    }
    candidate_facts = [
        fact for fact in facts if fact.kind == AuditFactKind.CANDIDATE_FINDING.value
    ]
    assert len(candidate_facts) == 1
    merged = candidate_facts[0].structured_payload["candidate"]
    assert merged["discovered_by"] == ["config-rules", "semgrep"]
    assert len(candidate_facts[0].evidence_ids) == 2


def test_completed_deterministic_stage_is_idempotent(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    audit_run.status = AuditRunStatus.SEMANTIC_AUDITING.value
    audit_run.current_stage = AuditRunStatus.SEMANTIC_AUDITING.value
    db_session.commit()
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, {})

    result = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    ).process_run(audit_run.id)

    # `semantic_auditing` is now a resumable branch rather than a parking
    # spot, so the run carries on to human_review. What must not happen is a
    # re-run of the deterministic profiles that already succeeded.
    assert result.status == AuditRunStatus.HUMAN_REVIEW.value
    assert sandbox.requests == []


def test_transient_scanner_failure_retries_and_preserves_attempt_artifacts(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    audit_run.policy.enabled_scanners = ["semgrep"]
    db_session.commit()
    manifests = {
        "inventory": _manifest(
            "inventory",
            inventory=build_inventory(FIXTURE),
        ),
        "build": _manifest(
            "build",
            build={"status": "failed", "steps": []},
        ),
        "semgrep": [
            _manifest(
                "semgrep",
                status="failed",
                version="1.130.0",
                reason="SCANNER_EXIT_NONZERO",
                raw_paths=["scanners/semgrep.log"],
            ),
            _manifest(
                "semgrep",
                version="1.130.0",
                raw_paths=["scanners/semgrep.json"],
            ),
        ],
    }
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, manifests)
    orchestrator = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    )

    first = orchestrator.process_run(audit_run.id)

    assert first.status == AuditRunStatus.STATIC_SCANNING.value
    task = db_session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == "deterministic:semgrep",
        )
    )
    assert task is not None
    assert task.status == AuditTaskStatus.QUEUED.value
    assert task.attempt == 1
    assert len(task.output_artifact_ids) == 1

    second = orchestrator.process_run(audit_run.id)

    assert second.status == AuditRunStatus.HUMAN_REVIEW.value
    db_session.refresh(task)
    assert task.status == AuditTaskStatus.SUCCEEDED.value
    assert task.attempt == 2
    assert len(task.output_artifact_ids) == 2
    coverage = db_session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    assert len(coverage.static_tools_completed["semgrep"]["artifact_ids"]) == 2


def test_invalid_manifest_retries_and_preserves_attempt_artifact(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    audit_run.policy.enabled_scanners = []
    db_session.commit()
    invalid_inventory = _manifest(
        "inventory",
        inventory=build_inventory(FIXTURE),
    )
    invalid_inventory.pop("tool_name")
    manifests = {
        "inventory": [
            invalid_inventory,
            _manifest("inventory", inventory=build_inventory(FIXTURE)),
        ],
        "build": _manifest(
            "build",
            build={"status": "failed", "steps": []},
        ),
    }
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, manifests)
    orchestrator = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    )

    first = orchestrator.process_run(audit_run.id)

    assert first.status == AuditRunStatus.PREPROCESSING.value
    inventory_task = db_session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == "deterministic:inventory",
        )
    )
    assert inventory_task is not None
    assert inventory_task.status == AuditTaskStatus.QUEUED.value
    assert inventory_task.error_code == "ANALYSIS_MANIFEST_INVALID"
    assert inventory_task.attempt == 1
    assert len(inventory_task.output_artifact_ids) == 1

    second = orchestrator.process_run(audit_run.id)

    assert second.status == AuditRunStatus.HUMAN_REVIEW.value
    db_session.refresh(inventory_task)
    assert inventory_task.status == AuditTaskStatus.SUCCEEDED.value
    assert inventory_task.attempt == 2
    assert len(inventory_task.output_artifact_ids) == 2


def test_start_failure_destroys_created_sandbox_before_retry(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FailingStartSandbox(store, tmp_path)

    result = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    ).process_run(audit_run.id)

    assert result.status == AuditRunStatus.PREPROCESSING.value
    task = db_session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == "deterministic:inventory",
        )
    )
    assert task is not None
    assert task.status == AuditTaskStatus.QUEUED.value
    assert task.sandbox_id is None
    assert len(sandbox.requests) == 1
    created_id = next(iter(sandbox.records))
    assert sandbox.destroyed == [created_id]
    assert sandbox.records[created_id].resources_destroyed is True


def test_invalid_scanner_manifest_stops_at_attempt_budget_with_coverage(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    audit_run.policy.enabled_scanners = ["semgrep"]
    db_session.commit()
    invalid_manifests: list[dict[str, object]] = []
    for index in range(3):
        invalid = _manifest(
            "semgrep",
            version="1.130.0",
            raw_paths=[f"scanners/attempt-{index}.log"],
        )
        invalid.pop("tool_name")
        invalid_manifests.append(invalid)
    manifests = {
        "inventory": _manifest(
            "inventory",
            inventory=build_inventory(FIXTURE),
        ),
        "build": _manifest(
            "build",
            build={"status": "failed", "steps": []},
        ),
        "semgrep": invalid_manifests,
    }
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    sandbox = FakeSandbox(store, tmp_path, manifests)
    orchestrator = DeterministicOrchestrator(
        db_session,
        settings,
        store,
        sandbox,
    )

    first_status = orchestrator.process_run(audit_run.id).status
    second_status = orchestrator.process_run(audit_run.id).status
    third_status = orchestrator.process_run(audit_run.id).status

    assert first_status == AuditRunStatus.STATIC_SCANNING.value
    assert second_status == AuditRunStatus.STATIC_SCANNING.value
    assert third_status == AuditRunStatus.HUMAN_REVIEW.value
    task = db_session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == "deterministic:semgrep",
        )
    )
    assert task is not None
    assert task.status == AuditTaskStatus.FAILED.value
    assert task.error_code == "ANALYSIS_MANIFEST_INVALID"
    assert task.attempt == task.max_attempts == 3
    assert len(task.output_artifact_ids) == 3
    coverage = db_session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    assert coverage.static_tools_completed["semgrep"] == {
        "status": "failed",
        "version": None,
        "task_id": str(task.id),
        "artifact_ids": task.output_artifact_ids,
        "reason_code": "ANALYSIS_MANIFEST_INVALID",
        "candidate_count": 0,
    }
