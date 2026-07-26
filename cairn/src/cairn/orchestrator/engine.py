from __future__ import annotations

from datetime import UTC, datetime
import logging
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import (
    AnalysisManifest,
    AnalysisOperation,
    BYTECODE_SCANNERS,
    ToolStatus,
)
from cairn.analysis.fingerprints import merge_candidates
from cairn.orchestrator.artifacts import SandboxArtifactRegistrar
from cairn.orchestrator.client import SandboxBackend
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.errors import OrchestratorError
from cairn.orchestrator.tasks import TASK_SPECS, get_or_create_task
from cairn.sandbox.contracts import (
    ACTIVE_SANDBOX_STATUSES,
    SandboxCreateRequest,
    SandboxLimitsOverride,
    SandboxStatus,
    SnapshotArtifact,
)
from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import (
    ArtifactKind,
    AuditFactKind,
    AuditRunStatus,
    AuditTaskStatus,
    BuildStatus,
)
from cairn.server.errors import DomainError
from cairn.server.ingestion import GitFetcher, IngestionLimits
from cairn.server.persistence.models import (
    Artifact,
    AuditCoverage,
    AuditFact,
    AuditRun,
    AuditTask,
    SourceSnapshot,
)
from cairn.server.services.audit_runs import AuditRunService
from cairn.server.services.snapshots import SnapshotService


LOG = logging.getLogger(__name__)
_ELIGIBLE_STATUSES = {
    AuditRunStatus.CREATED.value,
    AuditRunStatus.INGESTING.value,
    AuditRunStatus.PREPROCESSING.value,
    AuditRunStatus.STATIC_SCANNING.value,
    AuditRunStatus.CANCELLING.value,
}
_SCANNER_ORDER = (
    AnalysisOperation.CODEQL,
    AnalysisOperation.SEMGREP,
    AnalysisOperation.FINDSECBUGS,
    AnalysisOperation.DEPENDENCY_CHECK,
    AnalysisOperation.TRIVY,
    AnalysisOperation.GITLEAKS,
    AnalysisOperation.CONFIG_RULES,
)
_RETRYABLE_MANIFEST_CODES = {
    "ANALYSIS_COMMAND_FAILED",
    "ANALYSIS_COMMAND_TIMEOUT",
    "ANALYSIS_INTERNAL_FAILURE",
    "SCANNER_EXIT_NONZERO",
    "SCANNER_OUTPUT_MISSING",
    "SCANNER_VERSION_FAILED",
}
_RETRYABLE_OUTPUT_CODES = {
    "ANALYSIS_MANIFEST_INVALID",
    "ANALYSIS_MANIFEST_MISSING",
    "ANALYSIS_OPERATION_MISMATCH",
    "ANALYSIS_OUTPUT_INVALID",
    "SANDBOX_ARTIFACT_INVALID",
}


class _RunCancelled(Exception):
    pass


class DeterministicOrchestrator:
    def __init__(
        self,
        session: Session,
        settings: OrchestratorSettings,
        artifact_store: ArtifactStore,
        sandbox: SandboxBackend,
    ) -> None:
        self.session = session
        self.settings = settings
        self.artifact_store = artifact_store
        self.sandbox = sandbox

    def process_next(self) -> UUID | None:
        audit_run = self.session.scalar(
            select(AuditRun)
            .where(AuditRun.status.in_(_ELIGIBLE_STATUSES))
            .order_by(AuditRun.created_at, AuditRun.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if audit_run is None:
            self.session.rollback()
            return None
        run_id = audit_run.id
        self.session.commit()
        self.process_run(run_id)
        return run_id

    def process_run(self, run_id: UUID) -> AuditRun:
        try:
            while True:
                audit_run = self._run(run_id)
                status = AuditRunStatus(audit_run.status)
                if status is AuditRunStatus.CANCELLING:
                    self._cancel_run(audit_run)
                    raise _RunCancelled
                if status is AuditRunStatus.CREATED:
                    AuditRunService(self.session).transition(
                        run_id,
                        AuditRunStatus.INGESTING,
                    )
                    continue
                if status is AuditRunStatus.INGESTING:
                    snapshot = self._resolve_snapshot(audit_run)
                    AuditRunService(self.session).transition(
                        run_id,
                        AuditRunStatus.PREPROCESSING,
                        snapshot_id=snapshot.id,
                    )
                    continue
                if status is AuditRunStatus.PREPROCESSING:
                    self._preprocess(audit_run)
                    continue
                if status is AuditRunStatus.STATIC_SCANNING:
                    self._static_scan(audit_run)
                    continue
                return audit_run
        except _RunCancelled:
            return self._run(run_id)
        except OrchestratorError as exc:
            self.session.rollback()
            if not exc.retryable:
                self._fail_run(run_id, exc)
            else:
                LOG.warning("orchestrator retryable error: %s", exc.error_code)
            return self._run(run_id)

    def _resolve_snapshot(self, audit_run: AuditRun) -> SourceSnapshot:
        if audit_run.snapshot is not None:
            return audit_run.snapshot
        source_request = audit_run.source_request
        source_type = source_request.get("type")
        service = SnapshotService(
            self.session,
            self.artifact_store,
            IngestionLimits.from_settings(self.settings),
            git_fetcher=GitFetcher(
                allowed_hosts=self.settings.git_allowed_hosts,
                timeout_seconds=self.settings.git_clone_timeout_seconds,
                max_checkout_bytes=self.settings.snapshot_max_total_bytes,
            ),
            secret_key_file=self.settings.secret_key_file,
            work_root=self.settings.ingestion_work_root,
        )
        try:
            if source_type == "git_ref":
                ref = source_request.get("ref")
                if not isinstance(ref, str):
                    raise OrchestratorError(
                        "ORCHESTRATOR_SOURCE_REQUEST_INVALID",
                        "Git source request is invalid",
                    )
                return service.create_from_git(audit_run.repository_id, ref)
            if source_type == "upload":
                try:
                    upload_id = UUID(str(source_request["upload_id"]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise OrchestratorError(
                        "ORCHESTRATOR_SOURCE_REQUEST_INVALID",
                        "Upload source request is invalid",
                    ) from exc
                return service.create_from_upload(audit_run.repository_id, upload_id)
        except DomainError as exc:
            raise OrchestratorError(
                exc.error_code,
                "Source ingestion failed",
            ) from exc
        raise OrchestratorError(
            "ORCHESTRATOR_SNAPSHOT_REQUIRED",
            "AuditRun source did not resolve to a Snapshot",
        )

    def _preprocess(self, audit_run: AuditRun) -> None:
        coverage = self._coverage(audit_run)
        inventory_task, inventory, inventory_artifacts = self._execute_profile(
            audit_run,
            AnalysisOperation.INVENTORY,
        )
        if inventory is None or inventory.status is not ToolStatus.COMPLETED:
            raise OrchestratorError(
                inventory.reason_code if inventory else "INVENTORY_FAILED",
                "Java inventory did not complete",
            )
        assert inventory.inventory is not None
        self._persist_inventory(
            audit_run,
            inventory_task,
            inventory,
            inventory_artifacts,
        )
        data = inventory.inventory
        coverage.modules_total = len(data.modules)
        coverage.modules_analyzed = len(data.modules)
        coverage.java_files_total = data.java_files_total
        skipped_java = sum(path.lower().endswith(".java") for path in data.skipped_paths)
        coverage.java_files_analyzed = max(0, data.java_files_total - skipped_java)
        coverage.entrypoints_total = len(data.entrypoints)
        coverage.entrypoints_analyzed = 0
        coverage.sensitive_sinks_total = len(data.sinks)
        coverage.sensitive_sinks_analyzed = 0
        coverage.skipped_paths = list(data.skipped_paths)
        coverage.unsupported_components = list(data.unsupported_components)
        audit_run.progress = 25
        self.session.commit()

        build_task, build_manifest, build_artifacts = self._execute_profile(
            audit_run,
            AnalysisOperation.BUILD,
        )
        del build_artifacts
        if (
            build_manifest is not None
            and build_manifest.status is ToolStatus.COMPLETED
            and build_manifest.build is not None
        ):
            coverage.build_status = build_manifest.build.status
            if build_manifest.build.status != BuildStatus.SUCCESS.value:
                self._add_warning(
                    coverage,
                    "PROJECT_BUILD_FAILED",
                    tool="build",
                    task_id=build_task.id,
                )
        else:
            coverage.build_status = BuildStatus.FAILED.value
            self._add_warning(
                coverage,
                build_manifest.reason_code
                if build_manifest is not None
                else build_task.error_code or "BUILD_EXECUTION_FAILED",
                tool="build",
                task_id=build_task.id,
            )
        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 40
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.STATIC_SCANNING,
        )

    def _static_scan(self, audit_run: AuditRun) -> None:
        coverage = self._coverage(audit_run)
        enabled = set(audit_run.policy.enabled_scanners)
        completed = dict(coverage.static_tools_completed)
        for operation in _SCANNER_ORDER:
            if operation.value not in enabled or operation.value in completed:
                continue
            if (
                operation in BYTECODE_SCANNERS
                and coverage.build_status == BuildStatus.FAILED.value
            ):
                task = get_or_create_task(self.session, audit_run, operation)
                task.status = AuditTaskStatus.SKIPPED.value
                task.error_code = "BYTECODE_UNAVAILABLE"
                task.finished_at = datetime.now(UTC)
                completed[operation.value] = self._tool_coverage(
                    task,
                    status=ToolStatus.SKIPPED,
                    version=None,
                    artifact_ids=[],
                    reason_code="BYTECODE_UNAVAILABLE",
                    candidate_count=0,
                )
                coverage.static_tools_completed = dict(completed)
                self._add_warning(
                    coverage,
                    "BYTECODE_UNAVAILABLE",
                    tool=operation.value,
                    task_id=task.id,
                )
                self.session.commit()
                continue

            task, manifest, artifacts = self._execute_profile(
                audit_run,
                operation,
            )
            if manifest is None:
                status = ToolStatus.FAILED
                version = None
                reason_code = task.error_code or "SCANNER_EXECUTION_FAILED"
                candidate_count = 0
            else:
                status = manifest.status
                version = manifest.tool_version
                reason_code = manifest.reason_code
                candidate_count = len(manifest.candidates)
                if manifest.candidates:
                    self._persist_candidates(
                        audit_run,
                        task,
                        manifest,
                        artifacts,
                    )
            completed[operation.value] = self._tool_coverage(
                task,
                status=status,
                version=version,
                artifact_ids=[UUID(identifier) for identifier in task.output_artifact_ids],
                reason_code=reason_code,
                candidate_count=candidate_count,
            )
            coverage.static_tools_completed = dict(completed)
            if status is not ToolStatus.COMPLETED:
                self._add_warning(
                    coverage,
                    reason_code or "SCANNER_EXECUTION_FAILED",
                    tool=operation.value,
                    task_id=task.id,
                )
            audit_run.warning_count = len(coverage.coverage_warnings)
            finished = len(completed)
            total = max(1, len(enabled))
            audit_run.progress = min(60, 40 + int(20 * finished / total))
            self.session.commit()

        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 60
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.SEMANTIC_AUDITING,
        )

    def _execute_profile(
        self,
        audit_run: AuditRun,
        operation: AnalysisOperation,
    ) -> tuple[AuditTask, AnalysisManifest | None, list[Artifact]]:
        task = get_or_create_task(self.session, audit_run, operation)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        existing_artifacts = self._task_artifacts(task)
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
        }:
            if not existing_artifacts:
                return task, None, []
            try:
                manifest = SandboxArtifactRegistrar(
                    self.session,
                    self.artifact_store,
                ).load_manifest(
                    existing_artifacts[-1],
                    expected_operation=operation,
                )
            except OrchestratorError:
                if task.status == AuditTaskStatus.FAILED.value:
                    return task, None, existing_artifacts
                raise
            return task, manifest, existing_artifacts
        if task.status == AuditTaskStatus.SKIPPED.value:
            return task, None, existing_artifacts

        spec = TASK_SPECS[operation]
        if task.status == AuditTaskStatus.RUNNING.value and task.sandbox_id is not None:
            sandbox_record = self.sandbox.get(task.sandbox_id)
        else:
            task.status = AuditTaskStatus.RUNNING.value
            task.worker_name = self.settings.orchestrator_worker_name
            task.attempt += 1
            task.started_at = task.started_at or datetime.now(UTC)
            task.finished_at = None
            task.error_code = None
            task.error_detail = None
            self.session.commit()
            snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
            if snapshot is None:
                raise OrchestratorError(
                    "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                    "AuditTask Snapshot is unavailable",
                )
            request = SandboxCreateRequest(
                template=spec.template,
                operation=operation.value,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(
                    timeout_seconds=task.timeout_seconds,
                ),
            )
            try:
                sandbox_record = self.sandbox.create(request)
            except OrchestratorError as exc:
                self._queue_or_fail_task(task, exc.error_code, exc.retryable)
                raise
            task.sandbox_id = sandbox_record.id
            self.session.commit()
            try:
                sandbox_record = self.sandbox.start(sandbox_record.id)
            except OrchestratorError as exc:
                try:
                    self.sandbox.destroy(sandbox_record.id)
                except OrchestratorError:
                    pass
                self._queue_or_fail_task(task, exc.error_code, exc.retryable)
                raise

        while sandbox_record.status in ACTIVE_SANDBOX_STATUSES:
            if self._cancellation_requested(audit_run.id):
                sandbox_record = self.sandbox.cancel(sandbox_record.id)
                task.status = AuditTaskStatus.CANCELLED.value
                task.error_code = "AUDIT_RUN_CANCELLED"
                task.finished_at = datetime.now(UTC)
                self.session.commit()
                self._cancel_run(self._run(audit_run.id))
                raise _RunCancelled
            sandbox_record = self.sandbox.wait(
                sandbox_record.id,
                self.settings.orchestrator_wait_seconds,
            )

        if sandbox_record.status is not SandboxStatus.SUCCEEDED:
            error_code = sandbox_record.failure_code or (
                f"SANDBOX_{sandbox_record.status.value.upper()}"
            )
            retryable = sandbox_record.status in {
                SandboxStatus.FAILED,
                SandboxStatus.TIMED_OUT,
            }
            self._queue_or_fail_task(task, error_code, retryable)
            try:
                self.sandbox.destroy(sandbox_record.id)
            except OrchestratorError:
                pass
            if task.status == AuditTaskStatus.QUEUED.value:
                raise OrchestratorError(
                    error_code,
                    "Sandbox execution failed and will be retried",
                    retryable=True,
                )
            return task, None, []

        if not sandbox_record.resources_destroyed:
            sandbox_record = self.sandbox.destroy(sandbox_record.id)
        if len(sandbox_record.artifacts) != 1:
            self._queue_or_fail_task(task, "ANALYSIS_OUTPUT_MISSING", False)
            return task, None, []

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task,
                sandbox_record.artifacts[0],
                kind=(
                    ArtifactKind.BUILD_LOG
                    if operation is AnalysisOperation.BUILD
                    else ArtifactKind.SCAN_RESULT
                ),
            )
            manifest = registrar.load_manifest(
                artifact,
                expected_operation=operation,
            )
        except OrchestratorError as exc:
            retryable = exc.retryable or exc.error_code in _RETRYABLE_OUTPUT_CODES
            self._queue_or_fail_task(task, exc.error_code, retryable)
            artifacts = self._task_artifacts(task)
            if task.status == AuditTaskStatus.QUEUED.value:
                raise OrchestratorError(
                    exc.error_code,
                    "Analysis output failed validation and will be retried",
                    retryable=True,
                ) from exc
            return task, None, artifacts
        if (
            manifest.status is ToolStatus.FAILED
            and manifest.reason_code in _RETRYABLE_MANIFEST_CODES
            and task.attempt < task.max_attempts
        ):
            self._queue_or_fail_task(
                task,
                manifest.reason_code,
                retryable=True,
            )
            raise OrchestratorError(
                manifest.reason_code,
                "Deterministic tool failed transiently and will be retried",
                retryable=True,
            )
        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if manifest.status is ToolStatus.COMPLETED:
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        elif manifest.status is ToolStatus.SKIPPED:
            task.status = AuditTaskStatus.SKIPPED.value
            task.error_code = manifest.reason_code
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = manifest.reason_code
        return task, manifest, [artifact]

    def _persist_inventory(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        manifest: AnalysisManifest,
        artifacts: list[Artifact],
    ) -> None:
        assert manifest.inventory is not None
        inventory = manifest.inventory.model_dump(mode="json")
        evidence_ids = [str(artifact.id) for artifact in artifacts]
        payloads = {
            AuditFactKind.ARCHITECTURE: {
                "build_system": inventory["build_system"],
                "java_versions": inventory["java_versions"],
                "modules": inventory["modules"],
                "module_dependencies": inventory["module_dependencies"],
                "build_plan": inventory["build_plan"],
                "symbols": inventory["symbols"],
                "permissions": inventory["permissions"],
                "classified_paths": inventory["classified_paths"],
            },
            AuditFactKind.ENTRYPOINT: {"items": inventory["entrypoints"]},
            AuditFactKind.SOURCE: {"items": inventory["sources"]},
            AuditFactKind.SINK: {"items": inventory["sinks"]},
        }
        for kind, payload in payloads.items():
            fact = self.session.scalar(
                select(AuditFact).where(
                    AuditFact.audit_run_id == audit_run.id,
                    AuditFact.created_by_task_id == task.id,
                    AuditFact.kind == kind.value,
                )
            )
            if fact is None:
                fact = AuditFact(
                    audit_run_id=audit_run.id,
                    kind=kind.value,
                    structured_payload=payload,
                    evidence_ids=evidence_ids,
                    created_by_task_id=task.id,
                )
                self.session.add(fact)
            else:
                fact.structured_payload = payload
                fact.evidence_ids = evidence_ids

    def _persist_candidates(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        manifest: AnalysisManifest,
        artifacts: list[Artifact],
    ) -> None:
        raw_artifact_ids = sorted(str(artifact.id) for artifact in artifacts)
        existing = list(
            self.session.scalars(
                select(AuditFact).where(
                    AuditFact.audit_run_id == audit_run.id,
                    AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
                )
            )
        )
        by_root = {
            str(fact.structured_payload.get("candidate", {}).get("root_cause_key")): fact
            for fact in existing
            if isinstance(fact.structured_payload.get("candidate"), dict)
        }
        for candidate_model in manifest.candidates:
            candidate = candidate_model.model_dump(mode="json")
            root_key = candidate["root_cause_key"]
            fact = by_root.get(root_key)
            if fact is None:
                fact = AuditFact(
                    audit_run_id=audit_run.id,
                    kind=AuditFactKind.CANDIDATE_FINDING.value,
                    structured_payload={
                        "candidate": candidate,
                        "raw_artifact_ids": raw_artifact_ids,
                    },
                    evidence_ids=raw_artifact_ids,
                    created_by_task_id=task.id,
                )
                self.session.add(fact)
                by_root[root_key] = fact
                continue
            current = fact.structured_payload["candidate"]
            merged = merge_candidates([current, candidate])[0]
            evidence = sorted(set(fact.evidence_ids) | set(raw_artifact_ids))
            fact.structured_payload = {
                "candidate": merged,
                "raw_artifact_ids": evidence,
            }
            fact.evidence_ids = evidence

    def _coverage(self, audit_run: AuditRun) -> AuditCoverage:
        coverage = self.session.get(AuditCoverage, audit_run.id)
        if coverage is not None:
            return coverage
        coverage = AuditCoverage(
            audit_run_id=audit_run.id,
            modules_total=0,
            modules_analyzed=0,
            java_files_total=0,
            java_files_analyzed=0,
            entrypoints_total=0,
            entrypoints_analyzed=0,
            sensitive_sinks_total=0,
            sensitive_sinks_analyzed=0,
            build_status=BuildStatus.FAILED.value,
            static_tools_completed={},
            skipped_paths=[],
            unsupported_components=[],
            coverage_warnings=[],
        )
        self.session.add(coverage)
        self.session.flush()
        return coverage

    def _add_warning(
        self,
        coverage: AuditCoverage,
        reason_code: str,
        *,
        tool: str,
        task_id: UUID,
    ) -> None:
        warnings = list(coverage.coverage_warnings)
        key = (reason_code, tool)
        if not any(
            (item.get("reason_code"), item.get("tool")) == key for item in warnings
        ):
            warnings.append(
                {
                    "reason_code": reason_code,
                    "tool": tool,
                    "task_id": str(task_id),
                }
            )
            coverage.coverage_warnings = warnings

    @staticmethod
    def _tool_coverage(
        task: AuditTask,
        *,
        status: ToolStatus,
        version: str | None,
        artifact_ids: list[UUID],
        reason_code: str | None,
        candidate_count: int,
    ) -> dict[str, object]:
        return {
            "status": status.value,
            "version": version,
            "task_id": str(task.id),
            "artifact_ids": [str(identifier) for identifier in artifact_ids],
            "reason_code": reason_code,
            "candidate_count": candidate_count,
        }

    def _queue_or_fail_task(
        self,
        task: AuditTask,
        error_code: str,
        retryable: bool,
    ) -> None:
        task.error_code = error_code
        task.sandbox_id = None
        if retryable and task.attempt < task.max_attempts:
            task.status = AuditTaskStatus.QUEUED.value
            task.finished_at = None
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.finished_at = datetime.now(UTC)
        self.session.commit()

    def _task_artifacts(self, task: AuditTask) -> list[Artifact]:
        return list(
            self.session.scalars(
                select(Artifact)
                .where(Artifact.produced_by_task_id == task.id)
                .order_by(Artifact.created_at, Artifact.id)
            )
        )

    def _cancellation_requested(self, run_id: UUID) -> bool:
        audit_run = self.session.get(AuditRun, run_id)
        assert audit_run is not None
        self.session.refresh(audit_run, attribute_names=["status"])
        return audit_run.status == AuditRunStatus.CANCELLING.value

    def _cancel_run(self, audit_run: AuditRun) -> None:
        if audit_run.status == AuditRunStatus.CANCELLING.value:
            AuditRunService(self.session).transition(
                audit_run.id,
                AuditRunStatus.CANCELLED,
            )

    def _fail_run(self, run_id: UUID, error: OrchestratorError) -> None:
        audit_run = self._run(run_id)
        if audit_run.status in {
            AuditRunStatus.COMPLETED.value,
            AuditRunStatus.COMPLETED_WITH_WARNINGS.value,
            AuditRunStatus.CANCELLED.value,
            AuditRunStatus.FAILED.value,
        }:
            return
        audit_run.failure_code = error.error_code
        audit_run.failure_reason = error.message
        AuditRunService(self.session).transition(
            run_id,
            AuditRunStatus.FAILED,
        )

    def _run(self, run_id: UUID) -> AuditRun:
        audit_run = self.session.get(AuditRun, run_id)
        if audit_run is None:
            raise OrchestratorError(
                "AUDIT_RUN_NOT_FOUND",
                "AuditRun does not exist",
            )
        return audit_run
