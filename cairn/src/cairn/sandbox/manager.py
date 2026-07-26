from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
import os
from pathlib import Path
import shutil
import threading
import time
from uuid import UUID, uuid4

from cairn.sandbox.archives import (
    ArchiveLimits,
    archive_output_tree,
    extract_snapshot_archive,
    measure_writable_tree,
)
from cairn.sandbox.backend import (
    BackendContainerStatus,
    BackendFailure,
    SandboxContainerBackend,
    SandboxWorkspace,
)
from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.contracts import (
    ACTIVE_SANDBOX_STATUSES,
    SandboxArtifact,
    SandboxCreateRequest,
    SandboxRecord,
    SandboxStatus,
)
from cairn.sandbox.errors import SandboxError, invalid_sandbox_state
from cairn.sandbox.state import FileSandboxStateStore
from cairn.sandbox.templates import TemplateRegistry
from cairn.server.artifacts.base import ArtifactStoreError
from cairn.server.artifacts.local import LocalArtifactStore


LOG = logging.getLogger(__name__)


class SandboxManager:
    def __init__(
        self,
        settings: SandboxSettings,
        backend: SandboxContainerBackend,
        *,
        artifact_store: LocalArtifactStore | None = None,
        state_store: FileSandboxStateStore | None = None,
        templates: TemplateRegistry | None = None,
    ) -> None:
        self.settings = settings
        self.backend = backend
        self.artifact_store = artifact_store or LocalArtifactStore(
            settings.artifact_root
        )
        self.state_store = state_store or FileSandboxStateStore(settings.state_root)
        self.templates = templates or TemplateRegistry.from_settings(settings)
        self.work_root = settings.work_root.resolve()
        self.work_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.work_root, 0o700)
        self._locks: dict[UUID, threading.RLock] = {}
        self._locks_guard = threading.Lock()
        self._creation_lock = threading.Lock()

    def validate_ready(self) -> None:
        try:
            self.backend.validate_ready()
        except BackendFailure as exc:
            raise self._public_backend_error(exc) from exc

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        with self._creation_lock:
            active_count = sum(
                not record.resources_destroyed
                for record in self.state_store.list()
            )
            if active_count >= self.settings.max_active_sandboxes:
                raise SandboxError(
                    "SANDBOX_CAPACITY_EXHAUSTED",
                    "Sandbox Manager has reached its active capacity",
                    http_status=429,
                )
            return self._create_locked(request)

    def _create_locked(self, request: SandboxCreateRequest) -> SandboxRecord:
        template = self.templates.resolve(request.template, request.operation)
        limits = template.resolve_limits(request.limits)
        try:
            snapshot_path = self.artifact_store.resolve(
                request.snapshot.storage_key,
                expected_sha256=request.snapshot.sha256,
                expected_size=request.snapshot.size_bytes,
            )
        except ArtifactStoreError as exc:
            raise SandboxError(
                "SANDBOX_SNAPSHOT_INVALID",
                "Snapshot Artifact cannot be verified",
            ) from exc

        sandbox_id = uuid4()
        try:
            workspace = self._create_workspace(sandbox_id)
        except OSError as exc:
            raise SandboxError(
                "SANDBOX_WORKSPACE_UNAVAILABLE",
                "Sandbox workspace could not be prepared",
                http_status=503,
            ) from exc
        try:
            extract_snapshot_archive(
                snapshot_path,
                workspace.source,
                ArchiveLimits(
                    max_files=self.settings.max_snapshot_files,
                    max_total_bytes=self.settings.max_snapshot_bytes,
                    max_file_bytes=self.settings.max_snapshot_bytes,
                ),
            )
            self.backend.create(sandbox_id, template, limits, workspace)
        except SandboxError:
            self._remove_workspace(workspace.root)
            raise
        except BackendFailure as exc:
            self._remove_workspace(workspace.root)
            raise self._public_backend_error(exc) from exc
        except Exception:
            self._remove_workspace(workspace.root)
            raise

        now = _utcnow()
        record = SandboxRecord(
            id=sandbox_id,
            task_id=request.task_id,
            template=request.template,
            operation=request.operation,
            snapshot=request.snapshot,
            limits=limits,
            status=SandboxStatus.CREATED,
            created_at=now,
            deadline_at=now + timedelta(seconds=self.settings.created_ttl_seconds),
        )
        try:
            self.state_store.save(record)
        except Exception:
            try:
                self.backend.destroy(sandbox_id)
            finally:
                self._remove_workspace(workspace.root)
            raise
        return record

    def get(self, sandbox_id: UUID) -> SandboxRecord:
        self.state_store.get(sandbox_id)
        with self._lock_for(sandbox_id):
            return self._refresh_locked(self.state_store.get(sandbox_id))

    def start(self, sandbox_id: UUID) -> SandboxRecord:
        self.state_store.get(sandbox_id)
        with self._lock_for(sandbox_id):
            record = self._refresh_locked(self.state_store.get(sandbox_id))
            if record.status is not SandboxStatus.CREATED:
                raise invalid_sandbox_state("Sandbox is not in created state")
            if record.resources_destroyed:
                raise invalid_sandbox_state("Sandbox resources have been destroyed")
            try:
                self.backend.start(sandbox_id)
            except BackendFailure as exc:
                failed = record.model_copy(
                    update={
                        "status": SandboxStatus.FAILED,
                        "failure_code": str(exc),
                        "finished_at": _utcnow(),
                    }
                )
                self.state_store.save(failed)
                self._finalize_locked(failed)
                raise self._public_backend_error(exc) from exc
            now = _utcnow()
            running = record.model_copy(
                update={
                    "status": SandboxStatus.RUNNING,
                    "started_at": now,
                    "deadline_at": now
                    + timedelta(seconds=record.limits.timeout_seconds),
                }
            )
            self.state_store.save(running)
            return running

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        deadline = time.monotonic() + timeout_seconds
        while True:
            record = self.get(sandbox_id)
            if record.status not in ACTIVE_SANDBOX_STATUSES:
                return record
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return record
            time.sleep(min(0.1, remaining))

    def cancel(self, sandbox_id: UUID) -> SandboxRecord:
        self.state_store.get(sandbox_id)
        with self._lock_for(sandbox_id):
            record = self._refresh_locked(self.state_store.get(sandbox_id))
            if record.status not in ACTIVE_SANDBOX_STATUSES:
                return record
            cancelled = record.model_copy(
                update={
                    "status": SandboxStatus.CANCELLED,
                    "failure_code": "SANDBOX_CANCELLED",
                    "finished_at": _utcnow(),
                }
            )
            self.state_store.save(cancelled)
            return self._finalize_locked(cancelled)

    def collect_artifacts(self, sandbox_id: UUID) -> SandboxRecord:
        self.state_store.get(sandbox_id)
        with self._lock_for(sandbox_id):
            record = self._refresh_locked(self.state_store.get(sandbox_id))
            if record.status in ACTIVE_SANDBOX_STATUSES:
                raise invalid_sandbox_state(
                    "Sandbox output can only be collected after execution stops"
                )
            if record.artifacts:
                return record
            updated = self._collect_locked(record)
            self.state_store.save(updated)
            if updated.resources_destroyed:
                self._remove_workspace(self._workspace(sandbox_id).root)
            return updated

    def destroy(self, sandbox_id: UUID) -> SandboxRecord:
        self.state_store.get(sandbox_id)
        with self._lock_for(sandbox_id):
            record = self._refresh_locked(self.state_store.get(sandbox_id))
            if record.status in ACTIVE_SANDBOX_STATUSES:
                record = record.model_copy(
                    update={
                        "status": SandboxStatus.CANCELLED,
                        "failure_code": "SANDBOX_DESTROYED",
                        "finished_at": _utcnow(),
                    }
                )
                self.state_store.save(record)
            if record.resources_destroyed:
                return record
            return self._finalize_locked(record)

    def resolve_artifact(self, sha256: str) -> Path:
        if len(sha256) != 64 or any(
            character not in "0123456789abcdef" for character in sha256
        ):
            raise SandboxError(
                "SANDBOX_ARTIFACT_NOT_FOUND",
                "Sandbox Artifact was not found",
                http_status=404,
            )
        if not any(
            artifact.sha256 == sha256
            for record in self.state_store.list()
            for artifact in record.artifacts
        ):
            raise SandboxError(
                "SANDBOX_ARTIFACT_NOT_FOUND",
                "Sandbox Artifact was not found",
                http_status=404,
            )
        storage_key = f"sha256/{sha256[:2]}/{sha256}"
        try:
            return self.artifact_store.resolve(
                storage_key,
                expected_sha256=sha256,
            )
        except ArtifactStoreError as exc:
            raise SandboxError(
                "SANDBOX_ARTIFACT_NOT_FOUND",
                "Sandbox Artifact was not found",
                http_status=404,
            ) from exc

    def reconcile(self) -> None:
        """Fail closed after restart and remove every labeled orphan resource."""
        try:
            records = self.state_store.list()
        except SandboxError:
            # Corrupt local state must not leave target code running while the
            # operator repairs or restores the state volume.
            try:
                managed_ids = self.backend.managed_sandbox_ids()
                for sandbox_id in managed_ids:
                    self.backend.cancel(sandbox_id)
                    self.backend.destroy(sandbox_id)
            except BackendFailure:
                pass
            raise
        known_ids = {record.id for record in records}
        for record in records:
            with self._lock_for(record.id):
                current = self.state_store.get(record.id)
                if current.status in ACTIVE_SANDBOX_STATUSES:
                    current = current.model_copy(
                        update={
                            "status": SandboxStatus.FAILED,
                            "failure_code": "SANDBOX_MANAGER_RESTARTED",
                            "finished_at": _utcnow(),
                        }
                    )
                    self.state_store.save(current)
                if not current.resources_destroyed:
                    try:
                        self._finalize_locked(current)
                    except SandboxError as exc:
                        LOG.error(
                            "sandbox restart cleanup failed sandbox_id=%s code=%s",
                            current.id,
                            exc.error_code,
                        )
                else:
                    workspace = self._workspace(current.id)
                    if current.artifacts:
                        self._remove_workspace(workspace.root)
                    elif workspace.output.exists():
                        try:
                            recovered = self._collect_locked(current)
                            self.state_store.save(recovered)
                            self._remove_workspace(workspace.root)
                        except SandboxError as exc:
                            LOG.error(
                                "sandbox output recovery failed "
                                "sandbox_id=%s code=%s",
                                current.id,
                                exc.error_code,
                            )
                            if exc.error_code in {
                                "SANDBOX_OUTPUT_INVALID",
                                "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
                            }:
                                self._remove_workspace(workspace.root)

        try:
            managed_ids = self.backend.managed_sandbox_ids()
        except BackendFailure as exc:
            raise self._public_backend_error(exc) from exc
        for orphan_id in managed_ids - known_ids:
            try:
                self.backend.cancel(orphan_id)
                self.backend.destroy(orphan_id)
            except BackendFailure as exc:
                raise self._public_backend_error(exc) from exc
        self._remove_unrecorded_workspaces(known_ids)

    def reap(self) -> None:
        for record in self.state_store.list():
            try:
                with self._lock_for(record.id):
                    self._refresh_locked(self.state_store.get(record.id))
            except SandboxError as exc:
                LOG.error(
                    "sandbox reaper failed sandbox_id=%s code=%s",
                    record.id,
                    exc.error_code,
                )

    def close(self) -> None:
        self.backend.close()

    def _refresh_locked(self, record: SandboxRecord) -> SandboxRecord:
        if record.resources_destroyed:
            return record
        now = _utcnow()
        if record.status is SandboxStatus.CREATED:
            if record.deadline_at <= now:
                expired = record.model_copy(
                    update={
                        "status": SandboxStatus.CANCELLED,
                        "failure_code": "SANDBOX_START_TIMEOUT",
                        "finished_at": now,
                    }
                )
                self.state_store.save(expired)
                return self._finalize_locked(expired)
            return record
        if record.status is not SandboxStatus.RUNNING:
            return self._finalize_locked(record)
        if record.deadline_at <= now:
            timed_out = record.model_copy(
                update={
                    "status": SandboxStatus.TIMED_OUT,
                    "failure_code": "SANDBOX_TIMEOUT",
                    "finished_at": now,
                }
            )
            self.state_store.save(timed_out)
            return self._finalize_locked(timed_out)

        workspace = self._workspace(record.id)
        try:
            usage = measure_writable_tree(
                (workspace.scratch, workspace.output),
                max_entries=self.settings.max_output_files,
            )
        except OSError:
            usage = None
        if usage is not None and (
            usage.bytes > record.limits.disk_bytes
            or usage.files > self.settings.max_output_files
        ):
            exceeded = record.model_copy(
                update={
                    "status": SandboxStatus.RESOURCE_EXCEEDED,
                    "failure_code": "SANDBOX_DISK_LIMIT_EXCEEDED",
                    "finished_at": now,
                }
            )
            self.state_store.save(exceeded)
            return self._finalize_locked(exceeded)

        try:
            state = self.backend.inspect(record.id)
        except BackendFailure as exc:
            raise self._public_backend_error(exc) from exc
        if state.status in {
            BackendContainerStatus.CREATED,
            BackendContainerStatus.RUNNING,
        }:
            return record
        if state.status is BackendContainerStatus.MISSING:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.FAILED,
                    "failure_code": "SANDBOX_CONTAINER_LOST",
                    "finished_at": now,
                }
            )
        elif state.oom_killed:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.RESOURCE_EXCEEDED,
                    "failure_code": "SANDBOX_MEMORY_LIMIT_EXCEEDED",
                    "exit_code": state.exit_code,
                    "finished_at": now,
                }
            )
        elif state.exit_code == 124:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.TIMED_OUT,
                    "failure_code": "SANDBOX_TIMEOUT",
                    "exit_code": state.exit_code,
                    "finished_at": now,
                }
            )
        elif state.exit_code == 153:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.RESOURCE_EXCEEDED,
                    "failure_code": "SANDBOX_FILE_SIZE_LIMIT_EXCEEDED",
                    "exit_code": state.exit_code,
                    "finished_at": now,
                }
            )
        elif state.exit_code == 0:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.SUCCEEDED,
                    "exit_code": 0,
                    "finished_at": now,
                }
            )
        else:
            completed = record.model_copy(
                update={
                    "status": SandboxStatus.FAILED,
                    "failure_code": "SANDBOX_PROCESS_FAILED",
                    "exit_code": state.exit_code,
                    "finished_at": now,
                }
            )
        self.state_store.save(completed)
        return self._finalize_locked(completed)

    def _finalize_locked(self, record: SandboxRecord) -> SandboxRecord:
        if record.resources_destroyed:
            return record
        try:
            self.backend.cancel(record.id)
        except BackendFailure:
            # Force-removal is still attempted below. A failed graceful stop
            # must not turn into a residual workload.
            pass

        try:
            self.backend.destroy(record.id)
        except BackendFailure as exc:
            raise self._public_backend_error(exc) from exc
        record = record.model_copy(update={"resources_destroyed": True})
        self.state_store.save(record)

        collection_error: SandboxError | None = None
        try:
            record = self._collect_locked(record)
            self.state_store.save(record)
        except SandboxError as exc:
            collection_error = exc
            if record.status is SandboxStatus.SUCCEEDED:
                record = record.model_copy(
                    update={
                        "status": SandboxStatus.FAILED,
                        "failure_code": exc.error_code,
                    }
                )
            elif record.failure_code is None:
                record = record.model_copy(update={"failure_code": exc.error_code})
            self.state_store.save(record)

        workspace = self._workspace(record.id)
        if collection_error is None or collection_error.error_code in {
            "SANDBOX_OUTPUT_INVALID",
            "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
        }:
            self._remove_workspace(workspace.root)
        elif collection_error.error_code == "SANDBOX_ARTIFACT_WRITE_FAILED":
            self._remove_workspace(workspace.source)
            self._remove_workspace(workspace.scratch)
        return record

    def _collect_locked(self, record: SandboxRecord) -> SandboxRecord:
        if record.artifacts:
            return record
        workspace = self._workspace(record.id)
        if not workspace.output.exists():
            raise SandboxError(
                "SANDBOX_OUTPUT_INVALID",
                "Sandbox output directory is unavailable",
                http_status=500,
            )
        try:
            self.backend.prepare_collection(record.id, workspace)
        except BackendFailure as exc:
            raise self._public_backend_error(exc) from exc
        temporary_path = self.state_store.temporary_path(
            f"{record.id}-output.tar"
        )
        temporary_path.unlink(missing_ok=True)
        try:
            archive_output_tree(
                workspace.output,
                temporary_path,
                ArchiveLimits(
                    max_files=self.settings.max_output_files,
                    max_total_bytes=record.limits.output_bytes,
                    max_file_bytes=record.limits.output_bytes,
                ),
            )
            max_tar_bytes = (
                record.limits.output_bytes
                + self.settings.max_output_files * 1024
                + 1024 * 1024
            )
            stored = self.artifact_store.put_file(
                temporary_path,
                max_bytes=max_tar_bytes,
            )
        except ArtifactStoreError as exc:
            raise SandboxError(
                "SANDBOX_ARTIFACT_WRITE_FAILED",
                "Sandbox output Artifact could not be stored",
                http_status=503,
            ) from exc
        finally:
            temporary_path.unlink(missing_ok=True)
        artifact = SandboxArtifact(
            storage_key=stored.storage_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type="application/x-tar",
        )
        return record.model_copy(update={"artifacts": [artifact]})

    def _create_workspace(self, sandbox_id: UUID) -> SandboxWorkspace:
        workspace = self._workspace(sandbox_id)
        try:
            workspace.root.mkdir(mode=0o700)
            workspace.scratch.mkdir(mode=0o777)
            workspace.output.mkdir(mode=0o777)
            os.chmod(workspace.scratch, 0o777)
            os.chmod(workspace.output, 0o777)
        except OSError:
            self._remove_workspace(workspace.root)
            raise
        return workspace

    def _workspace(self, sandbox_id: UUID) -> SandboxWorkspace:
        root = self.work_root / str(sandbox_id)
        if root.parent != self.work_root:
            raise ValueError("invalid Sandbox workspace")
        return SandboxWorkspace(
            root=root,
            source=root / "source",
            scratch=root / "scratch",
            output=root / "output",
        )

    def _remove_workspace(self, path: Path) -> None:
        try:
            resolved_parent = path.parent.resolve()
        except OSError:
            return
        if resolved_parent != self.work_root and not resolved_parent.is_relative_to(
            self.work_root
        ):
            raise ValueError("refusing to remove a path outside Sandbox work root")
        if not path.exists() and not path.is_symlink():
            return
        if path.is_symlink():
            path.unlink(missing_ok=True)
            return
        if path.is_file():
            path.unlink(missing_ok=True)
            return
        for directory, directory_names, _file_names in os.walk(
            path,
            topdown=False,
            followlinks=False,
        ):
            directory_path = Path(directory)
            for name in directory_names:
                candidate = directory_path / name
                if not candidate.is_symlink():
                    try:
                        os.chmod(candidate, 0o700)
                    except (FileNotFoundError, PermissionError):
                        pass
            try:
                os.chmod(directory_path, 0o700)
            except (FileNotFoundError, PermissionError):
                pass
        shutil.rmtree(path, ignore_errors=False)

    def _remove_unrecorded_workspaces(self, known_ids: set[UUID]) -> None:
        for path in self.work_root.iterdir():
            try:
                identifier = UUID(path.name)
            except ValueError:
                continue
            if identifier not in known_ids:
                workspace = self._workspace(identifier)
                if workspace.scratch.exists() and workspace.output.exists():
                    try:
                        self.backend.prepare_collection(identifier, workspace)
                    except BackendFailure as exc:
                        LOG.error(
                            "orphan workspace normalization failed "
                            "sandbox_id=%s code=%s",
                            identifier,
                            str(exc),
                        )
                        continue
                try:
                    self._remove_workspace(path)
                except OSError:
                    LOG.error(
                        "orphan workspace removal failed sandbox_id=%s",
                        identifier,
                    )

    def _lock_for(self, sandbox_id: UUID) -> threading.RLock:
        with self._locks_guard:
            lock = self._locks.get(sandbox_id)
            if lock is None:
                lock = threading.RLock()
                self._locks[sandbox_id] = lock
            return lock

    @staticmethod
    def _public_backend_error(exc: BackendFailure) -> SandboxError:
        error_code = str(exc)
        if error_code == "SANDBOX_ROOTLESS_REQUIRED":
            return SandboxError(
                error_code,
                "Sandbox Manager requires a rootless Docker daemon",
                http_status=503,
            )
        if error_code == "SANDBOX_TEMPLATE_UNSAFE":
            return SandboxError(
                error_code,
                "Configured Sandbox template violates the security contract",
                http_status=500,
            )
        if error_code == "SANDBOX_RESOURCE_CONTROLS_UNAVAILABLE":
            return SandboxError(
                error_code,
                "Sandbox daemon lacks required cgroup v2 resource controls",
                http_status=503,
            )
        if error_code == "SANDBOX_COLLECTION_PREPARATION_FAILED":
            return SandboxError(
                error_code,
                "Sandbox output permissions could not be normalized safely",
                http_status=500,
            )
        return SandboxError(
            "SANDBOX_BACKEND_UNAVAILABLE",
            "Sandbox execution backend is unavailable",
            http_status=503,
        )


class SandboxReaper:
    def __init__(self, manager: SandboxManager, interval_seconds: float) -> None:
        self.manager = manager
        self.interval_seconds = interval_seconds
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="cairn-sandbox-reaper",
            daemon=True,
        )

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=max(15.0, self.interval_seconds * 2))

    def _run(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            try:
                self.manager.reap()
            except Exception:
                LOG.exception("sandbox reaper iteration failed")


def _utcnow() -> datetime:
    return datetime.now(UTC)
