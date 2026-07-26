from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import tarfile
from uuid import UUID, uuid4

import pytest

from cairn.sandbox.backend import (
    BackendContainerStatus,
    BackendFailure,
    BackendState,
    SandboxWorkspace,
)
from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxStatus,
    SandboxTemplateName,
)
from cairn.sandbox.errors import SandboxError
from cairn.sandbox.manager import SandboxManager
from cairn.server.artifacts.base import ArtifactIntegrityError


class FakeBackend:
    def __init__(self) -> None:
        self.states: dict[UUID, BackendState] = {}
        self.workspaces: dict[UUID, SandboxWorkspace] = {}
        self.cancelled: list[UUID] = []
        self.destroyed: list[UUID] = []
        self.validated = False
        self.readiness_error: str | None = None

    def validate_ready(self) -> None:
        if self.readiness_error is not None:
            raise BackendFailure(self.readiness_error)
        self.validated = True

    def create(self, sandbox_id, template, limits, workspace) -> None:  # noqa: ANN001
        del template, limits
        self.states[sandbox_id] = BackendState(BackendContainerStatus.CREATED)
        self.workspaces[sandbox_id] = workspace

    def start(self, sandbox_id: UUID) -> None:
        self.states[sandbox_id] = BackendState(BackendContainerStatus.RUNNING)

    def inspect(self, sandbox_id: UUID) -> BackendState:
        return self.states.get(
            sandbox_id,
            BackendState(BackendContainerStatus.MISSING),
        )

    def cancel(self, sandbox_id: UUID) -> None:
        self.cancelled.append(sandbox_id)
        state = self.states.get(sandbox_id)
        if state is not None and state.status is BackendContainerStatus.RUNNING:
            self.states[sandbox_id] = BackendState(
                BackendContainerStatus.EXITED,
                exit_code=137,
            )

    def destroy(self, sandbox_id: UUID) -> None:
        self.destroyed.append(sandbox_id)
        self.states.pop(sandbox_id, None)

    def prepare_collection(
        self,
        sandbox_id: UUID,
        workspace: SandboxWorkspace,
    ) -> None:
        del sandbox_id, workspace

    def managed_sandbox_ids(self) -> set[UUID]:
        return set(self.states)

    def close(self) -> None:
        return None


def make_manager(settings):  # noqa: ANN001, ANN201
    backend = FakeBackend()
    return SandboxManager(settings, backend), backend


def create_request(
    snapshot_artifact,  # noqa: ANN001
    *,
    limits: dict[str, int] | None = None,
) -> SandboxCreateRequest:
    return SandboxCreateRequest(
        template=SandboxTemplateName.ANALYSIS,
        snapshot=snapshot_artifact,
        limits=limits or {},
    )


def test_successful_lifecycle_collects_output_before_cleanup(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))

    assert created.status is SandboxStatus.CREATED
    source = backend.workspaces[created.id].source / "src/main/java/Application.java"
    assert source.is_file()
    assert source.stat().st_mode & 0o222 == 0

    running = manager.start(created.id)
    output = backend.workspaces[created.id].output
    (output / "evidence.json").write_text('{"verified":true}')
    backend.states[created.id] = BackendState(
        BackendContainerStatus.EXITED,
        exit_code=0,
    )

    completed = manager.wait(created.id, timeout_seconds=1)

    assert completed.status is SandboxStatus.SUCCEEDED
    assert completed.resources_destroyed is True
    assert len(completed.artifacts) == 1
    assert created.id in backend.destroyed
    assert not backend.workspaces[created.id].root.exists()
    artifact_path = manager.resolve_artifact(completed.artifacts[0].sha256)
    with tarfile.open(artifact_path, mode="r:") as archive:
        assert archive.extractfile("evidence.json").read() == b'{"verified":true}'


def test_cancel_is_idempotent_and_leaves_no_backend_resource(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))
    manager.start(created.id)

    first = manager.cancel(created.id)
    second = manager.cancel(created.id)

    assert first.status is SandboxStatus.CANCELLED
    assert first.resources_destroyed is True
    assert second == first
    assert backend.destroyed.count(created.id) == 1


def test_manager_enforces_active_capacity(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    limited_settings = sandbox_settings.model_copy(
        update={"max_active_sandboxes": 1}
    )
    manager, _backend = make_manager(limited_settings)
    first = manager.create(create_request(snapshot_artifact))

    with pytest.raises(SandboxError) as captured:
        manager.create(create_request(snapshot_artifact))

    assert captured.value.error_code == "SANDBOX_CAPACITY_EXHAUSTED"
    assert captured.value.http_status == 429

    manager.destroy(first.id)
    second = manager.create(create_request(snapshot_artifact))
    assert second.status is SandboxStatus.CREATED
    manager.destroy(second.id)


def test_deadline_timeout_collects_and_destroys(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))
    running = manager.start(created.id)
    expired = running.model_copy(
        update={"deadline_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    manager.state_store.save(expired)

    completed = manager.get(created.id)

    assert completed.status is SandboxStatus.TIMED_OUT
    assert completed.failure_code == "SANDBOX_TIMEOUT"
    assert completed.resources_destroyed is True
    assert created.id in backend.cancelled
    assert created.id in backend.destroyed


def test_disk_budget_excess_terminates_and_destroys(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(
        create_request(
            snapshot_artifact,
            limits={
                "disk_bytes": 16 * 1024 * 1024,
                "output_bytes": 1024 * 1024,
            },
        )
    )
    manager.start(created.id)
    large_file = backend.workspaces[created.id].scratch / "large.bin"
    with large_file.open("wb") as stream:
        stream.truncate(17 * 1024 * 1024)

    completed = manager.get(created.id)

    assert completed.status is SandboxStatus.RESOURCE_EXCEEDED
    assert completed.failure_code == "SANDBOX_DISK_LIMIT_EXCEEDED"
    assert completed.resources_destroyed is True
    assert created.id in backend.cancelled
    assert created.id in backend.destroyed


def test_oom_exit_is_classified_as_resource_exhaustion(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))
    manager.start(created.id)
    backend.states[created.id] = BackendState(
        BackendContainerStatus.EXITED,
        exit_code=137,
        oom_killed=True,
    )

    completed = manager.get(created.id)

    assert completed.status is SandboxStatus.RESOURCE_EXCEEDED
    assert completed.failure_code == "SANDBOX_MEMORY_LIMIT_EXCEEDED"


def test_invalid_output_fails_closed_and_removes_untrusted_workspace(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))
    manager.start(created.id)
    output = backend.workspaces[created.id].output
    (output / "escape").symlink_to("/etc/passwd")
    backend.states[created.id] = BackendState(
        BackendContainerStatus.EXITED,
        exit_code=0,
    )

    completed = manager.get(created.id)

    assert completed.status is SandboxStatus.FAILED
    assert completed.failure_code == "SANDBOX_OUTPUT_INVALID"
    assert completed.resources_destroyed is True
    assert completed.artifacts == []
    assert not backend.workspaces[created.id].root.exists()


def test_transient_artifact_failure_preserves_stopped_output_for_retry(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manager, backend = make_manager(sandbox_settings)
    created = manager.create(create_request(snapshot_artifact))
    manager.start(created.id)
    output = backend.workspaces[created.id].output
    (output / "evidence.txt").write_text("retry me")
    backend.states[created.id] = BackendState(
        BackendContainerStatus.EXITED,
        exit_code=0,
    )

    def fail_write(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
        del args, kwargs
        raise ArtifactIntegrityError("temporary test failure")

    monkeypatch.setattr(manager.artifact_store, "put_file", fail_write)

    completed = manager.get(created.id)

    assert completed.status is SandboxStatus.FAILED
    assert completed.failure_code == "SANDBOX_ARTIFACT_WRITE_FAILED"
    assert completed.resources_destroyed is True
    assert output.is_dir()
    assert (output / "evidence.txt").read_text() == "retry me"


def test_reconcile_fails_active_records_and_removes_orphans(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    first_manager, first_backend = make_manager(sandbox_settings)
    active = first_manager.create(create_request(snapshot_artifact))
    first_manager.start(active.id)
    orphan_id = uuid4()

    restarted_backend = FakeBackend()
    restarted_backend.states[active.id] = BackendState(
        BackendContainerStatus.RUNNING
    )
    restarted_backend.states[orphan_id] = BackendState(
        BackendContainerStatus.RUNNING
    )
    restarted = SandboxManager(sandbox_settings, restarted_backend)

    restarted.reconcile()

    recovered = restarted.state_store.get(active.id)
    assert recovered.status is SandboxStatus.FAILED
    assert recovered.failure_code == "SANDBOX_MANAGER_RESTARTED"
    assert recovered.resources_destroyed is True
    assert active.id in restarted_backend.destroyed
    assert orphan_id in restarted_backend.destroyed
    assert not first_backend.destroyed


def test_corrupt_state_still_fails_closed_for_managed_resources(
    sandbox_settings,  # noqa: ANN001
) -> None:
    manager, backend = make_manager(sandbox_settings)
    orphan_id = uuid4()
    backend.states[orphan_id] = BackendState(BackendContainerStatus.RUNNING)
    corrupt = manager.state_store.records_root / f"{uuid4()}.json"
    corrupt.write_text("{not-json")

    with pytest.raises(SandboxError) as captured:
        manager.reconcile()

    assert captured.value.error_code == "SANDBOX_STATE_CORRUPT"
    assert orphan_id in backend.cancelled
    assert orphan_id in backend.destroyed


def test_reconcile_resumes_output_collection_after_destroy_crash(
    sandbox_settings,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    first_manager, first_backend = make_manager(sandbox_settings)
    created = first_manager.create(create_request(snapshot_artifact))
    running = first_manager.start(created.id)
    output = first_backend.workspaces[created.id].output
    (output / "evidence.txt").write_text("durable")
    interrupted = running.model_copy(
        update={
            "status": SandboxStatus.SUCCEEDED,
            "finished_at": datetime.now(UTC),
            "exit_code": 0,
            "resources_destroyed": True,
        }
    )
    first_manager.state_store.save(interrupted)
    first_backend.states.pop(created.id)

    restarted, _backend = make_manager(sandbox_settings)
    restarted.reconcile()

    recovered = restarted.state_store.get(created.id)
    assert len(recovered.artifacts) == 1
    assert not first_backend.workspaces[created.id].root.exists()
    assert restarted.resolve_artifact(recovered.artifacts[0].sha256).is_file()
