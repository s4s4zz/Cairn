from datetime import UTC, datetime, timedelta
import stat
from uuid import uuid4

from cairn.sandbox.contracts import (
    SandboxLimits,
    SandboxRecord,
    SandboxStatus,
    SandboxTemplateName,
    SnapshotArtifact,
)
from cairn.sandbox.state import FileSandboxStateStore


def test_file_state_store_round_trips_and_replaces_atomically(tmp_path) -> None:  # noqa: ANN001
    store = FileSandboxStateStore(tmp_path / "state")
    now = datetime.now(UTC)
    digest = "a" * 64
    record = SandboxRecord(
        id=uuid4(),
        template=SandboxTemplateName.ANALYSIS,
        snapshot=SnapshotArtifact(
            storage_key=f"sha256/aa/{digest}",
            sha256=digest,
            size_bytes=1024,
        ),
        limits=SandboxLimits(
            cpu_millis=1000,
            memory_bytes=512 * 1024 * 1024,
            pids=128,
            disk_bytes=1024 * 1024 * 1024,
            output_bytes=256 * 1024 * 1024,
            tmpfs_bytes=64 * 1024 * 1024,
            timeout_seconds=60,
        ),
        status=SandboxStatus.CREATED,
        created_at=now,
        deadline_at=now + timedelta(seconds=60),
    )

    store.save(record)
    running = record.model_copy(update={"status": SandboxStatus.RUNNING})
    store.save(running)

    assert store.get(record.id) == running
    assert store.list() == [running]
    assert not list(store.temporary_root.iterdir())
    assert stat.S_IMODE(store.root.stat().st_mode) == 0o700
    assert (
        stat.S_IMODE(
            (store.records_root / f"{record.id}.json").stat().st_mode
        )
        == 0o600
    )
