from __future__ import annotations

from io import BytesIO
from pathlib import Path
import tarfile

import pytest

from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.contracts import SnapshotArtifact
from cairn.server.artifacts.local import LocalArtifactStore


@pytest.fixture
def sandbox_settings(tmp_path: Path) -> SandboxSettings:
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("t" * 48)
    return SandboxSettings(
        docker_host="unix:///test/rootless-docker.sock",
        require_rootless=True,
        auth_token_file=token_file,
        artifact_root=tmp_path / "artifacts",
        state_root=tmp_path / "state",
        work_root=tmp_path / "work",
        reap_interval_seconds=60,
    )


@pytest.fixture
def snapshot_artifact(
    sandbox_settings: SandboxSettings,
) -> SnapshotArtifact:
    archive_path = sandbox_settings.state_root.parent / "snapshot.tar"
    payload = b"public class Application {}\n"
    with tarfile.open(archive_path, mode="w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo("src/main/java/Application.java")
        info.size = len(payload)
        info.mode = 0o444
        info.mtime = 0
        archive.addfile(info, BytesIO(payload))
    stored = LocalArtifactStore(sandbox_settings.artifact_root).put_file(archive_path)
    return SnapshotArtifact(
        storage_key=stored.storage_key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
    )
