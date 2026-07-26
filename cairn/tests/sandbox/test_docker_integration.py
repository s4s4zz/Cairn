from __future__ import annotations

from dataclasses import replace
from io import BytesIO
import os
from pathlib import Path
import tarfile
import time

import pytest

from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxStatus,
    SandboxTemplateName,
)
from cairn.sandbox.docker_backend import RootlessDockerBackend
from cairn.sandbox.manager import SandboxManager
from cairn.sandbox.templates import TemplateRegistry
from cairn.server.artifacts.local import LocalArtifactStore


@pytest.mark.docker
@pytest.mark.parametrize(
    "template_name",
    [
        SandboxTemplateName.ANALYSIS,
        SandboxTemplateName.BUILD,
        SandboxTemplateName.VALIDATION,
    ],
)
def test_real_docker_security_lifecycle(
    tmp_path: Path,
    template_name: SandboxTemplateName,
) -> None:
    settings = _docker_settings(tmp_path)
    request = _snapshot_request(settings, tmp_path, template_name)
    backend = RootlessDockerBackend(settings)
    manager = SandboxManager(settings, backend)
    manager.validate_ready()
    created = manager.create(request)
    try:
        manager.start(created.id)
        container = backend._client.containers.get(f"cairn-sandbox-{created.id}")
        container.reload()
        container_config = container.attrs["Config"]
        host_config = container.attrs["HostConfig"]
        assert container_config["User"] == "65532:65532"
        assert container_config["Entrypoint"] == []
        assert container_config["Healthcheck"]["Test"] == ["NONE"]
        assert host_config["ReadonlyRootfs"] is True
        assert host_config["Privileged"] is False
        assert host_config["CapDrop"] == ["ALL"]
        assert host_config["IpcMode"] == "none"
        assert host_config["CgroupnsMode"] == "private"
        assert host_config["PidMode"] == ""
        if template_name is SandboxTemplateName.VALIDATION:
            network_name = f"cairn-sandbox-net-{created.id}"
            assert host_config["NetworkMode"] == network_name
            network = backend._client.networks.get(network_name)
            assert network.attrs["Internal"] is True
        else:
            assert host_config["NetworkMode"] == "none"
        assert host_config["PidsLimit"] == created.limits.pids
        assert host_config["Memory"] == created.limits.memory_bytes
        assert host_config["NanoCpus"] == created.limits.cpu_millis * 1_000_000
        assert "no-new-privileges:true" in host_config["SecurityOpt"]
        mount_sources = {
            mount["Source"] for mount in container.attrs["Mounts"]
        }
        assert mount_sources == {
            str((settings.work_root / str(created.id) / name).resolve())
            for name in ("source", "scratch", "output")
        }
        assert not any("docker.sock" in source for source in mount_sources)
        deadline = time.monotonic() + 20
        completed = manager.get(created.id)
        while (
            completed.status in {SandboxStatus.CREATED, SandboxStatus.RUNNING}
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)
            completed = manager.get(created.id)

        assert completed.status is SandboxStatus.SUCCEEDED
        assert completed.resources_destroyed is True
        assert len(completed.artifacts) == 1
        artifact_path = manager.resolve_artifact(completed.artifacts[0].sha256)
        with tarfile.open(artifact_path, mode="r:") as archive:
            result = archive.extractfile("template-result.json")
            assert result is not None
            assert f'"template":"{template_name.value}"'.encode() in result.read()
        assert created.id not in manager.backend.managed_sandbox_ids()
    finally:
        manager.destroy(created.id)
        manager.close()


@pytest.mark.docker
def test_real_docker_timeout_and_cancel_leave_no_resources(
    tmp_path: Path,
) -> None:
    settings = _docker_settings(tmp_path)
    base_registry = TemplateRegistry.from_settings(settings)
    templates = tuple(
        replace(
            base_registry.get(name),
            command=(
                "/usr/local/bin/python3",
                "-c",
                "import time; time.sleep(30)",
            ),
        )
        if name is SandboxTemplateName.ANALYSIS
        else base_registry.get(name)
        for name in SandboxTemplateName
    )
    backend = RootlessDockerBackend(settings)
    manager = SandboxManager(
        settings,
        backend,
        templates=TemplateRegistry(templates),
    )
    manager.validate_ready()
    timeout_request = _snapshot_request(
        settings,
        tmp_path,
        SandboxTemplateName.ANALYSIS,
        limits={"timeout_seconds": 1},
    )
    timed = manager.create(timeout_request)
    cancelled = None
    try:
        manager.start(timed.id)
        deadline = time.monotonic() + 10
        result = manager.get(timed.id)
        while (
            result.status in {SandboxStatus.CREATED, SandboxStatus.RUNNING}
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)
            result = manager.get(timed.id)
        assert result.status is SandboxStatus.TIMED_OUT
        assert result.resources_destroyed is True
        assert len(result.artifacts) == 1
        assert timed.id not in backend.managed_sandbox_ids()

        cancel_request = _snapshot_request(
            settings,
            tmp_path,
            SandboxTemplateName.ANALYSIS,
        )
        cancelled = manager.create(cancel_request)
        manager.start(cancelled.id)
        cancelled_result = manager.cancel(cancelled.id)
        assert cancelled_result.status is SandboxStatus.CANCELLED
        assert cancelled_result.resources_destroyed is True
        assert len(cancelled_result.artifacts) == 1
        assert cancelled.id not in backend.managed_sandbox_ids()
    finally:
        manager.destroy(timed.id)
        if cancelled is not None:
            manager.destroy(cancelled.id)
        manager.close()


@pytest.mark.docker
def test_real_docker_helper_recovers_mode_zero_output(
    tmp_path: Path,
) -> None:
    settings = _docker_settings(tmp_path)
    base_registry = TemplateRegistry.from_settings(settings)
    locked_command = (
        "/usr/local/bin/python3",
        "-c",
        (
            "from pathlib import Path; import os; "
            "p=Path('/work/output/locked'); p.mkdir(); "
            "f=p/'evidence.txt'; f.write_text('durable'); "
            "os.chmod(f, 0); os.chmod(p, 0)"
        ),
    )
    templates = tuple(
        replace(base_registry.get(name), command=locked_command)
        if name is SandboxTemplateName.ANALYSIS
        else base_registry.get(name)
        for name in SandboxTemplateName
    )
    backend = RootlessDockerBackend(settings)
    manager = SandboxManager(
        settings,
        backend,
        templates=TemplateRegistry(templates),
    )
    manager.validate_ready()
    request = _snapshot_request(
        settings,
        tmp_path,
        SandboxTemplateName.ANALYSIS,
    )
    created = manager.create(request)
    try:
        manager.start(created.id)
        deadline = time.monotonic() + 20
        completed = manager.get(created.id)
        while (
            completed.status in {SandboxStatus.CREATED, SandboxStatus.RUNNING}
            and time.monotonic() < deadline
        ):
            time.sleep(0.1)
            completed = manager.get(created.id)

        assert completed.status is SandboxStatus.SUCCEEDED
        assert completed.resources_destroyed is True
        assert not (settings.work_root / str(created.id)).exists()
        artifact_path = manager.resolve_artifact(completed.artifacts[0].sha256)
        with tarfile.open(artifact_path, mode="r:") as archive:
            evidence = archive.extractfile("locked/evidence.txt")
            assert evidence is not None
            assert evidence.read() == b"durable"
        assert created.id not in backend.managed_sandbox_ids()
    finally:
        manager.destroy(created.id)
        manager.close()


def _docker_settings(tmp_path: Path) -> SandboxSettings:
    docker_host = os.environ.get("TEST_SANDBOX_DOCKER_HOST")
    image = os.environ.get("TEST_SANDBOX_IMAGE")
    if not docker_host or not image:
        pytest.skip(
            "TEST_SANDBOX_DOCKER_HOST and TEST_SANDBOX_IMAGE are not configured"
        )
    token_file = tmp_path / "token"
    token_file.write_text("i" * 48)
    return SandboxSettings(
        docker_host=docker_host,
        require_rootless=os.environ.get("TEST_SANDBOX_REQUIRE_ROOTLESS") == "1",
        auth_token_file=token_file,
        artifact_root=tmp_path / "artifacts",
        state_root=tmp_path / "state",
        work_root=tmp_path / "work",
        analysis_image=image,
        build_image=image,
        validation_image=image,
        helper_image=image,
    )


def _snapshot_request(
    settings: SandboxSettings,
    tmp_path: Path,
    template_name: SandboxTemplateName,
    *,
    limits: dict[str, int] | None = None,
) -> SandboxCreateRequest:
    source_store = LocalArtifactStore(settings.artifact_root)
    snapshot_path = tmp_path / "snapshot.tar"
    source = b"public class Application {}\n"
    with tarfile.open(snapshot_path, mode="w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo("src/main/java/Application.java")
        info.size = len(source)
        info.mode = 0o444
        info.mtime = 0
        archive.addfile(info, BytesIO(source))
    stored = source_store.put_file(snapshot_path)
    return SandboxCreateRequest(
        template=template_name,
        snapshot={
            "storage_key": stored.storage_key,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
        },
        limits=limits or {},
    )
