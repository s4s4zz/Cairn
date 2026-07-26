from pathlib import Path
from uuid import uuid4

import pytest
from docker.errors import NotFound

from cairn.sandbox.backend import BackendFailure, SandboxWorkspace
from cairn.sandbox.contracts import (
    SandboxLimitsOverride,
    SandboxTemplateName,
)
from cairn.sandbox.docker_backend import RootlessDockerBackend
from cairn.sandbox.templates import TemplateRegistry


class FakeContainers:
    def __init__(self) -> None:
        self.created: list[tuple[str, dict[str, object]]] = []

    def create(self, image: str, **options) -> object:  # noqa: ANN003
        self.created.append((image, options))

        class Container:
            def start(self) -> None:
                return None

            def wait(self, timeout: int) -> dict[str, int]:
                assert timeout == 15
                return {"StatusCode": 0}

            def remove(self, force: bool) -> None:
                assert force is True

        return Container()

    def get(self, name: str) -> object:
        del name
        raise NotFound("not found")


class FakeNetworks:
    def __init__(self) -> None:
        self.created: list[tuple[str, dict[str, object]]] = []

    def create(self, name: str, **options) -> object:  # noqa: ANN003
        self.created.append((name, options))
        return object()


class FakeImages:
    def __init__(self, volumes: dict[str, object] | None = None) -> None:
        self.volumes = volumes

    def get(self, name: str) -> object:
        del name

        class Image:
            attrs: dict[str, object] = {}

        Image.attrs = {"Config": {"Volumes": self.volumes}}

        return Image()


class FakeDockerClient:
    def __init__(
        self,
        *,
        rootless: bool = True,
        image_volumes: dict[str, object] | None = None,
        cgroup_version: str = "2",
    ) -> None:
        self.rootless = rootless
        self.cgroup_version = cgroup_version
        self.containers = FakeContainers()
        self.networks = FakeNetworks()
        self.images = FakeImages(image_volumes)

    def ping(self) -> bool:
        return True

    def info(self) -> dict[str, object]:
        options = ["name=rootless"] if self.rootless else ["name=seccomp"]
        return {
            "SecurityOptions": options,
            "CgroupVersion": self.cgroup_version,
            "MemoryLimit": True,
            "SwapLimit": True,
            "PidsLimit": True,
            "CpuCfsPeriod": True,
            "CpuCfsQuota": True,
        }

    def close(self) -> None:
        return None


def make_workspace(root: Path, sandbox_id) -> SandboxWorkspace:  # noqa: ANN001
    workspace_root = root / str(sandbox_id)
    source = workspace_root / "source"
    scratch = workspace_root / "scratch"
    output = workspace_root / "output"
    for path in (source, scratch, output):
        path.mkdir(parents=True, exist_ok=True)
    return SandboxWorkspace(workspace_root, source, scratch, output)


def test_backend_requires_rootless_daemon(sandbox_settings) -> None:  # noqa: ANN001
    backend = RootlessDockerBackend(
        sandbox_settings,
        client=FakeDockerClient(rootless=False),
    )

    with pytest.raises(BackendFailure, match="SANDBOX_ROOTLESS_REQUIRED"):
        backend.validate_ready()


def test_backend_requires_cgroup_v2_resource_controls(
    sandbox_settings,  # noqa: ANN001
) -> None:
    backend = RootlessDockerBackend(
        sandbox_settings,
        client=FakeDockerClient(cgroup_version="1"),
    )

    with pytest.raises(
        BackendFailure,
        match="SANDBOX_RESOURCE_CONTROLS_UNAVAILABLE",
    ):
        backend.validate_ready()


def test_analysis_container_uses_exact_security_baseline(
    sandbox_settings,  # noqa: ANN001
) -> None:
    client = FakeDockerClient()
    backend = RootlessDockerBackend(sandbox_settings, client=client)
    template = TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.ANALYSIS
    )
    limits = template.resolve_limits(SandboxLimitsOverride())
    sandbox_id = uuid4()
    workspace = make_workspace(sandbox_settings.work_root, sandbox_id)

    backend.create(sandbox_id, template, limits, workspace)

    image, options = client.containers.created[0]
    assert image == sandbox_settings.analysis_image
    assert options["command"] == [
        "/usr/bin/timeout",
        "--signal=TERM",
        "--kill-after=5s",
        f"{limits.timeout_seconds + 2}s",
        "/opt/cairn/bin/run-analysis",
    ]
    assert options["entrypoint"] == []
    assert options["user"] == "65532:65532"
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["security_opt"] == ["no-new-privileges:true"]
    assert options["privileged"] is False
    assert options["ipc_mode"] == "none"
    assert options["cgroupns"] == "private"
    assert options["network_mode"] == "none"
    assert options["pids_limit"] == limits.pids
    assert options["mem_limit"] == limits.memory_bytes
    assert options["memswap_limit"] == limits.memory_bytes
    assert options["nano_cpus"] == limits.cpu_millis * 1_000_000
    assert options["restart_policy"] == {"Name": "no"}
    assert options["healthcheck"] == {"test": ["NONE"]}
    ulimits = {item.name: item for item in options["ulimits"]}
    assert ulimits["fsize"]["Soft"] == limits.disk_bytes
    assert ulimits["fsize"]["Hard"] == limits.disk_bytes
    assert set(options["volumes"]) == {
        str(workspace.source),
        str(workspace.scratch),
        str(workspace.output),
    }
    assert all(
        "/var/run/docker.sock" not in path for path in options["volumes"]
    )
    assert "ports" not in options
    assert "devices" not in options
    assert "pid_mode" not in options


def test_validation_network_is_manager_created_and_internal(
    sandbox_settings,  # noqa: ANN001
) -> None:
    client = FakeDockerClient()
    backend = RootlessDockerBackend(sandbox_settings, client=client)
    template = TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.VALIDATION
    )
    sandbox_id = uuid4()
    workspace = make_workspace(sandbox_settings.work_root, sandbox_id)

    backend.create(
        sandbox_id,
        template,
        template.resolve_limits(SandboxLimitsOverride()),
        workspace,
    )

    network_name, network_options = client.networks.created[0]
    _, container_options = client.containers.created[0]
    assert network_options["internal"] is True
    assert container_options["network"] == network_name
    assert "network_mode" not in container_options


def test_backend_rejects_image_declared_writable_volumes(
    sandbox_settings,  # noqa: ANN001
) -> None:
    client = FakeDockerClient(image_volumes={"/data": {}})
    backend = RootlessDockerBackend(sandbox_settings, client=client)
    template = TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.ANALYSIS
    )
    sandbox_id = uuid4()
    workspace = make_workspace(sandbox_settings.work_root, sandbox_id)

    with pytest.raises(BackendFailure, match="SANDBOX_TEMPLATE_UNSAFE"):
        backend.create(
            sandbox_id,
            template,
            template.resolve_limits(SandboxLimitsOverride()),
            workspace,
        )

    assert client.containers.created == []


def test_collection_helper_has_minimal_namespaced_permissions(
    sandbox_settings,  # noqa: ANN001
) -> None:
    client = FakeDockerClient()
    backend = RootlessDockerBackend(sandbox_settings, client=client)
    sandbox_id = uuid4()
    workspace = make_workspace(sandbox_settings.work_root, sandbox_id)

    backend.prepare_collection(sandbox_id, workspace)

    image, options = client.containers.created[0]
    assert image == sandbox_settings.helper_image
    assert options["user"] == "0:0"
    assert options["read_only"] is True
    assert options["cap_drop"] == ["ALL"]
    assert options["cap_add"] == ["DAC_OVERRIDE", "FOWNER"]
    assert options["network_mode"] == "none"
    assert options["ipc_mode"] == "none"
    assert options["privileged"] is False
    assert set(options["volumes"]) == {
        str(workspace.scratch),
        str(workspace.output),
    }
    assert str(workspace.source) not in options["volumes"]
