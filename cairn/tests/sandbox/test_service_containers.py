"""Dependency service containers inside a validation Sandbox (§7.7, §9.3, §9.4).

Subproject three's property is that a create request cannot choose an image, a
command, an environment variable, a mount, a capability, a device, a port or a
network. A second container in the sandbox is exactly the kind of change that
quietly reopens it, so these tests hold the line explicitly.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest
from docker.errors import DockerException, NotFound

from cairn.sandbox.backend import BackendFailure
from cairn.sandbox.contracts import SandboxTemplateName
from cairn.sandbox.docker_backend import RootlessDockerBackend
from cairn.sandbox.services import ServiceCatalogue, ServiceKind
from cairn.sandbox.templates import NetworkPolicy, TemplateRegistry

from .test_docker_backend import (
    FakeDockerClient,
    FakeImages,
    FakeNetworks,
    make_workspace,
)


class RecordingContainers:
    """Records every create, and can be told which one to fail."""

    def __init__(self, fail_on_image: str | None = None) -> None:
        self.created: list[tuple[str, dict[str, object]]] = []
        self.removed: list[str] = []
        self.started: list[str] = []
        self.fail_on_image = fail_on_image
        self._live: dict[str, object] = {}

    def create(self, image: str, **options):  # noqa: ANN003, ANN201
        if self.fail_on_image is not None and image == self.fail_on_image:
            raise DockerException("service image unavailable")
        self.created.append((image, options))
        name = str(options.get("name"))
        parent = self

        class Container:
            labels = dict(options.get("labels") or {})

            def start(self) -> None:
                parent.started.append(name)

            def remove(self, force: bool = False) -> None:
                del force
                parent.removed.append(name)
                parent._live.pop(name, None)

        container = Container()
        self._live[name] = container
        return container

    def get(self, name: str):  # noqa: ANN201
        if name in self._live:
            return self._live[name]
        raise NotFound("not found")

    def list(self, all: bool = False, filters: dict | None = None):  # noqa: A002, ANN201
        del all
        wanted = set((filters or {}).get("label") or [])
        matched = []
        for name, container in self._live.items():
            labels = getattr(container, "labels", {}) or {}
            rendered = {f"{key}={value}" for key, value in labels.items()}
            if wanted.issubset(rendered):
                matched.append(container)
        return matched


class ServiceDockerClient(FakeDockerClient):
    def __init__(self, fail_on_image: str | None = None) -> None:
        super().__init__()
        self.containers = RecordingContainers(fail_on_image)
        self.networks = RecordingNetworks()
        self.images = FakeImages(None)


class RecordingNetworks(FakeNetworks):
    def __init__(self) -> None:
        super().__init__()
        self.removed: list[str] = []
        self._live: dict[str, object] = {}

    def create(self, name: str, **options):  # noqa: ANN003, ANN201
        self.created.append((name, options))
        parent = self

        class Network:
            attrs = {"Labels": dict(options.get("labels") or {})}

            def remove(self) -> None:
                parent.removed.append(name)
                parent._live.pop(name, None)

        network = Network()
        self._live[name] = network
        return network

    def get(self, name: str):  # noqa: ANN201
        if name in self._live:
            return self._live[name]
        raise NotFound("not found")


@pytest.fixture
def backend(sandbox_settings, tmp_path: Path):  # noqa: ANN001, ANN201
    client = ServiceDockerClient()
    return RootlessDockerBackend(sandbox_settings, client=client), client


def validation_template(sandbox_settings):  # noqa: ANN001, ANN201
    return TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.VALIDATION
    )


# --- the catalogue is closed --------------------------------------------------


def test_the_caller_names_a_kind_and_the_platform_supplies_everything_else(
    sandbox_settings,  # noqa: ANN001
) -> None:
    catalogue = ServiceCatalogue.from_settings(sandbox_settings)

    for kind in ServiceKind:
        spec = catalogue.get(kind)
        assert spec.image
        assert spec.port > 0
        # Never root, on every dependency container.
        assert not spec.user.startswith("0:")


def test_the_echo_target_introduces_no_new_image(sandbox_settings) -> None:  # noqa: ANN001
    catalogue = ServiceCatalogue.from_settings(sandbox_settings)

    assert catalogue.get(ServiceKind.ECHO).image == sandbox_settings.validation_image


# --- services join the isolated network under the §9.3 baseline --------------


def test_services_run_under_the_same_container_baseline_as_the_task(
    backend,  # noqa: ANN001
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    runner, client = backend
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)

    runner.create(
        sandbox_id,
        template,
        template.defaults,
        make_workspace(sandbox_settings.work_root, sandbox_id),
        None,
        [ServiceKind.POSTGRES, ServiceKind.ECHO],
    )

    services = [
        options
        for _image, options in client.containers.created
        if (options.get("labels") or {}).get("cairn.sandbox.resource") == "service"
    ]
    assert len(services) == 2
    for options in services:
        assert options["read_only"] is True
        assert options["cap_drop"] == ["ALL"]
        assert options["security_opt"] == ["no-new-privileges:true"]
        assert options["privileged"] is False
        assert options["ipc_mode"] == "none"
        assert options["restart_policy"] == {"Name": "no"}
        assert not str(options["user"]).startswith("0:")
        # Same isolated network as the task container, and nothing else.
        assert options["network"] == f"cairn-sandbox-net-{sandbox_id}"


def test_services_and_the_task_share_one_isolated_internal_network(
    backend,  # noqa: ANN001
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    runner, client = backend
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)
    assert template.network_policy is NetworkPolicy.ISOLATED

    runner.create(
        sandbox_id,
        template,
        template.defaults,
        make_workspace(sandbox_settings.work_root, sandbox_id),
        None,
        [ServiceKind.REDIS],
    )

    name, options = client.networks.created[0]
    assert name == f"cairn-sandbox-net-{sandbox_id}"
    # §9.4: no route to the internet, the control plane, the host or cloud
    # metadata.
    assert options["internal"] is True


def test_a_template_without_an_isolated_network_cannot_start_services(
    backend,  # noqa: ANN001
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    """A service on a shared or absent network would be reachable elsewhere."""

    runner, _client = backend
    sandbox_id = uuid4()
    template = TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.ANALYSIS
    )

    with pytest.raises(BackendFailure) as excinfo:
        runner.create(
            sandbox_id,
            template,
            template.defaults,
            make_workspace(sandbox_settings.work_root, sandbox_id),
            None,
            [ServiceKind.POSTGRES],
        )

    assert "ISOLATED_NETWORK" in str(excinfo.value)


# --- failure rolls the whole group back --------------------------------------


def test_a_service_that_will_not_start_rolls_the_group_back(
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    """A half-built environment would let a probe run against a dependency that
    never came up, and report the result as if it meant something."""

    client = ServiceDockerClient(fail_on_image=sandbox_settings.postgres_image)
    runner = RootlessDockerBackend(sandbox_settings, client=client)
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)

    with pytest.raises(BackendFailure):
        runner.create(
            sandbox_id,
            template,
            template.defaults,
            make_workspace(sandbox_settings.work_root, sandbox_id),
            None,
            [ServiceKind.ECHO, ServiceKind.POSTGRES],
        )

    # The echo service started before postgres failed; it must not survive.
    assert client.containers.removed
    assert client.networks.removed == [f"cairn-sandbox-net-{sandbox_id}"]
    # And no task container was ever created.
    assert not any(
        (options.get("labels") or {}).get("cairn.sandbox.resource") == "container"
        for _image, options in client.containers.created
    )


# --- destroy removes everything ----------------------------------------------


def test_destroy_removes_the_services_the_network_and_the_task(
    backend,  # noqa: ANN001
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    runner, client = backend
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)
    runner.create(
        sandbox_id,
        template,
        template.defaults,
        make_workspace(sandbox_settings.work_root, sandbox_id),
        None,
        [ServiceKind.POSTGRES, ServiceKind.ECHO],
    )

    runner.destroy(sandbox_id)

    assert len(client.containers.removed) == 3  # two services plus the task
    assert client.networks.removed == [f"cairn-sandbox-net-{sandbox_id}"]


def test_services_are_reclaimed_by_label_not_by_memory(
    backend,  # noqa: ANN001
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    """A Manager restart between create and destroy must still clean up."""

    runner, client = backend
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)
    runner.create(
        sandbox_id,
        template,
        template.defaults,
        make_workspace(sandbox_settings.work_root, sandbox_id),
        None,
        [ServiceKind.REDIS],
    )

    # A fresh backend has no memory of what was started.
    reborn = RootlessDockerBackend(sandbox_settings, client=client)
    reborn.destroy(sandbox_id)

    assert any("svc-redis" in name for name in client.containers.removed)


# --- the runner is told where the services are -------------------------------


def test_service_endpoints_are_resolved_for_the_task(
    backend,  # noqa: ANN001
) -> None:
    """The runner must not have to guess a container name."""

    runner, _client = backend
    sandbox_id = uuid4()

    hosts = runner.service_hosts(sandbox_id, [ServiceKind.POSTGRES, ServiceKind.ECHO])

    assert hosts["postgres"] == f"cairn-sandbox-svc-postgres-{sandbox_id}:5432"
    assert hosts["echo"] == f"cairn-sandbox-svc-echo-{sandbox_id}:8081"


# --- declared volumes must be covered ----------------------------------------


class VolumeImages(FakeImages):
    def __init__(self, volumes_by_image: dict[str, dict]) -> None:
        super().__init__(None)
        self.volumes_by_image = volumes_by_image

    def get(self, name: str):  # noqa: ANN201
        declared = self.volumes_by_image.get(name)

        class Image:
            attrs = {"Config": {"Volumes": declared}}

        return Image()


def test_a_declared_volume_covered_by_tmpfs_is_allowed(
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    """Official database images always declare a data volume. Refusing them
    outright would ban every supported dependency; what matters is that nothing
    durable is created, and a tmpfs over the path gives exactly that."""

    client = ServiceDockerClient()
    client.images = VolumeImages(
        {sandbox_settings.postgres_image: {"/var/lib/postgresql/data": {}}}
    )
    runner = RootlessDockerBackend(sandbox_settings, client=client)
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)

    runner.create(
        sandbox_id,
        template,
        template.defaults,
        make_workspace(sandbox_settings.work_root, sandbox_id),
        None,
        [ServiceKind.POSTGRES],
    )

    assert any("svc-postgres" in str(o.get("name")) for _i, o in client.containers.created)


def test_a_declared_volume_the_spec_does_not_cover_is_refused(
    sandbox_settings,  # noqa: ANN001
    tmp_path: Path,
) -> None:
    """An uncovered volume becomes an anonymous Docker volume outside the
    Manager's lifecycle, and real data would outlive the sandbox."""

    client = ServiceDockerClient()
    client.images = VolumeImages(
        {sandbox_settings.postgres_image: {"/somewhere/unexpected": {}}}
    )
    runner = RootlessDockerBackend(sandbox_settings, client=client)
    sandbox_id = uuid4()
    template = validation_template(sandbox_settings)

    with pytest.raises(BackendFailure) as excinfo:
        runner.create(
            sandbox_id,
            template,
            template.defaults,
            make_workspace(sandbox_settings.work_root, sandbox_id),
            None,
            [ServiceKind.POSTGRES],
        )

    assert "VOLUME_UNCOVERED" in str(excinfo.value)


def test_every_catalogued_service_covers_the_volumes_its_image_declares(
    sandbox_settings,  # noqa: ANN001
) -> None:
    """A pin on the specs themselves, so a future image bump that adds a volume
    fails here rather than in a deployment."""

    catalogue = ServiceCatalogue.from_settings(sandbox_settings)
    known_declared = {
        ServiceKind.POSTGRES: {"/var/lib/postgresql/data"},
        ServiceKind.MYSQL: {"/var/lib/mysql"},
        ServiceKind.REDIS: {"/data"},
        ServiceKind.ECHO: set(),
    }

    for kind, declared in known_declared.items():
        assert declared <= set(catalogue.get(kind).tmpfs), kind
