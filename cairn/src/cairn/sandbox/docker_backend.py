from __future__ import annotations

from pathlib import Path
import re
from uuid import UUID

import docker
from docker.errors import DockerException, NotFound
from docker.types import Ulimit
from requests.exceptions import RequestException

from cairn.sandbox.backend import (
    BackendContainerStatus,
    BackendFailure,
    BackendState,
    SandboxWorkspace,
)
from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.contracts import SandboxLimits
from cairn.sandbox.templates import NetworkPolicy, SandboxTemplate


_MANAGED_LABEL = "cairn.sandbox.managed"
_ID_LABEL = "cairn.sandbox.id"
_TEMPLATE_LABEL = "cairn.sandbox.template"
_RESOURCE_LABEL = "cairn.sandbox.resource"
_NAME_PREFIX = "cairn-sandbox-"
_NETWORK_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class RootlessDockerBackend:
    """Docker implementation whose daemon must itself run rootless."""

    def __init__(
        self,
        settings: SandboxSettings,
        *,
        client=None,  # noqa: ANN001
    ) -> None:
        self.settings = settings
        self._work_root = settings.work_root.resolve()
        self._client = client or docker.DockerClient(
            base_url=settings.docker_host,
            timeout=10,
        )

    def validate_ready(self) -> None:
        try:
            self._client.ping()
            information = self._client.info()
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        security_options = [
            str(option).lower()
            for option in information.get("SecurityOptions", [])
        ]
        if self.settings.require_rootless and not any(
            "rootless" in option for option in security_options
        ):
            raise BackendFailure("SANDBOX_ROOTLESS_REQUIRED")
        if self.settings.require_rootless and (
            str(information.get("CgroupVersion")) != "2"
            or information.get("MemoryLimit") is not True
            or information.get("SwapLimit") is not True
            or information.get("PidsLimit") is not True
            or information.get("CpuCfsPeriod") is not True
            or information.get("CpuCfsQuota") is not True
        ):
            raise BackendFailure("SANDBOX_RESOURCE_CONTROLS_UNAVAILABLE")

    def create(
        self,
        sandbox_id: UUID,
        template: SandboxTemplate,
        limits: SandboxLimits,
        workspace: SandboxWorkspace,
    ) -> None:
        self._validate_workspace(workspace)
        self._validate_template_image(template.image)
        labels = self._labels(sandbox_id, template)
        network_name: str | None = None
        dynamic_network = False
        if template.network_policy is NetworkPolicy.ISOLATED:
            network_name = self._network_name(sandbox_id)
            dynamic_network = True
            try:
                self._client.networks.create(
                    network_name,
                    driver="bridge",
                    internal=True,
                    check_duplicate=True,
                    labels={**labels, _RESOURCE_LABEL: "network"},
                )
            except DockerException as exc:
                raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        elif template.network_policy is NetworkPolicy.FIXED:
            network_name = template.network_name
            if network_name is None or _NETWORK_NAME.fullmatch(network_name) is None:
                raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")

        create_options: dict[str, object] = {
            "name": self._container_name(sandbox_id),
            "entrypoint": [],
            "command": [
                "/usr/bin/timeout",
                "--signal=TERM",
                "--kill-after=5s",
                f"{limits.timeout_seconds + 2}s",
                *template.command,
            ],
            "user": template.user,
            "working_dir": "/work/source",
            "read_only": True,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "privileged": False,
            "ipc_mode": "none",
            "cgroupns": "private",
            "pids_limit": limits.pids,
            "mem_limit": limits.memory_bytes,
            "memswap_limit": limits.memory_bytes,
            "nano_cpus": limits.cpu_millis * 1_000_000,
            "init": True,
            "stdin_open": False,
            "tty": False,
            "restart_policy": {"Name": "no"},
            "healthcheck": {"test": ["NONE"]},
            "tmpfs": {
                "/tmp": (
                    f"rw,noexec,nosuid,nodev,size={limits.tmpfs_bytes},mode=1777"
                )
            },
            "volumes": {
                str(workspace.source): {"bind": "/work/source", "mode": "ro"},
                str(workspace.scratch): {"bind": "/work/scratch", "mode": "rw"},
                str(workspace.output): {"bind": "/work/output", "mode": "rw"},
            },
            "environment": {"CAIRN_SANDBOX_ID": str(sandbox_id)},
            "labels": {**labels, _RESOURCE_LABEL: "container"},
            "ulimits": [
                Ulimit(name="nofile", soft=1024, hard=1024),
                Ulimit(name="core", soft=0, hard=0),
                Ulimit(
                    name="fsize",
                    soft=limits.disk_bytes,
                    hard=limits.disk_bytes,
                ),
            ],
        }
        if network_name is None:
            create_options["network_mode"] = "none"
        else:
            create_options["network"] = network_name

        try:
            self._client.containers.create(template.image, **create_options)
        except DockerException as exc:
            if dynamic_network:
                self._remove_network(sandbox_id)
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc

    def start(self, sandbox_id: UUID) -> None:
        container = self._require_container(sandbox_id)
        try:
            container.start()
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc

    def inspect(self, sandbox_id: UUID) -> BackendState:
        container = self._get_container(sandbox_id)
        if container is None:
            return BackendState(BackendContainerStatus.MISSING)
        try:
            container.reload()
        except NotFound:
            return BackendState(BackendContainerStatus.MISSING)
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        state = container.attrs.get("State") or {}
        status = str(state.get("Status") or "")
        if status == "running":
            return BackendState(BackendContainerStatus.RUNNING)
        if status in {"created", "restarting", "paused"}:
            return BackendState(BackendContainerStatus.CREATED)
        exit_code = state.get("ExitCode")
        return BackendState(
            BackendContainerStatus.EXITED,
            exit_code=int(exit_code) if exit_code is not None else None,
            oom_killed=bool(state.get("OOMKilled", False)),
        )

    def cancel(self, sandbox_id: UUID) -> None:
        container = self._get_container(sandbox_id)
        if container is None:
            return
        try:
            container.reload()
            if (container.attrs.get("State") or {}).get("Running"):
                try:
                    container.stop(timeout=1)
                except DockerException:
                    container.kill()
        except NotFound:
            return
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc

    def destroy(self, sandbox_id: UUID) -> None:
        self._remove_helper(sandbox_id)
        container = self._get_container(sandbox_id)
        if container is not None:
            try:
                container.remove(force=True)
            except NotFound:
                pass
            except DockerException as exc:
                raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        self._remove_network(sandbox_id)

    def prepare_collection(
        self,
        sandbox_id: UUID,
        workspace: SandboxWorkspace,
    ) -> None:
        self._validate_workspace(workspace)
        self._remove_helper(sandbox_id)
        self._validate_template_image(self.settings.helper_image)
        labels = {
            _MANAGED_LABEL: "true",
            _ID_LABEL: str(sandbox_id),
            _TEMPLATE_LABEL: "manager-helper",
            _RESOURCE_LABEL: "helper",
        }
        helper = None
        failure: Exception | None = None
        result: dict[str, object] | None = None
        try:
            helper = self._client.containers.create(
                self.settings.helper_image,
                name=self._helper_name(sandbox_id),
                entrypoint=[],
                command=[
                    "/usr/bin/timeout",
                    "--signal=TERM",
                    "--kill-after=2s",
                    "10s",
                    "/opt/cairn/bin/normalize-workspace-permissions",
                ],
                user="0:0",
                working_dir="/work",
                read_only=True,
                cap_drop=["ALL"],
                cap_add=["DAC_OVERRIDE", "FOWNER"],
                security_opt=["no-new-privileges:true"],
                privileged=False,
                ipc_mode="none",
                cgroupns="private",
                network_mode="none",
                pids_limit=32,
                mem_limit=64 * 1024 * 1024,
                memswap_limit=64 * 1024 * 1024,
                nano_cpus=250 * 1_000_000,
                init=True,
                stdin_open=False,
                tty=False,
                restart_policy={"Name": "no"},
                healthcheck={"test": ["NONE"]},
                tmpfs={
                    "/tmp": "rw,noexec,nosuid,nodev,size=1048576,mode=1777"
                },
                volumes={
                    str(workspace.scratch): {
                        "bind": "/work/scratch",
                        "mode": "rw",
                    },
                    str(workspace.output): {
                        "bind": "/work/output",
                        "mode": "rw",
                    },
                },
                labels=labels,
                ulimits=[
                    Ulimit(name="nofile", soft=256, hard=256),
                    Ulimit(name="core", soft=0, hard=0),
                ],
            )
            helper.start()
            result = helper.wait(timeout=15)
        except (DockerException, RequestException, TypeError, ValueError) as exc:
            failure = exc
        finally:
            if helper is not None:
                try:
                    helper.remove(force=True)
                except (DockerException, RequestException) as exc:
                    failure = failure or exc
        if failure is not None:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from failure
        if result is None or int(result.get("StatusCode", -1)) != 0:
            raise BackendFailure("SANDBOX_COLLECTION_PREPARATION_FAILED")

    def managed_sandbox_ids(self) -> set[UUID]:
        identifiers: set[UUID] = set()
        try:
            resources = self._client.containers.list(
                all=True,
                filters={"label": f"{_MANAGED_LABEL}=true"},
            )
            resources += self._client.networks.list(
                filters={"label": f"{_MANAGED_LABEL}=true"},
            )
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        for resource in resources:
            labels = getattr(resource, "labels", None)
            if labels is None:
                labels = (getattr(resource, "attrs", {}) or {}).get("Labels", {})
            value = (labels or {}).get(_ID_LABEL)
            try:
                identifiers.add(UUID(str(value)))
            except (TypeError, ValueError):
                continue
        return identifiers

    def close(self) -> None:
        self._client.close()

    def _validate_workspace(self, workspace: SandboxWorkspace) -> None:
        for path in (
            workspace.root,
            workspace.source,
            workspace.scratch,
            workspace.output,
        ):
            resolved = path.resolve()
            if not resolved.is_relative_to(self._work_root):
                raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")
        if {
            workspace.source.parent,
            workspace.scratch.parent,
            workspace.output.parent,
        } != {workspace.root}:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")

    def _validate_template_image(self, image_name: str) -> None:
        try:
            image = self._client.images.get(image_name)
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        config = (getattr(image, "attrs", {}) or {}).get("Config", {}) or {}
        if config.get("Volumes"):
            raise BackendFailure("SANDBOX_TEMPLATE_UNSAFE")

    def _get_container(self, sandbox_id: UUID):  # noqa: ANN202
        try:
            container = self._client.containers.get(
                self._container_name(sandbox_id)
            )
        except NotFound:
            return None
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        labels = getattr(container, "labels", None)
        if labels is None:
            labels = (
                (getattr(container, "attrs", {}) or {}).get("Config", {})
                or {}
            ).get("Labels", {})
        if (
            (labels or {}).get(_MANAGED_LABEL) != "true"
            or (labels or {}).get(_ID_LABEL) != str(sandbox_id)
        ):
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")
        return container

    def _remove_helper(self, sandbox_id: UUID) -> None:
        try:
            helper = self._client.containers.get(self._helper_name(sandbox_id))
        except NotFound:
            return
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        labels = getattr(helper, "labels", None)
        if labels is None:
            labels = (
                (getattr(helper, "attrs", {}) or {}).get("Config", {})
                or {}
            ).get("Labels", {})
        if (
            (labels or {}).get(_MANAGED_LABEL) != "true"
            or (labels or {}).get(_ID_LABEL) != str(sandbox_id)
            or (labels or {}).get(_RESOURCE_LABEL) != "helper"
        ):
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")
        try:
            helper.remove(force=True)
        except NotFound:
            return
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc

    def _require_container(self, sandbox_id: UUID):  # noqa: ANN202
        container = self._get_container(sandbox_id)
        if container is None:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")
        return container

    def _remove_network(self, sandbox_id: UUID) -> None:
        try:
            network = self._client.networks.get(self._network_name(sandbox_id))
        except NotFound:
            return
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc
        labels = getattr(network, "attrs", {}).get("Labels", {}) or {}
        if (
            labels.get(_MANAGED_LABEL) != "true"
            or labels.get(_ID_LABEL) != str(sandbox_id)
        ):
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE")
        try:
            network.remove()
        except NotFound:
            return
        except DockerException as exc:
            raise BackendFailure("SANDBOX_BACKEND_UNAVAILABLE") from exc

    @staticmethod
    def _labels(
        sandbox_id: UUID,
        template: SandboxTemplate,
    ) -> dict[str, str]:
        return {
            _MANAGED_LABEL: "true",
            _ID_LABEL: str(sandbox_id),
            _TEMPLATE_LABEL: template.name.value,
        }

    @staticmethod
    def _container_name(sandbox_id: UUID) -> str:
        return f"{_NAME_PREFIX}{sandbox_id}"

    @staticmethod
    def _network_name(sandbox_id: UUID) -> str:
        return f"{_NAME_PREFIX}net-{sandbox_id}"

    @staticmethod
    def _helper_name(sandbox_id: UUID) -> str:
        return f"{_NAME_PREFIX}helper-{sandbox_id}"
