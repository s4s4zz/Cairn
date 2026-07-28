"""The dependency services a validation Sandbox may start (§7.7, §9.4).

§7.7 permits "temporary PostgreSQL, MySQL, Redis or HTTP echo services, per the
build plan". This module is that closed set, and it is closed the same way the
template registry is closed: a caller names a :class:`ServiceKind`, never an
image, a command, a port or an environment mapping. Subproject three's property
— the request schema cannot choose what runs — has to survive the arrival of a
second container in the sandbox.

Every service runs under the §9.3 baseline: non-root, read-only root
filesystem, ``cap_drop: ALL``, no-new-privileges, no privileged mode, bounded
CPU, memory and PIDs. The database images need writable state directories, and
they get tmpfs rather than a relaxed rootfs — the environment is single-use and
destroyed with the sandbox, so durable storage would be a liability rather than
a feature.

The credentials below are fixed and deliberately not secret. The network is
``internal: true``, nothing outside the sandbox can reach these services, and
the whole group is destroyed when the task finishes. A generated password would
add a moving part without adding a boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.errors import SandboxError

# Fixed throwaway credentials; see the module docstring.
SERVICE_USER = "cairn"
SERVICE_PASSWORD = "cairn"
SERVICE_DATABASE = "cairn"

ECHO_PORT = 8081


class ServiceKind(StrEnum):
    POSTGRES = "postgres"
    MYSQL = "mysql"
    REDIS = "redis"
    ECHO = "echo"


@dataclass(frozen=True, slots=True)
class ServiceSpec:
    """One dependency container, fully determined by its kind."""

    kind: ServiceKind
    image: str
    port: int
    user: str
    environment: Mapping[str, str] = field(default_factory=dict)
    command: tuple[str, ...] = ()
    tmpfs: Mapping[str, str] = field(default_factory=dict)
    memory_bytes: int = 512 * 1024 * 1024
    cpu_millis: int = 1000
    pids: int = 128


class ServiceCatalogue:
    """The server-fixed mapping from kind to container specification."""

    def __init__(self, specs: tuple[ServiceSpec, ...]) -> None:
        self._specs = {spec.kind: spec for spec in specs}
        if set(self._specs) != set(ServiceKind):
            raise ValueError("all supported dependency services must be registered")

    @property
    def kinds(self) -> frozenset[ServiceKind]:
        return frozenset(self._specs)

    def get(self, kind: ServiceKind) -> ServiceSpec:
        try:
            return self._specs[kind]
        except KeyError as exc:
            raise SandboxError(
                "SANDBOX_SERVICE_UNKNOWN",
                "Dependency service kind is not registered",
            ) from exc

    @classmethod
    def from_settings(cls, settings: SandboxSettings) -> "ServiceCatalogue":
        return cls(
            (
                ServiceSpec(
                    kind=ServiceKind.POSTGRES,
                    image=settings.postgres_image,
                    port=5432,
                    # The official image's own unprivileged user; PGDATA lives
                    # on tmpfs so the root filesystem stays read-only.
                    user="70:70",
                    environment={
                        "POSTGRES_USER": SERVICE_USER,
                        "POSTGRES_PASSWORD": SERVICE_PASSWORD,
                        "POSTGRES_DB": SERVICE_DATABASE,
                        "PGDATA": "/var/lib/postgresql/data/pgdata",
                    },
                    tmpfs={
                        "/var/lib/postgresql/data": "rw,nosuid,nodev,size=536870912",
                        "/var/run/postgresql": "rw,nosuid,nodev,size=16777216",
                        "/tmp": "rw,noexec,nosuid,nodev,size=67108864",
                    },
                    memory_bytes=512 * 1024 * 1024,
                ),
                ServiceSpec(
                    kind=ServiceKind.MYSQL,
                    image=settings.mysql_image,
                    port=3306,
                    user="999:999",
                    environment={
                        "MYSQL_USER": SERVICE_USER,
                        "MYSQL_PASSWORD": SERVICE_PASSWORD,
                        "MYSQL_DATABASE": SERVICE_DATABASE,
                        "MYSQL_RANDOM_ROOT_PASSWORD": "yes",
                    },
                    tmpfs={
                        "/var/lib/mysql": "rw,nosuid,nodev,size=1073741824",
                        "/var/run/mysqld": "rw,nosuid,nodev,size=16777216",
                        "/tmp": "rw,noexec,nosuid,nodev,size=67108864",
                    },
                    memory_bytes=1024 * 1024 * 1024,
                ),
                ServiceSpec(
                    kind=ServiceKind.REDIS,
                    image=settings.redis_image,
                    port=6379,
                    user="999:999",
                    # No persistence: `--save ''` keeps it from trying to write
                    # an RDB snapshot onto a read-only filesystem.
                    command=("redis-server", "--save", "", "--appendonly", "no"),
                    tmpfs={"/data": "rw,nosuid,nodev,size=134217728"},
                    memory_bytes=256 * 1024 * 1024,
                ),
                ServiceSpec(
                    kind=ServiceKind.ECHO,
                    # The validation image itself, so the out-of-band target
                    # introduces no image the platform does not already ship.
                    image=settings.validation_image,
                    port=ECHO_PORT,
                    user="65532:65532",
                    command=("/opt/cairn/bin/run-echo",),
                    tmpfs={"/tmp": "rw,noexec,nosuid,nodev,size=16777216"},
                    memory_bytes=128 * 1024 * 1024,
                    pids=32,
                ),
            )
        )
