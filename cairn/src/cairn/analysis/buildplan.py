"""Derive the runtime environment an application needs (§7.7).

§7.7 starts "the permitted temporary PostgreSQL, MySQL, Redis or HTTP echo
services, per the build plan". This module is where that plan comes from: it
reads the application's own Spring configuration and reports which dependency
services the platform should start and which port the application will listen
on.

Two boundaries are deliberate.

**Only the application's own configuration is read.** A repository may well ship
a ``docker-compose.yml`` describing its dependencies, and parsing it would be
convenient — but it would also let the repository decide which containers the
platform runs. The service set stays closed and derived from configuration the
application itself consumes.

**Nothing here is trusted.** These files are repository-controlled. YAML is
parsed with ``safe_load`` under file-count and size bounds, an unparseable file
contributes nothing rather than failing the stage, and the only outputs are a
member of the closed service set and an integer port.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

import yaml

DEFAULT_APP_PORT = 8080

MAX_CONFIG_FILES = 32
MAX_CONFIG_BYTES = 512 * 1024

_CONFIG_NAMES = re.compile(
    r"^application(?:-[A-Za-z0-9_.-]{1,64})?\.(?:ya?ml|properties)$"
)
# Only where Spring itself looks. A stray `application.yml` under test
# fixtures or a vendored sample is not the deployed configuration, and reading
# it would start services the application never asked for.
_CONFIG_PARENTS = ("src/main/resources", "resources", "config")


def _is_config_location(parent: str) -> bool:
    """True for a module root or a Spring configuration directory.

    An explicit membership test rather than `endswith`: the empty-string case
    that would allow a module root makes `endswith` true for every path, which
    silently disables the filter.
    """

    if parent in {"", "."}:
        return True
    return any(
        parent == marker or parent.endswith(f"/{marker}")
        for marker in _CONFIG_PARENTS
    )

# JDBC sub-protocol -> dependency service. Closed on purpose: an unrecognised
# datasource yields no service, which downgrades verification to inconclusive
# rather than starting something nobody chose.
_JDBC_SERVICES = {
    "postgresql": "postgres",
    "postgres": "postgres",
    "mysql": "mysql",
    "mariadb": "mysql",
}

_DATASOURCE_KEYS = (
    ("spring", "datasource", "url"),
    ("spring", "r2dbc", "url"),
)
_REDIS_KEYS = (
    ("spring", "data", "redis", "host"),
    ("spring", "redis", "host"),
)
_PORT_KEYS = (("server", "port"),)


@dataclass(frozen=True, slots=True)
class BuildPlan:
    """What the dynamic verifier needs to stand the application up."""

    services: tuple[str, ...] = ()
    app_port: int = DEFAULT_APP_PORT
    config_paths: tuple[str, ...] = ()

    def as_payload(self) -> dict[str, object]:
        return {
            "services": list(self.services),
            "app_port": self.app_port,
            "config_paths": list(self.config_paths),
        }


def detect_build_plan(root: Path) -> BuildPlan:
    """Read the application's Spring configuration and derive its environment."""

    services: set[str] = set()
    port = DEFAULT_APP_PORT
    read: list[str] = []

    for path in _config_files(root):
        try:
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        values = (
            _flatten_yaml(raw)
            if path.suffix in {".yml", ".yaml"}
            else _flatten_properties(raw)
        )
        if not values:
            continue
        read.append(path.relative_to(root).as_posix())
        for keys in _DATASOURCE_KEYS:
            service = _jdbc_service(values.get(keys))
            if service is not None:
                services.add(service)
        if any(values.get(keys) for keys in _REDIS_KEYS):
            services.add("redis")
        for keys in _PORT_KEYS:
            candidate = _port(values.get(keys))
            if candidate is not None:
                port = candidate

    return BuildPlan(
        services=tuple(sorted(services)),
        app_port=port,
        config_paths=tuple(sorted(read)),
    )


def _config_files(root: Path) -> list[Path]:
    found: list[Path] = []
    for path in sorted(root.rglob("application*")):
        if len(found) >= MAX_CONFIG_FILES:
            break
        if path.is_symlink() or not path.is_file():
            continue
        if _CONFIG_NAMES.fullmatch(path.name) is None:
            continue
        parent = path.parent.relative_to(root).as_posix()
        if not _is_config_location(parent):
            continue
        try:
            if path.stat().st_size > MAX_CONFIG_BYTES:
                continue
        except OSError:
            continue
        found.append(path)
    return found


def _flatten_yaml(raw: str) -> dict[tuple[str, ...], object]:
    """Flatten a Spring YAML document into dotted key tuples.

    `safe_load_all` because a Spring config may carry several profile documents
    separated by `---`. A malformed document contributes nothing: the detector
    degrades to fewer services, and fewer services degrades to inconclusive,
    which is the correct direction to fail in.
    """

    flattened: dict[tuple[str, ...], object] = {}
    try:
        documents = list(yaml.safe_load_all(raw))
    except yaml.YAMLError:
        return {}
    for document in documents:
        if isinstance(document, dict):
            _walk(document, (), flattened)
    return flattened


def _walk(
    node: dict[object, object],
    prefix: tuple[str, ...],
    into: dict[tuple[str, ...], object],
    depth: int = 0,
) -> None:
    if depth > 16:
        return
    for key, value in node.items():
        path = (*prefix, str(key))
        if isinstance(value, dict):
            _walk(value, path, into, depth + 1)
        else:
            into[path] = value
            # Spring accepts `spring.datasource.url: ...` as a flat key too, so
            # a dotted key is expanded into the same shape rather than missed.
            if "." in str(key):
                into[(*prefix, *str(key).split("."))] = value


def _flatten_properties(raw: str) -> dict[tuple[str, ...], object]:
    flattened: dict[tuple[str, ...], object] = {}
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        key, separator, value = stripped.partition("=")
        if not separator:
            continue
        flattened[tuple(key.strip().split("."))] = value.strip()
    return flattened


def _jdbc_service(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    rendered = value.strip().lower()
    for prefix in ("jdbc:", "r2dbc:"):
        if rendered.startswith(prefix):
            sub_protocol = rendered[len(prefix) :].split(":", 1)[0]
            return _JDBC_SERVICES.get(sub_protocol)
    return None


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 1 <= value <= 65535 else None
    if isinstance(value, str):
        # `server.port: ${PORT:8080}` is common; take the default half.
        candidate = value.strip()
        if candidate.startswith("${") and ":" in candidate:
            candidate = candidate.rstrip("}").split(":", 1)[1]
        if candidate.isdigit():
            number = int(candidate)
            return number if 1 <= number <= 65535 else None
    return None
