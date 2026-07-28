"""Bring the dependency services and the target application up (§7.7).

Everything here fails in one direction. A service that never became ready, an
application that would not start, a readiness probe that timed out — each is
reported as a reason the run could not verify anything, never as evidence that
a weakness is absent. §7.7 is explicit about this and it is the whole reason
this module returns reason codes rather than booleans.

The application runs as a child process of the runner rather than in its own
container. It needs no image the platform would otherwise build, its stdout and
stderr are captured directly as §7.7's required log evidence, and "the sandbox
is destroyed" already means "the application is gone" without a second
lifecycle to coordinate.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import subprocess
import time
import urllib.error
import urllib.request

from cairn.dynamic.contracts import (
    REASON_APP_NOT_READY,
    REASON_APP_START_FAILED,
    REASON_BUILD_ARTIFACT_MISSING,
    REASON_SERVICE_UNAVAILABLE,
)

# Deliberately re-declared rather than imported from
# `cairn.sandbox.services`. The validation image ships only `cairn.analysis`
# and `cairn.dynamic`; importing the sandbox package would pull
# pydantic-settings and the whole Manager configuration into a container that
# has no business holding either, and the import would simply fail there.
#
# `cairn/tests/dynamic/test_app.py` pins these against the catalogue, because
# two copies of one value that nothing compares is how they drift.
SERVICE_USER = "cairn"
SERVICE_PASSWORD = "cairn"
SERVICE_DATABASE = "cairn"

SERVICE_READY_TIMEOUT_SECONDS = 90.0
APP_READY_TIMEOUT_SECONDS = 180.0
APP_POLL_INTERVAL_SECONDS = 1.0
# Probed in order; the first that answers at all means the application is up.
READINESS_PATHS = ("/actuator/health", "/actuator/info", "/")


class EnvironmentError_(Exception):
    """The environment could not be brought up. Carries a §7.7 reason code."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class RunningApp:
    process: subprocess.Popen
    base_url: str
    log_path: Path


def wait_for_services(
    service_hosts: dict[str, str],
    *,
    timeout_seconds: float = SERVICE_READY_TIMEOUT_SECONDS,
    sleep=time.sleep,
) -> list[str]:
    """Block until every dependency accepts a connection.

    A TCP accept is all this checks. A protocol handshake would need a client
    per service, and the application is about to perform the real one — if the
    database is listening but not yet accepting queries, the application's own
    startup fails and that is reported as `DYNAMIC_APP_START_FAILED`, which is
    both accurate and inconclusive.
    """

    ready: list[str] = []
    deadline = time.monotonic() + timeout_seconds
    for name, endpoint in sorted(service_hosts.items()):
        host, _, port = endpoint.rpartition(":")
        if not host or not port.isdigit():
            raise EnvironmentError_(
                REASON_SERVICE_UNAVAILABLE,
                f"dependency service {name} has no usable endpoint",
            )
        while True:
            if _accepts(host, int(port)):
                ready.append(name)
                break
            if time.monotonic() >= deadline:
                raise EnvironmentError_(
                    REASON_SERVICE_UNAVAILABLE,
                    f"dependency service {name} did not accept a connection in time",
                )
            sleep(0.5)
    return ready


def _accepts(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=2.0):
            return True
    except OSError:
        return False


def application_environment(service_hosts: dict[str, str]) -> dict[str, str]:
    """Point the application at the dependency containers.

    Spring reads these relaxed-binding variables ahead of anything in
    `application.yml`, so the application connects to the throwaway services
    rather than to whatever hostname the repository's configuration names —
    which would be a host that does not exist on an isolated network.
    """

    environment: dict[str, str] = {
        "SPRING_MAIN_BANNER_MODE": "off",
        # A profile the repository is unlikely to define, so nothing in its
        # configuration is activated by this name.
        "SPRING_PROFILES_ACTIVE": "cairn-verification",
    }
    postgres = service_hosts.get("postgres")
    if postgres:
        environment.update(
            {
                "SPRING_DATASOURCE_URL": f"jdbc:postgresql://{postgres}/{SERVICE_DATABASE}",
                "SPRING_DATASOURCE_USERNAME": SERVICE_USER,
                "SPRING_DATASOURCE_PASSWORD": SERVICE_PASSWORD,
                "SPRING_DATASOURCE_DRIVER_CLASS_NAME": "org.postgresql.Driver",
            }
        )
    mysql = service_hosts.get("mysql")
    if mysql:
        environment.update(
            {
                "SPRING_DATASOURCE_URL": f"jdbc:mysql://{mysql}/{SERVICE_DATABASE}",
                "SPRING_DATASOURCE_USERNAME": SERVICE_USER,
                "SPRING_DATASOURCE_PASSWORD": SERVICE_PASSWORD,
            }
        )
    redis = service_hosts.get("redis")
    if redis:
        host, _, port = redis.rpartition(":")
        environment.update(
            {
                "SPRING_DATA_REDIS_HOST": host,
                "SPRING_DATA_REDIS_PORT": port,
                "SPRING_REDIS_HOST": host,
                "SPRING_REDIS_PORT": port,
            }
        )
    return environment


def start_application(
    jar_path: Path,
    *,
    port: int,
    service_hosts: dict[str, str],
    output_root: Path,
    scratch_root: Path,
) -> RunningApp:
    """Launch the packaged application and wait for it to answer."""

    if not jar_path.is_file() or jar_path.is_symlink():
        raise EnvironmentError_(
            REASON_BUILD_ARTIFACT_MISSING,
            "the build output does not contain the runnable artifact",
        )

    log_path = output_root / "runtime" / "application.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(scratch_root / "apphome"),
        "JAVA_HOME": os.environ.get("JAVA_HOME", "/opt/java/openjdk"),
        "SERVER_PORT": str(port),
        **application_environment(service_hosts),
    }
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    argv = [
        "java",
        # A read-only root filesystem means the JVM cannot use its default
        # temporary directory; /tmp is the tmpfs the template mounts.
        "-Djava.io.tmpdir=/tmp",
        "-XX:+ExitOnOutOfMemoryError",
        "-jar",
        str(jar_path),
    ]
    try:
        handle = log_path.open("wb")
        process = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            argv,
            cwd=str(scratch_root),
            env=environment,
            stdout=handle,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError as exc:
        raise EnvironmentError_(
            REASON_APP_START_FAILED,
            f"the application could not be started: {exc}",
        ) from exc

    base_url = f"http://127.0.0.1:{port}"
    if not _wait_ready(process, base_url):
        stop_application(process)
        raise EnvironmentError_(
            REASON_APP_NOT_READY
            if process.poll() is None
            else REASON_APP_START_FAILED,
            "the application did not become ready before the deadline",
        )
    return RunningApp(process=process, base_url=base_url, log_path=log_path)


def _wait_ready(
    process: subprocess.Popen,
    base_url: str,
    *,
    timeout_seconds: float = APP_READY_TIMEOUT_SECONDS,
) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            # It exited on its own; no amount of waiting will help.
            return False
        for path in READINESS_PATHS:
            try:
                with urllib.request.urlopen(f"{base_url}{path}", timeout=2.0):
                    return True
            except urllib.error.HTTPError:
                # Any HTTP status means something is listening and routing.
                return True
            except (urllib.error.URLError, OSError, ValueError):
                continue
        time.sleep(APP_POLL_INTERVAL_SECONDS)
    return False


def stop_application(process: subprocess.Popen, *, grace_seconds: float = 5.0) -> int | None:
    """Terminate the application, escalating if it ignores the first signal."""

    if process.poll() is not None:
        return process.returncode
    process.terminate()
    try:
        return process.wait(timeout=grace_seconds)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            return process.wait(timeout=grace_seconds)
        except subprocess.TimeoutExpired:  # pragma: no cover - defensive
            return None
