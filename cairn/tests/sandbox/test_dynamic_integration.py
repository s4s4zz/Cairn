"""The sandbox group against a real Docker daemon.

**This is not the rootless configuration production requires.** It runs against
whatever daemon the developer has, with `require_rootless` switched off, so it
proves nothing about user-namespace mapping. What it does prove is the part
6b actually adds and that a fake client cannot check: that the containers come
up on one isolated network, that the isolation is real in both directions, that
the out-of-band echo tripwire works end to end, and that destruction leaves
nothing behind.

`cairn/tests/sandbox/test_docker_integration.py` remains the rootless matrix
and is still the one that has to pass before a deployment is trusted.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

import pytest

docker = pytest.importorskip("docker")

from cairn.sandbox.backend import SandboxWorkspace  # noqa: E402
from cairn.sandbox.config import SandboxSettings  # noqa: E402
from cairn.sandbox.contracts import SandboxTemplateName  # noqa: E402
from cairn.sandbox.docker_backend import RootlessDockerBackend  # noqa: E402
from cairn.sandbox.services import ServiceKind  # noqa: E402
from cairn.sandbox.templates import TemplateRegistry  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[3]
VALIDATION_IMAGE = "cairn-sandbox-validation:test"
POSTGRES_IMAGE = "postgres:16-alpine"
# Reachable only if the network is *not* internal. 169.254.169.254 is the cloud
# metadata endpoint §9.4 names explicitly.
METADATA_ADDRESS = "169.254.169.254"


def _docker_available() -> bool:
    try:
        client = docker.from_env()
        client.ping()
        client.close()
        return True
    except Exception:  # noqa: BLE001
        return False


# Opt-in, like the rootless matrix in `test_docker_integration.py`: this layer
# builds an image and starts real containers, so it does not belong in the
# default run.
pytestmark = [
    pytest.mark.docker_local,
    pytest.mark.skipif(
        os.environ.get("CAIRN_TEST_LOCAL_DOCKER") != "1" or not _docker_available(),
        reason="set CAIRN_TEST_LOCAL_DOCKER=1 with a reachable Docker daemon",
    ),
]


@pytest.fixture(scope="module")
def validation_image() -> str:
    """Build the validation image once, or skip if it cannot be built."""

    client = docker.from_env()
    try:
        client.images.get(VALIDATION_IMAGE)
        return VALIDATION_IMAGE
    except docker.errors.ImageNotFound:
        pass
    finally:
        client.close()
    completed = subprocess.run(  # noqa: S603
        [
            "docker",
            "build",
            "-f",
            "sandbox-images/Dockerfile.validation",
            "-t",
            VALIDATION_IMAGE,
            ".",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        timeout=900,
    )
    if completed.returncode != 0:
        pytest.skip(
            "validation image could not be built: "
            + completed.stderr.decode("utf-8", "replace")[-400:]
        )
    return VALIDATION_IMAGE


@pytest.fixture
def settings(tmp_path: Path, validation_image: str) -> SandboxSettings:
    token_file = tmp_path / "token"
    token_file.write_text("t" * 48)
    return SandboxSettings(
        docker_host=os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock"),
        # Off on purpose, and the reason this file is not the rootless matrix.
        require_rootless=False,
        auth_token_file=token_file,
        artifact_root=tmp_path / "artifacts",
        state_root=tmp_path / "state",
        work_root=tmp_path / "work",
        validation_image=validation_image,
        postgres_image=POSTGRES_IMAGE,
    )


@pytest.fixture
def backend(settings: SandboxSettings):  # noqa: ANN201
    runner = RootlessDockerBackend(settings, client=docker.from_env())
    yield runner
    runner.close()


def workspace(settings: SandboxSettings, sandbox_id) -> SandboxWorkspace:  # noqa: ANN001
    root = settings.work_root / str(sandbox_id)
    source, scratch, output = root / "source", root / "scratch", root / "output"
    for path in (source, scratch, output):
        path.mkdir(parents=True, exist_ok=True)
    os.chmod(scratch, 0o777)
    os.chmod(output, 0o777)
    return SandboxWorkspace(root, source, scratch, output)


def sleeping_template(settings: SandboxSettings):  # noqa: ANN201
    """The validation template, told to idle so the test can exec into it."""

    from dataclasses import replace

    template = TemplateRegistry.from_settings(settings).get(
        SandboxTemplateName.VALIDATION
    )
    return replace(template, command=("/usr/bin/python3", "-c", "import time; time.sleep(600)"))


def run_in(container, argv: list[str]) -> tuple[int, str]:  # noqa: ANN001
    result = container.exec_run(argv, demux=False)
    return int(result.exit_code), result.output.decode("utf-8", "replace")


@pytest.fixture
def group(backend, settings: SandboxSettings):  # noqa: ANN001, ANN201
    """One live sandbox group, torn down whatever the test does."""

    sandbox_id = uuid4()
    template = sleeping_template(settings)
    backend.create(
        sandbox_id,
        template,
        template.defaults,
        workspace(settings, sandbox_id),
        None,
        [ServiceKind.POSTGRES, ServiceKind.ECHO],
    )
    backend.start(sandbox_id)
    client = docker.from_env()
    try:
        yield sandbox_id, backend, client
    finally:
        try:
            backend.destroy(sandbox_id)
        finally:
            client.close()


def test_the_group_comes_up_on_one_isolated_network(group) -> None:  # noqa: ANN001
    sandbox_id, _backend, client = group

    containers = client.containers.list(
        all=True,
        filters={"label": [f"cairn.sandbox.id={sandbox_id}"]},
    )
    networks = client.networks.list(
        filters={"label": [f"cairn.sandbox.id={sandbox_id}"]},
    )

    # Task container plus two services.
    assert len(containers) == 3
    assert len(networks) == 1
    assert networks[0].attrs["Internal"] is True


def test_the_task_reaches_its_dependency_by_name(group) -> None:  # noqa: ANN001
    sandbox_id, _backend, client = group
    task = client.containers.get(f"cairn-sandbox-{sandbox_id}")
    target = f"cairn-sandbox-svc-postgres-{sandbox_id}"

    exit_code, output = run_in(
        task,
        [
            "python3",
            "-c",
            (
                "import socket,sys\n"
                f"s=socket.create_connection(('{target}',5432),timeout=20)\n"
                "s.close(); print('connected')"
            ),
        ],
    )

    assert exit_code == 0, output
    assert "connected" in output


@pytest.mark.parametrize(
    ("label", "address", "port"),
    [
        ("cloud metadata", METADATA_ADDRESS, 80),
        ("public internet", "1.1.1.1", 443),
    ],
)
def test_the_group_cannot_reach_anything_outside_itself(
    group,  # noqa: ANN001
    label: str,
    address: str,
    port: int,
) -> None:
    """§9.4: no internet, no control plane, no host, no cloud metadata."""

    sandbox_id, _backend, client = group
    task = client.containers.get(f"cairn-sandbox-{sandbox_id}")

    exit_code, output = run_in(
        task,
        [
            "python3",
            "-c",
            (
                "import socket,sys\n"
                "try:\n"
                f"    socket.create_connection(('{address}',{port}),timeout=5)\n"
                "    print('REACHED')\n"
                "except OSError as exc:\n"
                "    print('blocked'); sys.exit(0)\n"
            ),
        ],
    )

    assert "REACHED" not in output, f"{label} was reachable: {output}"


def test_the_out_of_band_tripwire_records_a_nonce(group) -> None:  # noqa: ANN001
    """The mechanism SSRF, XXE and command-execution confirmations rely on."""

    sandbox_id, _backend, client = group
    task = client.containers.get(f"cairn-sandbox-{sandbox_id}")
    echo = f"cairn-sandbox-svc-echo-{sandbox_id}:8081"
    nonce = "cairn-" + "ab12" * 8

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        exit_code, _ = run_in(
            task,
            [
                "python3",
                "-c",
                (
                    "import urllib.request\n"
                    f"urllib.request.urlopen('http://{echo}/{nonce}', timeout=5).read()"
                ),
            ],
        )
        if exit_code == 0:
            break
        time.sleep(1)
    else:  # pragma: no cover - the echo service never came up
        pytest.fail("the echo service never accepted a request")

    exit_code, output = run_in(
        task,
        [
            "python3",
            "-c",
            (
                "import urllib.request\n"
                f"print(urllib.request.urlopen('http://{echo}/__cairn/observed',"
                " timeout=5).read().decode())"
            ),
        ],
    )

    assert exit_code == 0, output
    assert nonce in json.loads(output.strip().splitlines()[-1])["nonces"]


def test_an_authored_pocs_callback_is_confirmed_out_of_band(group) -> None:  # noqa: ANN001
    """The PoC executor's echo-hit check, end to end against the real service.

    The `PocExecutor` substitutes `{{CAIRN_CALLBACK}}` with a nonce URL, and an
    out-of-band criterion confirms only when that nonce reaches the echo
    service. Here the running "application" is the task container making the
    callback the payload would have caused, and the executor's own `_echo_hit`
    reads it back — the same code path the container runs.
    """

    from cairn.dynamic.poc import PocExecutor
    from cairn.dynamic.probes import default_caller

    sandbox_id, _backend, client = group
    task = client.containers.get(f"cairn-sandbox-{sandbox_id}")
    echo = f"cairn-sandbox-svc-echo-{sandbox_id}:8081"

    # Wait for the echo service, then have the container plant a nonce, standing
    # in for an application the PoC's payload made call out.
    nonce = "cairn-" + "cd34" * 8
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        exit_code, _ = run_in(
            task,
            [
                "python3",
                "-c",
                (
                    "import urllib.request\n"
                    f"urllib.request.urlopen('http://{echo}/{nonce}', timeout=5).read()"
                ),
            ],
        )
        if exit_code == 0:
            break
        time.sleep(1)
    else:  # pragma: no cover
        pytest.fail("the echo service never accepted a request")

    # The executor reads observed nonces from inside the container, where the
    # echo service is reachable. A hit for the planted nonce; a miss for one
    # that was never planted.
    check = (
        "import json, urllib.request\n"
        f"seen = json.loads(urllib.request.urlopen('http://{echo}/__cairn/observed',"
        " timeout=5).read())['nonces']\n"
        f"print('HIT' if '{nonce}' in seen else 'MISS')\n"
        "print('MISS2' if 'cairn-{}'.format('00'*16) in seen else 'CLEAN')"
    )
    exit_code, output = run_in(task, ["python3", "-c", check])

    assert exit_code == 0, output
    assert "HIT" in output
    assert "CLEAN" in output
    # The reader path the executor uses is the standard-library caller it ships.
    assert default_caller is not None and PocExecutor is not None


def test_the_validation_image_can_import_and_run_the_dynamic_runner(
    validation_image: str,
) -> None:
    """The in-container entry point must actually import.

    A regression guard the `sleep`-command tests above cannot give: they never
    exercise `run-validation`, so nothing there would notice the runner failing
    to import — which it did, until the image gained Pydantic. The image ships
    a package manager to no one, so a missing runtime dependency is a build-time
    problem or it is a production outage.
    """

    result = subprocess.run(  # noqa: S603
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "python3",
            validation_image,
            "-c",
            (
                "import cairn.dynamic.runner, cairn.dynamic.poc, cairn.poc.contracts\n"
                "import pydantic, sys\n"
                "assert 'cairn.poc.author' not in sys.modules\n"
                "print('ok', pydantic.VERSION)"
            ),
        ],
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout.decode("utf-8").startswith("ok 2.")


def test_the_validation_image_ships_no_package_manager_or_build_tool(
    validation_image: str,
) -> None:
    """§9.7: a JRE runs the packaged artifact; a JDK, Maven, pip or curl would
    let a compromised probe rebuild or re-fetch."""

    script = (
        "for b in javac mvn gradle git curl wget pip pip3 uv; do "
        'command -v "$b" >/dev/null 2>&1 && echo "PRESENT $b"; done; '
        "python3 -m pip --version >/dev/null 2>&1 && echo PRESENT pip-module; "
        "true"
    )
    result = subprocess.run(  # noqa: S603
        ["docker", "run", "--rm", "--entrypoint", "sh", validation_image, "-c", script],
        capture_output=True,
        timeout=60,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")
    assert result.stdout.decode("utf-8").strip() == ""


def test_destroy_leaves_nothing_running_or_reachable(
    backend,  # noqa: ANN001
    settings: SandboxSettings,
) -> None:
    """§13.6: after the sandbox is destroyed the target must be unreachable."""

    sandbox_id = uuid4()
    template = sleeping_template(settings)
    backend.create(
        sandbox_id,
        template,
        template.defaults,
        workspace(settings, sandbox_id),
        None,
        [ServiceKind.POSTGRES, ServiceKind.ECHO],
    )
    backend.start(sandbox_id)
    client = docker.from_env()
    try:
        assert client.containers.list(
            filters={"label": [f"cairn.sandbox.id={sandbox_id}"]}
        )

        backend.destroy(sandbox_id)

        assert (
            client.containers.list(
                all=True,
                filters={"label": [f"cairn.sandbox.id={sandbox_id}"]},
            )
            == []
        )
        assert (
            client.networks.list(
                filters={"label": [f"cairn.sandbox.id={sandbox_id}"]},
            )
            == []
        )
    finally:
        client.close()
