"""Standing the application up (§7.7).

The one test here that is not about failure modes is the constant-pinning one.
`cairn.dynamic.app` re-declares the throwaway service credentials rather than
importing them from `cairn.sandbox.services`, because the validation image
ships only `cairn.analysis` and `cairn.dynamic` — the import would fail in the
container. Two copies of one value that nothing compares is how they drift, so
this file compares them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cairn.dynamic import app as dynamic_app
from cairn.dynamic.app import (
    EnvironmentError_,
    application_environment,
    start_application,
    wait_for_services,
)
from cairn.dynamic.contracts import (
    REASON_BUILD_ARTIFACT_MISSING,
    REASON_SERVICE_UNAVAILABLE,
)
from cairn.sandbox import services as sandbox_services


def test_the_service_credentials_match_the_catalogue() -> None:
    """The runtime and the container specification must agree, or the
    application authenticates against a database that rejected it."""

    assert dynamic_app.SERVICE_USER == sandbox_services.SERVICE_USER
    assert dynamic_app.SERVICE_PASSWORD == sandbox_services.SERVICE_PASSWORD
    assert dynamic_app.SERVICE_DATABASE == sandbox_services.SERVICE_DATABASE


def test_the_dynamic_package_does_not_import_the_sandbox_package() -> None:
    """It is absent from the validation image; importing it would break there
    and nowhere else."""

    source = Path(dynamic_app.__file__).read_text(encoding="utf-8")

    assert "from cairn.sandbox" not in source
    assert "import cairn.sandbox" not in source


# --- the application is pointed at the throwaway services --------------------


def test_the_application_is_pointed_at_the_containers_not_its_own_config() -> None:
    """The repository's configuration names hosts that do not exist on an
    isolated network, so the platform overrides them."""

    environment = application_environment(
        {"postgres": "svc-postgres:5432", "redis": "svc-redis:6379"}
    )

    assert environment["SPRING_DATASOURCE_URL"].startswith(
        "jdbc:postgresql://svc-postgres:5432/"
    )
    assert environment["SPRING_DATASOURCE_USERNAME"] == sandbox_services.SERVICE_USER
    assert environment["SPRING_DATA_REDIS_HOST"] == "svc-redis"
    assert environment["SPRING_DATA_REDIS_PORT"] == "6379"


def test_the_activated_profile_is_one_the_repository_will_not_have_defined() -> None:
    environment = application_environment({})

    assert environment["SPRING_PROFILES_ACTIVE"] == "cairn-verification"


def test_no_datasource_is_injected_when_no_database_was_planned() -> None:
    environment = application_environment({"echo": "svc-echo:8081"})

    assert "SPRING_DATASOURCE_URL" not in environment


# --- failure modes -------------------------------------------------------------


def test_a_service_that_never_accepts_is_reported_not_waited_on_forever() -> None:
    with pytest.raises(EnvironmentError_) as excinfo:
        wait_for_services(
            {"postgres": "127.0.0.1:1"},
            timeout_seconds=0.05,
            sleep=lambda _seconds: None,
        )

    assert excinfo.value.reason_code == REASON_SERVICE_UNAVAILABLE


def test_an_endpoint_without_a_port_is_refused() -> None:
    with pytest.raises(EnvironmentError_) as excinfo:
        wait_for_services({"postgres": "no-port-here"}, sleep=lambda _s: None)

    assert excinfo.value.reason_code == REASON_SERVICE_UNAVAILABLE


def test_a_missing_runnable_artifact_is_reported_before_anything_starts(
    tmp_path: Path,
) -> None:
    with pytest.raises(EnvironmentError_) as excinfo:
        start_application(
            tmp_path / "absent.jar",
            port=8080,
            service_hosts={},
            output_root=tmp_path / "output",
            scratch_root=tmp_path / "scratch",
        )

    assert excinfo.value.reason_code == REASON_BUILD_ARTIFACT_MISSING


def test_a_symlinked_artifact_is_refused(tmp_path: Path) -> None:
    """The build output is unpacked from an archive; a symlink there would be
    pointing somewhere the archive did not carry."""

    real = tmp_path / "real.jar"
    real.write_bytes(b"not really a jar")
    link = tmp_path / "app.jar"
    link.symlink_to(real)

    with pytest.raises(EnvironmentError_) as excinfo:
        start_application(
            link,
            port=8080,
            service_hosts={},
            output_root=tmp_path / "output",
            scratch_root=tmp_path / "scratch",
        )

    assert excinfo.value.reason_code == REASON_BUILD_ARTIFACT_MISSING
