"""Deriving the runtime environment from the application's own configuration.

The boundary this file defends is which files count. A repository ships plenty
of `application.yml` — in test fixtures, in vendored samples, in
`node_modules` — and reading one of those would start a database the deployed
application never asked for. It also ships `docker-compose.yml`, and parsing
that would hand the repository the decision of which containers the platform
runs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cairn.analysis.buildplan import DEFAULT_APP_PORT, detect_build_plan

POSTGRES = "spring:\n  datasource:\n    url: jdbc:postgresql://db:5432/shop\n"


def tree(root: Path, files: dict[str, str]) -> Path:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    return root


# --- what is detected ---------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("jdbc:postgresql://db/shop", "postgres"),
        ("jdbc:postgres://db/shop", "postgres"),
        ("jdbc:mysql://db/shop", "mysql"),
        ("jdbc:mariadb://db/shop", "mysql"),
        ("r2dbc:postgresql://db/shop", "postgres"),
    ],
)
def test_a_supported_datasource_selects_its_service(
    tmp_path: Path,
    url: str,
    expected: str,
) -> None:
    root = tree(
        tmp_path,
        {
            "src/main/resources/application.yml": (
                f"spring:\n  datasource:\n    url: {url}\n"
            )
        },
    )

    assert detect_build_plan(root).services == (expected,)


def test_an_unsupported_datasource_selects_nothing(tmp_path: Path) -> None:
    """An in-memory H2 needs no container, and an unknown driver must not make
    the platform guess one."""

    root = tree(
        tmp_path,
        {
            "src/main/resources/application.yml": (
                "spring:\n  datasource:\n    url: jdbc:h2:mem:shop\n"
            )
        },
    )

    assert detect_build_plan(root).services == ()


@pytest.mark.parametrize(
    "body",
    [
        "spring:\n  data:\n    redis:\n      host: cache\n",
        "spring:\n  redis:\n    host: cache\n",
    ],
)
def test_redis_is_detected_under_either_property_name(
    tmp_path: Path,
    body: str,
) -> None:
    root = tree(tmp_path, {"src/main/resources/application.yml": body})

    assert detect_build_plan(root).services == ("redis",)


def test_properties_files_are_read_too(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        {
            "src/main/resources/application.properties": (
                "server.port=8443\nspring.datasource.url=jdbc:mysql://db/shop\n"
            )
        },
    )

    plan = detect_build_plan(root)

    assert plan.services == ("mysql",)
    assert plan.app_port == 8443


def test_a_dotted_yaml_key_is_read_like_a_nested_one(tmp_path: Path) -> None:
    """Spring accepts both forms, so the detector has to."""

    root = tree(
        tmp_path,
        {
            "src/main/resources/application.yml": (
                "spring.datasource.url: jdbc:postgresql://db/shop\n"
            )
        },
    )

    assert detect_build_plan(root).services == ("postgres",)


def test_a_placeholder_port_falls_back_to_its_default(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        {"src/main/resources/application.yml": "server:\n  port: ${PORT:7000}\n"},
    )

    assert detect_build_plan(root).app_port == 7000


def test_the_default_port_is_used_when_none_is_configured(tmp_path: Path) -> None:
    root = tree(tmp_path, {"src/main/resources/application.yml": POSTGRES})

    assert detect_build_plan(root).app_port == DEFAULT_APP_PORT


# --- which files count --------------------------------------------------------


@pytest.mark.parametrize(
    "relative",
    [
        "application.yml",
        "src/main/resources/application.yml",
        "web/src/main/resources/application.yml",
        "config/application.yml",
        "src/main/resources/application-prod.yml",
    ],
)
def test_configuration_where_spring_looks_is_read(
    tmp_path: Path,
    relative: str,
) -> None:
    root = tree(tmp_path, {relative: POSTGRES})

    assert detect_build_plan(root).services == ("postgres",)


@pytest.mark.parametrize(
    "relative",
    [
        "test-fixtures/application.yml",
        "vendor/samples/application.yml",
        "node_modules/pkg/application.yml",
        "docs/examples/application.yml",
    ],
)
def test_configuration_anywhere_else_is_ignored(
    tmp_path: Path,
    relative: str,
) -> None:
    """A fixture in the repository must not be able to make the platform start
    a database."""

    root = tree(tmp_path, {relative: POSTGRES})

    plan = detect_build_plan(root)

    assert plan.services == ()
    assert plan.config_paths == ()


def test_a_repository_compose_file_decides_nothing(tmp_path: Path) -> None:
    """Parsing it would let the repository choose which containers run."""

    root = tree(
        tmp_path,
        {
            "docker-compose.yml": (
                "services:\n  db:\n    image: postgres:16\n  cache:\n"
                "    image: redis:7\n"
            )
        },
    )

    assert detect_build_plan(root).services == ()


# --- untrusted input ----------------------------------------------------------


def test_malformed_yaml_contributes_nothing_rather_than_failing(
    tmp_path: Path,
) -> None:
    """Fewer services degrades to inconclusive, which is the right direction."""

    root = tree(
        tmp_path,
        {"src/main/resources/application.yml": "spring:\n  - [unbalanced\n"},
    )

    plan = detect_build_plan(root)

    assert plan.services == ()
    assert plan.app_port == DEFAULT_APP_PORT


def test_an_oversized_configuration_file_is_skipped(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        {"src/main/resources/application.yml": POSTGRES + ("# pad\n" * 200_000)},
    )

    assert detect_build_plan(root).services == ()


@pytest.mark.parametrize("port", ["0", "70000", "not-a-number", "-1"])
def test_an_out_of_range_port_falls_back(tmp_path: Path, port: str) -> None:
    root = tree(
        tmp_path,
        {"src/main/resources/application.yml": f"server:\n  port: '{port}'\n"},
    )

    assert detect_build_plan(root).app_port == DEFAULT_APP_PORT


def test_multi_document_profiles_are_all_read(tmp_path: Path) -> None:
    root = tree(
        tmp_path,
        {
            "src/main/resources/application.yml": (
                "server:\n  port: 9000\n---\n"
                "spring:\n  datasource:\n    url: jdbc:postgresql://db/shop\n"
            )
        },
    )

    plan = detect_build_plan(root)

    assert plan.services == ("postgres",)
    assert plan.app_port == 9000
