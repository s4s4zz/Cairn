from pathlib import Path

import pytest

from cairn.analysis.contracts import InventoryResult
from cairn.analysis.indexer import build_inventory, index_source
from cairn.analysis.project import detect_project


FIXTURES = Path(__file__).parent / "fixtures"


def test_maven_multimodule_detection_and_build_plan_are_stable() -> None:
    result = detect_project(FIXTURES / "maven-multi")

    assert result["build_system"] == "maven"
    assert result["java_versions"] == ["21"]
    assert [(item["path"], item["name"]) for item in result["modules"]] == [
        (".", "maven-parent"),
        ("core", "core"),
        ("web", "web"),
    ]
    assert result["module_dependencies"] == [
        {"source": "web", "target": "core", "kind": "maven"}
    ]
    assert result["build_plan"] == [
        {
            "module_path": ".",
            "build_system": "maven",
            "runner": "maven-wrapper",
            "argv": [
                "./mvnw",
                "--batch-mode",
                "--no-transfer-progress",
                "-DskipTests",
                "package",
            ],
            "java_version": "21",
        }
    ]
    web = next(item for item in result["modules"] if item["path"] == "web")
    assert web["frameworks"] == ["spring-boot", "spring-security"]
    assert web["parent_path"] == "."


def test_gradle_multimodule_detection_tracks_project_dependency() -> None:
    result = detect_project(FIXTURES / "gradle-multi")

    assert result["build_system"] == "gradle"
    assert result["java_versions"] == ["17"]
    assert [(item["path"], item["name"]) for item in result["modules"]] == [
        (".", "gradle-multi"),
        ("app", "app"),
        ("library", "library"),
    ]
    assert result["module_dependencies"] == [
        {"source": "app", "target": "library", "kind": "gradle"}
    ]
    assert result["build_plan"][0]["runner"] == "gradle-wrapper"
    assert result["build_plan"][0]["argv"][0] == "./gradlew"


def test_java_index_covers_entrypoints_permissions_sources_and_sinks() -> None:
    result = index_source(FIXTURES / "maven-multi")

    assert result["java_files_total"] == 2
    assert {
        (item["kind"], item["symbol"], item["route"])
        for item in result["entrypoints"]
    } >= {
        ("http-controller", "dev.cairn.UserController", None),
        ("http-route", "user", "/users/{name}"),
    }
    assert {
        (item["kind"], item["symbol"], item["expression"])
        for item in result["permissions"]
    } == {("pre-authorize", "user", "\"hasRole('ADMIN')\"")}
    assert any(
        item["kind"] == "http-path" and item["symbol"] == "user"
        for item in result["sources"]
    )
    assert [
        (item["kind"], item["path"])
        for item in result["sinks"]
    ] == [
        (
            "database-query",
            "core/src/main/java/dev/cairn/UserRepository.java",
        )
    ]


def test_gradle_index_detects_message_and_deserialization_surfaces() -> None:
    result = index_source(FIXTURES / "gradle-multi")

    assert any(
        item["kind"] == "message-consumer" and item["symbol"] == "consume"
        for item in result["entrypoints"]
    )
    assert {item["kind"] for item in result["sinks"]} == {
        "deserialization",
        "outbound-http",
    }


def test_complete_inventory_matches_strict_contract() -> None:
    raw = build_inventory(FIXTURES / "maven-multi")

    inventory = InventoryResult.model_validate(raw)

    assert len(inventory.modules) == 3
    assert len(inventory.entrypoints) == 2
    assert inventory.java_files_total == 2


def test_independent_nested_mixed_builds_each_receive_a_build_step(
    tmp_path: Path,
) -> None:
    tmp_path.joinpath("pom.xml").write_text(
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>dev.cairn</groupId>
  <artifactId>root-service</artifactId>
  <version>1.0.0</version>
</project>
"""
    )
    gradle_root = tmp_path / "tools" / "worker"
    gradle_root.mkdir(parents=True)
    gradle_root.joinpath("settings.gradle").write_text(
        "rootProject.name = 'worker'\n"
    )
    gradle_root.joinpath("build.gradle").write_text("plugins { id 'java' }\n")

    result = detect_project(tmp_path)

    assert result["build_system"] == "mixed"
    assert result["build_plan"] == [
        {
            "module_path": ".",
            "build_system": "maven",
            "runner": "maven",
            "argv": [
                "mvn",
                "--batch-mode",
                "--no-transfer-progress",
                "-DskipTests",
                "package",
            ],
            "java_version": None,
        },
        {
            "module_path": "tools/worker",
            "build_system": "gradle",
            "runner": "gradle",
            "argv": ["gradle", "--no-daemon", "--console=plain", "assemble"],
            "java_version": None,
        },
    ]


def test_a_module_builds_on_the_jdk_it_declares(tmp_path: Path) -> None:
    """A project is audited as it is, not as it would have to be rewritten.

    A Spring Boot 2.x project pinning an annotation processor of its era cannot
    compile on a current JDK at all, so the declared version has to reach the
    build rather than stopping at the inventory.
    """

    tmp_path.joinpath("pom.xml").write_text(
        """<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>demo</groupId>
  <artifactId>legacy</artifactId>
  <version>1.0.0</version>
  <properties><java.version>1.8</java.version></properties>
</project>
"""
    )

    result = detect_project(tmp_path)

    assert result["java_versions"] == ["8"]
    assert result["build_plan"][0]["java_version"] == "8"


def test_select_jdk_prefers_the_exact_version_then_the_next_one_up(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cairn.analysis import execution

    homes = {version: tmp_path / f"jdk-{version}" for version in ("8", "17")}
    for home in homes.values():
        home.mkdir()
    monkeypatch.setattr(execution, "_JDK_HOMES", homes)

    assert execution.select_jdk("8") == homes["8"]
    assert execution.select_jdk("17") == homes["17"]
    # 11 is absent, so the next usable toolchain up is chosen rather than a
    # lower one that could not read the project's class files.
    assert execution.select_jdk("11") == homes["17"]
    # Nothing at or above 21, and no declaration at all, both keep the default.
    assert execution.select_jdk("21") is None
    assert execution.select_jdk(None) is None
