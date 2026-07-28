from pathlib import Path

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
        },
        {
            "module_path": "tools/worker",
            "build_system": "gradle",
            "runner": "gradle",
            "argv": ["gradle", "--no-daemon", "--console=plain", "assemble"],
        },
    ]
