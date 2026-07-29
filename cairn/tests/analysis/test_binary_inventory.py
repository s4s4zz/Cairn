from __future__ import annotations

from io import BytesIO
from pathlib import Path
import shutil
import stat
import subprocess
import zipfile

import pytest

from cairn.analysis.binary_inventory import (
    BinaryInventoryFailure,
    BinaryInventoryLimits,
    build_binary_inventory,
    stage_binary_classes,
)
from cairn.analysis.contracts import AnalysisManifest, BinaryInventoryResult
from cairn.analysis.runner import run_operation
def _archive(path: Path, entries: list[tuple[str | zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as output:
        for name, payload in entries:
            output.writestr(name, payload)


@pytest.fixture(scope="module")
def class_bytes(tmp_path_factory: pytest.TempPathFactory) -> bytes:
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("javac is required for the binary inventory integration tests")
    root = tmp_path_factory.mktemp("binary-inventory-class")
    source = root / "Fixture.java"
    source.write_text("public final class Fixture { public void run() {} }\n")
    subprocess.run(
        [javac, "--release", "17", "-g:none", str(source)],
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )
    return (root / "Fixture.class").read_bytes()


def _fixture_war(path: Path, class_bytes: bytes) -> None:
    nested = BytesIO()
    with zipfile.ZipFile(nested, "w") as jar:
        jar.writestr(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nImplementation-Version: 1.0\r\n\r\n",
        )
        for name in ("PlatformRequest", "PlatformSql", "Guard", "TenantGuard"):
            jar.writestr(f"org/cairn/fixture/{name}.class", class_bytes)
    with zipfile.ZipFile(path, "w") as war:
        war.writestr("WEB-INF/classes/org/cairn/fixture/Action.class", class_bytes)
        war.writestr("WEB-INF/lib/synthetic-core.jar", nested.getvalue())
        war.writestr("WEB-INF/web.xml", b"<web-app/>\n")
        war.writestr("views/lookup.jsp", b"<%-- fixture --%>\n")


def test_nested_war_inventory_has_stable_paths_components_and_sbom(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    war = source / "opaque-input.bin"
    _fixture_war(war, class_bytes)

    first = build_binary_inventory(source, scratch=tmp_path / "scratch-one")
    second = build_binary_inventory(source, scratch=tmp_path / "scratch-two")

    assert first == second
    assert first["archive_count"] == 2
    assert first["class_entry_count"] == 5
    assert first["selected_class_count"] == 5
    assert [item["kind"] for item in first["components"]] == ["war", "jar"]
    paths = {item["logical_path"] for item in first["entries"]}
    assert (
        "opaque-input.bin!/WEB-INF/lib/synthetic-core.jar!/"
        "org/cairn/fixture/PlatformSql.class"
    ) in paths
    nested_class = next(
        item
        for item in first["entries"]
        if item["logical_path"].endswith("/PlatformSql.class")
    )
    assert nested_class["container_path"] == "opaque-input.bin"
    assert nested_class["entry_path"] == (
        "WEB-INF/lib/synthetic-core.jar!/org/cairn/fixture/PlatformSql.class"
    )
    assert "opaque-input.bin!/WEB-INF/web.xml" in paths
    assert first["sbom"]["bomFormat"] == "CycloneDX"


def test_web_inf_class_alone_still_identifies_a_modern_war(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _archive(
        source / "deployment.bin",
        [("WEB-INF/classes/org/cairn/fixture/Action.class", class_bytes)],
    )

    result = build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert [component["kind"] for component in result["components"]] == ["war"]


def test_standalone_class_is_detected_by_magic_not_suffix(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "payload.data").write_bytes(class_bytes)

    result = build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert result["archive_count"] == 0
    assert result["class_entry_count"] == 1
    assert result["entries"][0]["validation"] == "header-only"
    assert result["entries"][0]["entry_path"] == "payload.data"


@pytest.mark.parametrize(
    ("member", "reason_code"),
    [
        ("../Escape.class", "BINARY_ARCHIVE_PATH_ESCAPE"),
        ("/absolute.class", "BINARY_ARCHIVE_INVALID_PATH"),
        ("C:/drive.class", "BINARY_ARCHIVE_PATH_ESCAPE"),
        ("pkg\\Backslash.class", "BINARY_ARCHIVE_INVALID_PATH"),
    ],
)
def test_nested_archive_path_escape_is_rejected(
    tmp_path: Path,
    member: str,
    reason_code: str,
    class_bytes: bytes,
) -> None:
    nested = BytesIO()
    with zipfile.ZipFile(nested, "w") as output:
        output.writestr(member, class_bytes)
    source = tmp_path / "source"
    source.mkdir()
    _archive(source / "outer.bin", [("lib/inner.bin", nested.getvalue())])

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert captured.value.reason_code == reason_code


def test_unicode_normalization_collision_is_rejected(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _archive(
        source / "input.bin",
        [
            ("caf\u00e9.class", class_bytes),
            ("cafe\u0301.class", class_bytes),
        ],
    )

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert captured.value.reason_code == "BINARY_ARCHIVE_DUPLICATE_PATH"


def test_symlink_and_file_directory_collision_are_rejected(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    symlink = zipfile.ZipInfo("pkg/Link.class")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    _archive(source / "symlink.bin", [(symlink, b"target")])

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch-one")
    assert captured.value.reason_code == "BINARY_ARCHIVE_SYMLINK"

    (source / "symlink.bin").unlink()
    _archive(
        source / "collision.bin",
        [("pkg", b"file"), ("pkg/Type.class", class_bytes)],
    )
    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch-two")
    assert captured.value.reason_code == "BINARY_ARCHIVE_PATH_COLLISION"


def test_nested_compression_ratio_uses_one_budget_for_all_layers(
    tmp_path: Path,
) -> None:
    nested = BytesIO()
    with zipfile.ZipFile(nested, "w", compression=zipfile.ZIP_DEFLATED) as output:
        output.writestr("large.properties", b"0" * 50_000)
    source = tmp_path / "source"
    source.mkdir()
    _archive(source / "outer.bin", [("nested.bin", nested.getvalue())])

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(
            source,
            scratch=tmp_path / "scratch",
            limits=BinaryInventoryLimits(max_compression_ratio=5),
        )

    assert captured.value.reason_code == "BINARY_ARCHIVE_COMPRESSION_RATIO"


def test_multi_release_jar_selects_highest_supported_class(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    manifest = b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n"
    _archive(
        source / "multi.bin",
        [
            ("META-INF/MANIFEST.MF", manifest),
            ("pkg/Type.class", class_bytes),
            ("META-INF/versions/11/pkg/Type.class", class_bytes),
            ("META-INF/versions/17/pkg/Type.class", class_bytes),
            ("META-INF/versions/21/pkg/Type.class", class_bytes),
        ],
    )

    result = build_binary_inventory(source, scratch=tmp_path / "scratch")
    selected = [
        item["entry_path"]
        for item in result["entries"]
        if item["kind"] == "class" and item["selected"]
    ]

    assert selected == ["META-INF/versions/17/pkg/Type.class"]
    assert result["selected_class_count"] == 1
    assert {
        gap["reason_code"] for gap in result["coverage_gaps"]
    } == {"MULTI_RELEASE_CLASS_SHADOWED"}


def test_nested_multi_release_jar_selects_only_the_target_version(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    nested = BytesIO()
    with zipfile.ZipFile(nested, "w") as jar:
        jar.writestr(
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
        )
        jar.writestr("pkg/Type.class", class_bytes)
        jar.writestr("META-INF/versions/11/pkg/Type.class", class_bytes)
        jar.writestr("META-INF/versions/17/pkg/Type.class", class_bytes)
        jar.writestr("META-INF/versions/21/pkg/Type.class", class_bytes)

    source = tmp_path / "source"
    source.mkdir()
    _archive(
        source / "application.war",
        [
            ("WEB-INF/lib/multi.jar", nested.getvalue()),
            ("WEB-INF/web.xml", b"<web-app/>\n"),
        ],
    )

    inventory, staged = stage_binary_classes(
        source,
        tmp_path / "classes",
        scratch=tmp_path / "scratch",
    )

    selected = [
        entry["entry_path"]
        for entry in inventory["entries"]
        if entry["kind"] == "class" and entry["selected"]
    ]
    assert selected == [
        "WEB-INF/lib/multi.jar!/META-INF/versions/17/pkg/Type.class"
    ]
    assert [item.entry_path for item in staged] == selected


def test_empty_zip_is_not_a_supported_jvm_input(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _archive(source / "empty.bin", [])

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert captured.value.reason_code == "NO_SUPPORTED_JVM_INPUT"


def test_archive_member_cannot_collide_with_logical_path_delimiter(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _archive(source / "input.bin", [("ambiguous!/Type.class", class_bytes)])

    with pytest.raises(BinaryInventoryFailure) as captured:
        build_binary_inventory(source, scratch=tmp_path / "scratch")

    assert captured.value.reason_code == "BINARY_ARCHIVE_PATH_ESCAPE"


def test_binary_inventory_runner_emits_strict_manifest_and_raw_results(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    scratch = tmp_path / "scratch"
    output = tmp_path / "output"
    source.mkdir()
    scratch.mkdir()
    output.mkdir()
    (source / "Type.bin").write_bytes(class_bytes)

    payload = run_operation(
        "binary-inventory",
        source=source,
        scratch=scratch,
        output=output,
    )
    manifest = AnalysisManifest.model_validate(payload)

    inventory = BinaryInventoryResult.model_validate_json(
        (output / "binary-inventory.json").read_bytes()
    )
    assert manifest.binary_inventory is None
    assert manifest.binary_inventory_path == "binary-inventory.json"
    assert manifest.binary_inventory_summary is not None
    assert manifest.binary_inventory_summary.archive_count == inventory.archive_count
    assert manifest.binary_inventory_summary.coverage_gap_count == len(
        inventory.coverage_gaps
    )
    assert manifest.raw_result_paths == ["binary-inventory.json", "sbom.cdx.json"]


def test_class_staging_keeps_only_selected_multi_release_inputs(
    tmp_path: Path,
    class_bytes: bytes,
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    _archive(
        source / "multi.bin",
        [
            (
                "META-INF/MANIFEST.MF",
                b"Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n",
            ),
            ("pkg/Type.class", class_bytes),
            ("META-INF/versions/17/pkg/Type.class", class_bytes),
            ("META-INF/versions/21/pkg/Type.class", class_bytes),
        ],
    )

    inventory, staged = stage_binary_classes(
        source,
        tmp_path / "classes",
        scratch=tmp_path / "scratch",
    )

    assert inventory["class_entry_count"] == 3
    assert len(staged) == 1
    assert staged[0].entry_path == "META-INF/versions/17/pkg/Type.class"
    assert [path.name for path in (tmp_path / "classes").iterdir()] == [
        staged[0].staged_name
    ]
    assert (tmp_path / "classes" / staged[0].staged_name).read_bytes() == class_bytes
