from io import BytesIO
import os
from pathlib import Path
import stat
import tarfile
import zipfile

import pytest

from cairn.server.domain.enums import SnapshotInputKind
from cairn.server.ingestion import (
    IngestionFailure,
    IngestionLimits,
    collect_snapshot_tree,
    extract_zip_archive,
    write_snapshot_archive,
)


def _classfile() -> bytes:
    return bytes.fromhex(
        "cafebabe0000003d0005"
        "01000444656d6f"
        "070001"
        "0100106a6176612f6c616e672f4f626a656374"
        "070003"
        "0021000200040000000000000000"
    )


@pytest.fixture
def limits() -> IngestionLimits:
    return IngestionLimits(
        upload_max_bytes=1024 * 1024,
        max_files=100,
        max_total_bytes=1024 * 1024,
        max_file_bytes=512 * 1024,
        max_compression_ratio=200,
        max_path_length=256,
        max_path_depth=16,
    )


def _zip(path: Path, members: list[tuple[str | zipfile.ZipInfo, bytes]]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in members:
            archive.writestr(name, content)


@pytest.mark.parametrize(
    "member_name",
    [
        "../escape.java",
        "/absolute.java",
        "C:/windows.java",
        "src\\escape.java",
    ],
)
def test_zip_path_escape_is_rejected(
    tmp_path,
    limits: IngestionLimits,
    member_name: str,
) -> None:
    archive = tmp_path / "unsafe.zip"
    _zip(archive, [(member_name, b"class Unsafe {}")])

    with pytest.raises(IngestionFailure) as captured:
        extract_zip_archive(archive, tmp_path / "out", limits)

    assert captured.value.error_code in {
        "SNAPSHOT_ARCHIVE_PATH_ESCAPE",
        "SNAPSHOT_ARCHIVE_INVALID_PATH",
    }
    assert not (tmp_path / "escape.java").exists()


def test_zip_symbolic_link_is_rejected(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    archive = tmp_path / "symlink.zip"
    link = zipfile.ZipInfo("src/link.java")
    link.create_system = 3
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    _zip(archive, [(link, b"../../outside")])

    with pytest.raises(IngestionFailure) as captured:
        extract_zip_archive(archive, tmp_path / "out", limits)

    assert captured.value.error_code == "SNAPSHOT_ARCHIVE_SYMLINK"


def test_zip_compression_bomb_ratio_is_rejected(tmp_path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(
        archive,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as output:
        output.writestr("src/Bomb.java", b"0" * 50_000)
    strict_limits = IngestionLimits(
        upload_max_bytes=1024 * 1024,
        max_files=100,
        max_total_bytes=1024 * 1024,
        max_file_bytes=1024 * 1024,
        max_compression_ratio=5,
        max_path_length=256,
        max_path_depth=16,
    )

    with pytest.raises(IngestionFailure) as captured:
        extract_zip_archive(archive, tmp_path / "out", strict_limits)

    assert captured.value.error_code == "SNAPSHOT_ARCHIVE_COMPRESSION_RATIO"


def test_normalized_tree_hash_and_tar_ignore_zip_order_and_timestamps(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    first_zip = tmp_path / "first.zip"
    second_zip = tmp_path / "second.zip"
    first_java = zipfile.ZipInfo("src/main/java/Demo.java", (2020, 1, 1, 0, 0, 0))
    first_pom = zipfile.ZipInfo("pom.xml", (2020, 1, 1, 0, 0, 0))
    second_java = zipfile.ZipInfo("src/main/java/Demo.java", (2026, 1, 1, 0, 0, 0))
    second_pom = zipfile.ZipInfo("pom.xml", (2026, 1, 1, 0, 0, 0))
    _zip(
        first_zip,
        [
            (first_java, b"public class Demo {}\n"),
            (first_pom, b"<project />\n"),
        ],
    )
    _zip(
        second_zip,
        [
            (second_pom, b"<project />\n"),
            (second_java, b"public class Demo {}\n"),
        ],
    )

    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    extract_zip_archive(first_zip, first_root, limits)
    extract_zip_archive(second_zip, second_root, limits)
    first_tree = collect_snapshot_tree(first_root, limits)
    second_tree = collect_snapshot_tree(second_root, limits)
    first_tar = tmp_path / "first.tar"
    second_tar = tmp_path / "second.tar"
    write_snapshot_archive(first_tree, first_tar)
    write_snapshot_archive(second_tree, second_tar)

    assert first_tree.content_sha256 == second_tree.content_sha256
    assert first_tree.java_file_count == 1
    assert first_tree.jvm_artifact_count == 0
    assert first_tree.input_kind is SnapshotInputKind.SOURCE
    assert first_tree.build_system.value == "maven"
    assert first_tar.read_bytes() == second_tar.read_bytes()
    with tarfile.open(first_tar) as archive:
        members = archive.getmembers()
        assert [member.name for member in members] == [
            "pom.xml",
            "src/main/java/Demo.java",
        ]
        assert all(member.mtime == 0 for member in members)
        assert all(member.mode == 0o444 for member in members)


def test_tree_without_supported_jvm_input_is_rejected(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "README.md").write_text("not Java")

    with pytest.raises(IngestionFailure) as captured:
        collect_snapshot_tree(root, limits)

    assert captured.value.error_code == "NO_SUPPORTED_JVM_INPUT"


def test_tree_classifies_bytecode_and_hybrid_inputs(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    classfile = _classfile()
    bytecode_root = tmp_path / "bytecode"
    bytecode_root.mkdir()
    (bytecode_root / "renamed.bin").write_bytes(classfile)
    hybrid_root = tmp_path / "hybrid"
    hybrid_root.mkdir()
    (hybrid_root / "Demo.java").write_text("class Demo {}")
    (hybrid_root / "Demo.class").write_bytes(classfile)

    bytecode = collect_snapshot_tree(bytecode_root, limits)
    hybrid = collect_snapshot_tree(hybrid_root, limits)

    assert bytecode.java_file_count == 0
    assert bytecode.jvm_artifact_count == 1
    assert bytecode.input_kind is SnapshotInputKind.BYTECODE
    assert hybrid.java_file_count == 1
    assert hybrid.jvm_artifact_count == 1
    assert hybrid.input_kind is SnapshotInputKind.HYBRID


def test_tree_rejects_a_live_symbolic_link(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    outside = tmp_path / "Outside.java"
    outside.write_text("class Outside {}")
    os.symlink(outside, root / "Link.java")

    with pytest.raises(IngestionFailure) as captured:
        collect_snapshot_tree(root, limits)

    assert captured.value.error_code == "SNAPSHOT_SYMLINK_UNSUPPORTED"


def test_tree_rejects_control_characters_in_git_style_paths(
    tmp_path,
    limits: IngestionLimits,
) -> None:
    root = tmp_path / "source"
    root.mkdir()
    (root / "Unsafe\nName.java").write_text("class Unsafe {}")

    with pytest.raises(IngestionFailure) as captured:
        collect_snapshot_tree(root, limits)

    assert captured.value.error_code == "SNAPSHOT_INVALID_PATH"
