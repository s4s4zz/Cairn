from io import BytesIO
from pathlib import Path
import os
import tarfile

import pytest

from cairn.sandbox.archives import (
    ArchiveLimits,
    archive_output_tree,
    extract_snapshot_archive,
    measure_writable_tree,
)
from cairn.sandbox.errors import SandboxError


LIMITS = ArchiveLimits(
    max_files=10,
    max_total_bytes=1024,
    max_file_bytes=512,
)


def write_tar(path: Path, members: list[tuple[tarfile.TarInfo, bytes]]) -> None:
    with tarfile.open(path, mode="w") as archive:
        for info, payload in members:
            archive.addfile(info, BytesIO(payload) if info.isreg() else None)


def regular_member(name: str, payload: bytes) -> tuple[tarfile.TarInfo, bytes]:
    info = tarfile.TarInfo(name)
    info.size = len(payload)
    info.mode = 0o644
    return info, payload


def test_snapshot_tar_is_safely_extracted_read_only(tmp_path: Path) -> None:
    archive_path = tmp_path / "snapshot.tar"
    write_tar(
        archive_path,
        [regular_member("src/Application.java", b"class Application {}")],
    )

    usage = extract_snapshot_archive(archive_path, tmp_path / "source", LIMITS)

    source = tmp_path / "source" / "src" / "Application.java"
    assert source.read_text() == "class Application {}"
    assert usage.files == 1
    assert source.stat().st_mode & 0o222 == 0


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/windows", "a\\b"])
def test_snapshot_tar_rejects_escaping_paths(tmp_path: Path, name: str) -> None:
    archive_path = tmp_path / "snapshot.tar"
    write_tar(archive_path, [regular_member(name, b"bad")])

    with pytest.raises(SandboxError) as captured:
        extract_snapshot_archive(archive_path, tmp_path / "source", LIMITS)

    assert captured.value.error_code == "SANDBOX_SNAPSHOT_INVALID"
    assert not (tmp_path / "escape").exists()


def test_snapshot_tar_rejects_links(tmp_path: Path) -> None:
    archive_path = tmp_path / "snapshot.tar"
    link = tarfile.TarInfo("source-link")
    link.type = tarfile.SYMTYPE
    link.linkname = "/etc/passwd"
    write_tar(archive_path, [(link, b"")])

    with pytest.raises(SandboxError) as captured:
        extract_snapshot_archive(archive_path, tmp_path / "source", LIMITS)

    assert captured.value.error_code == "SANDBOX_SNAPSHOT_INVALID"


def test_output_archive_is_deterministic_and_rejects_symlinks(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    (output / "evidence.json").write_text('{"ok":true}')
    first = tmp_path / "first.tar"
    second = tmp_path / "second.tar"

    archive_output_tree(output, first, LIMITS)
    os.utime(output / "evidence.json", (2_000_000_000, 2_000_000_000))
    archive_output_tree(output, second, LIMITS)

    assert first.read_bytes() == second.read_bytes()

    (output / "escape").symlink_to("/etc/passwd")
    with pytest.raises(SandboxError) as captured:
        archive_output_tree(output, tmp_path / "bad.tar", LIMITS)
    assert captured.value.error_code == "SANDBOX_OUTPUT_INVALID"


def test_output_limit_and_disk_measurement_count_sparse_files(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    scratch = tmp_path / "scratch"
    output.mkdir()
    scratch.mkdir()
    large = scratch / "large.bin"
    with large.open("wb") as stream:
        stream.truncate(2048)

    usage = measure_writable_tree((scratch, output), max_entries=10)

    assert usage.bytes >= 2048

    (output / "too-large").write_bytes(b"x" * 513)
    with pytest.raises(SandboxError) as captured:
        archive_output_tree(output, tmp_path / "output.tar", LIMITS)
    assert captured.value.error_code == "SANDBOX_OUTPUT_LIMIT_EXCEEDED"
