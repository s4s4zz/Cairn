from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
from pathlib import PurePosixPath
import stat
import tarfile
import unicodedata

from cairn.server.domain.enums import BuildSystem
from cairn.server.ingestion.errors import IngestionFailure
from cairn.server.ingestion.limits import IngestionLimits


_HASH_CHUNK_SIZE = 1024 * 1024
_TREE_HASH_HEADER = b"cairn-source-tree-v1\0"
_IGNORED_DIRECTORY_NAMES = {".git", ".hg", ".svn"}


@dataclass(frozen=True, slots=True)
class SnapshotFile:
    relative_path: str
    source_path: Path
    size_bytes: int
    executable: bool
    sha256: str


@dataclass(frozen=True, slots=True)
class SnapshotTree:
    files: tuple[SnapshotFile, ...]
    content_sha256: str
    file_count: int
    total_bytes: int
    java_file_count: int
    build_system: BuildSystem


def _hash_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        while chunk := stream.read(_HASH_CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return digest.hexdigest(), size


def collect_snapshot_tree(root: Path, limits: IngestionLimits) -> SnapshotTree:
    root = root.resolve()
    files: list[SnapshotFile] = []
    total_bytes = 0
    has_maven = False
    has_gradle = False
    normalized_paths: set[str] = set()

    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        retained_directories: list[str] = []
        for name in directory_names:
            candidate = directory_path / name
            if name in _IGNORED_DIRECTORY_NAMES:
                continue
            if candidate.is_symlink():
                raise IngestionFailure(
                    "SNAPSHOT_SYMLINK_UNSUPPORTED",
                    "Source tree contains a symbolic link",
                )
            retained_directories.append(name)
        directory_names[:] = retained_directories

        for name in file_names:
            source_path = directory_path / name
            raw_relative = source_path.relative_to(root).as_posix()
            relative = unicodedata.normalize("NFC", raw_relative)
            relative_path = PurePosixPath(relative)
            if any(
                part in _IGNORED_DIRECTORY_NAMES for part in relative_path.parts
            ):
                continue
            if (
                "\\" in relative
                or any(ord(character) < 32 for character in relative)
                or ":" in relative_path.parts[0]
            ):
                raise IngestionFailure(
                    "SNAPSHOT_INVALID_PATH",
                    "Source tree contains an invalid relative path",
                )
            if relative in normalized_paths:
                raise IngestionFailure(
                    "SNAPSHOT_DUPLICATE_PATH",
                    "Source tree contains duplicate normalized paths",
                )
            normalized_paths.add(relative)
            file_stat = source_path.lstat()
            if stat.S_ISLNK(file_stat.st_mode):
                raise IngestionFailure(
                    "SNAPSHOT_SYMLINK_UNSUPPORTED",
                    "Source tree contains a symbolic link",
                )
            if not stat.S_ISREG(file_stat.st_mode):
                raise IngestionFailure(
                    "SNAPSHOT_SPECIAL_FILE_UNSUPPORTED",
                    "Source tree contains an unsupported special file",
                )
            if len(relative.encode("utf-8")) > limits.max_path_length:
                raise IngestionFailure(
                    "SNAPSHOT_PATH_TOO_LONG",
                    "Source tree path exceeds the configured length limit",
                )
            if len(relative_path.parts) > limits.max_path_depth:
                raise IngestionFailure(
                    "SNAPSHOT_PATH_TOO_DEEP",
                    "Source tree path exceeds the configured depth limit",
                )
            if len(files) + 1 > limits.max_files:
                raise IngestionFailure(
                    "SNAPSHOT_TOO_MANY_FILES",
                    "Source tree exceeds the configured file count limit",
                    http_status=413,
                )
            if file_stat.st_size > limits.max_file_bytes:
                raise IngestionFailure(
                    "SNAPSHOT_FILE_TOO_LARGE",
                    "Source tree contains a file larger than the configured limit",
                    http_status=413,
                )

            sha256, size_bytes = _hash_file(source_path)
            total_bytes += size_bytes
            if total_bytes > limits.max_total_bytes:
                raise IngestionFailure(
                    "SNAPSHOT_TOO_LARGE",
                    "Source tree exceeds the configured expanded size limit",
                    http_status=413,
                )
            basename = source_path.name
            has_maven = has_maven or basename == "pom.xml"
            has_gradle = has_gradle or basename in {
                "build.gradle",
                "build.gradle.kts",
                "settings.gradle",
                "settings.gradle.kts",
            }
            files.append(
                SnapshotFile(
                    relative_path=relative,
                    source_path=source_path,
                    size_bytes=size_bytes,
                    executable=bool(file_stat.st_mode & 0o111),
                    sha256=sha256,
                )
            )

    files.sort(key=lambda item: item.relative_path.encode("utf-8"))
    java_file_count = sum(
        item.relative_path.lower().endswith(".java") for item in files
    )
    if java_file_count == 0:
        raise IngestionFailure(
            "NO_JAVA_SOURCE",
            "Source tree does not contain any Java source files",
        )

    digest = hashlib.sha256(_TREE_HASH_HEADER)
    for item in files:
        encoded_path = item.relative_path.encode("utf-8")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(b"\0regular\0")
        digest.update(b"1" if item.executable else b"0")
        digest.update(bytes.fromhex(item.sha256))

    if has_maven and has_gradle:
        build_system = BuildSystem.MIXED
    elif has_maven:
        build_system = BuildSystem.MAVEN
    elif has_gradle:
        build_system = BuildSystem.GRADLE
    else:
        build_system = BuildSystem.UNKNOWN

    return SnapshotTree(
        files=tuple(files),
        content_sha256=digest.hexdigest(),
        file_count=len(files),
        total_bytes=total_bytes,
        java_file_count=java_file_count,
        build_system=build_system,
    )


def write_snapshot_archive(tree: SnapshotTree, destination: Path) -> None:
    """Write a deterministic, read-only tar representation of a source tree."""
    with tarfile.open(destination, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for item in tree.files:
            info = tarfile.TarInfo(item.relative_path)
            info.size = item.size_bytes
            info.mode = 0o555 if item.executable else 0o444
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            with item.source_path.open("rb") as source:
                archive.addfile(info, source)
