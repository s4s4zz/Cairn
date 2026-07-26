from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import tarfile
import unicodedata

from cairn.sandbox.errors import SandboxError


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    max_files: int
    max_total_bytes: int
    max_file_bytes: int
    max_path_length: int = 1024
    max_path_depth: int = 64


@dataclass(frozen=True, slots=True)
class TreeUsage:
    files: int
    bytes: int


@dataclass(frozen=True, slots=True)
class _OutputFile:
    relative_path: str
    path: Path
    size_bytes: int
    executable: bool


def extract_snapshot_archive(
    archive_path: Path,
    destination: Path,
    limits: ArchiveLimits,
) -> TreeUsage:
    """Extract a trusted-by-hash but still structurally untrusted Snapshot TAR."""
    destination.mkdir(parents=True, exist_ok=False)
    root = destination.resolve()
    if any(destination.iterdir()):
        raise ValueError("snapshot extraction directory must be empty")

    seen_paths: set[str] = set()
    directories: set[Path] = {root}
    entry_count = 0
    file_count = 0
    total_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            for member in archive:
                entry_count += 1
                if entry_count > limits.max_files:
                    raise SandboxError(
                        "SANDBOX_SNAPSHOT_INVALID",
                        "Snapshot archive exceeds the entry-count limit",
                        http_status=413,
                    )
                relative = _normalize_relative_path(
                    member.name,
                    limits,
                    error_code="SANDBOX_SNAPSHOT_INVALID",
                )
                if relative in seen_paths:
                    raise _snapshot_invalid("Snapshot archive has duplicate paths")
                seen_paths.add(relative)
                target = root.joinpath(*PurePosixPath(relative).parts)
                if not target.resolve().is_relative_to(root):
                    raise _snapshot_invalid("Snapshot archive path escapes its root")

                if member.isdir():
                    _mkdir_chain(root, target)
                    directories.add(target)
                    continue
                if not member.isreg():
                    raise _snapshot_invalid(
                        "Snapshot archive contains a link or special file"
                    )

                file_count += 1
                if member.size < 0 or member.size > limits.max_file_bytes:
                    raise SandboxError(
                        "SANDBOX_SNAPSHOT_INVALID",
                        "Snapshot archive contains an oversized file",
                        http_status=413,
                    )
                total_bytes += member.size
                if total_bytes > limits.max_total_bytes:
                    raise SandboxError(
                        "SANDBOX_SNAPSHOT_INVALID",
                        "Snapshot archive exceeds the expanded-size limit",
                        http_status=413,
                    )

                _mkdir_chain(root, target.parent)
                directories.update(
                    parent
                    for parent in target.parents
                    if parent == root or parent.is_relative_to(root)
                )
                source = archive.extractfile(member)
                if source is None:
                    raise _snapshot_invalid("Snapshot archive member cannot be read")
                try:
                    with target.open("xb") as output:
                        copied = _copy_limited(source, output, member.size)
                        output.flush()
                        os.fsync(output.fileno())
                except FileExistsError as exc:
                    raise _snapshot_invalid(
                        "Snapshot archive has conflicting paths"
                    ) from exc
                if copied != member.size:
                    raise _snapshot_invalid("Snapshot archive member is truncated")
                os.chmod(target, 0o555 if member.mode & 0o111 else 0o444)
    except tarfile.TarError as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise _snapshot_invalid("Snapshot artifact is not a valid TAR archive") from exc
    except OSError as exc:
        shutil.rmtree(destination, ignore_errors=True)
        raise SandboxError(
            "SANDBOX_WORKSPACE_UNAVAILABLE",
            "Sandbox workspace could not be prepared",
            http_status=503,
        ) from exc
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise

    for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
        if directory.exists():
            os.chmod(directory, 0o555)
    return TreeUsage(files=file_count, bytes=total_bytes)


def archive_output_tree(
    root: Path,
    destination: Path,
    limits: ArchiveLimits,
) -> TreeUsage:
    """Create a deterministic TAR from stopped, untrusted workload output."""
    try:
        files = _collect_output_files(root, limits)
        with tarfile.open(
            destination,
            mode="w",
            format=tarfile.GNU_FORMAT,
        ) as archive:
            for item in files:
                info = tarfile.TarInfo(item.relative_path)
                info.size = item.size_bytes
                info.mode = 0o555 if item.executable else 0o444
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                with item.path.open("rb") as source:
                    archive.addfile(info, source)
    except SandboxError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise SandboxError(
            "SANDBOX_OUTPUT_INVALID",
            "Sandbox output could not be archived safely",
        ) from exc
    return TreeUsage(
        files=len(files),
        bytes=sum(item.size_bytes for item in files),
    )


def measure_writable_tree(
    roots: tuple[Path, ...],
    *,
    max_entries: int,
) -> TreeUsage:
    """Measure logical and allocated bytes without following workload links."""
    entries = 0
    total_bytes = 0
    regular_files = 0
    for root in roots:
        for directory, directory_names, file_names in os.walk(root, followlinks=False):
            directory_path = Path(directory)
            retained: list[str] = []
            for name in directory_names:
                candidate = directory_path / name
                entries += 1
                if entries > max_entries:
                    return TreeUsage(files=entries, bytes=total_bytes)
                metadata = candidate.lstat()
                if not stat.S_ISLNK(metadata.st_mode):
                    retained.append(name)
                total_bytes += metadata.st_blocks * 512
            directory_names[:] = retained
            for name in file_names:
                candidate = directory_path / name
                entries += 1
                if entries > max_entries:
                    return TreeUsage(files=entries, bytes=total_bytes)
                metadata = candidate.lstat()
                total_bytes += max(metadata.st_size, metadata.st_blocks * 512)
                if stat.S_ISREG(metadata.st_mode):
                    regular_files += 1
    return TreeUsage(files=regular_files, bytes=total_bytes)


def _collect_output_files(root: Path, limits: ArchiveLimits) -> list[_OutputFile]:
    root = root.resolve()
    files: list[_OutputFile] = []
    seen_paths: set[str] = set()
    entry_count = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in directory_names:
            entry_count += 1
            if entry_count > limits.max_files:
                raise SandboxError(
                    "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
                    "Sandbox output exceeds the entry-count limit",
                    http_status=413,
                )
            candidate = directory_path / name
            directory_relative = _normalize_relative_path(
                candidate.relative_to(root).as_posix(),
                limits,
                error_code="SANDBOX_OUTPUT_INVALID",
            )
            if directory_relative in seen_paths:
                raise SandboxError(
                    "SANDBOX_OUTPUT_INVALID",
                    "Sandbox output contains duplicate normalized paths",
                )
            seen_paths.add(directory_relative)
            if candidate.is_symlink():
                raise SandboxError(
                    "SANDBOX_OUTPUT_INVALID",
                    "Sandbox output contains a symbolic link",
                )
        for name in file_names:
            entry_count += 1
            if entry_count > limits.max_files:
                raise SandboxError(
                    "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
                    "Sandbox output exceeds the entry-count limit",
                    http_status=413,
                )
            candidate = directory_path / name
            raw_relative = candidate.relative_to(root).as_posix()
            relative = _normalize_relative_path(
                raw_relative,
                limits,
                error_code="SANDBOX_OUTPUT_INVALID",
            )
            if relative in seen_paths:
                raise SandboxError(
                    "SANDBOX_OUTPUT_INVALID",
                    "Sandbox output contains duplicate normalized paths",
                )
            seen_paths.add(relative)
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise SandboxError(
                    "SANDBOX_OUTPUT_INVALID",
                    "Sandbox output contains a link or special file",
                )
            if metadata.st_size > limits.max_file_bytes:
                raise SandboxError(
                    "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
                    "Sandbox output contains an oversized file",
                    http_status=413,
                )
            total_bytes += metadata.st_size
            if total_bytes > limits.max_total_bytes:
                raise SandboxError(
                    "SANDBOX_OUTPUT_LIMIT_EXCEEDED",
                    "Sandbox output exceeds the byte limit",
                    http_status=413,
                )
            files.append(
                _OutputFile(
                    relative_path=relative,
                    path=candidate,
                    size_bytes=metadata.st_size,
                    executable=bool(metadata.st_mode & 0o111),
                )
            )
    files.sort(key=lambda item: item.relative_path.encode("utf-8"))
    return files


def _normalize_relative_path(
    name: str,
    limits: ArchiveLimits,
    *,
    error_code: str,
) -> str:
    relative = unicodedata.normalize("NFC", name)
    path = PurePosixPath(relative)
    if (
        not relative
        or path.is_absolute()
        or relative.startswith("/")
        or "\\" in relative
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
        or any(ord(character) < 32 or ord(character) == 127 for character in relative)
    ):
        raise SandboxError(error_code, "Archive contains an invalid relative path")
    try:
        encoded = relative.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise SandboxError(
            error_code,
            "Archive contains an invalid Unicode path",
        ) from exc
    if len(encoded) > limits.max_path_length:
        raise SandboxError(error_code, "Archive contains an overlong path")
    if len(path.parts) > limits.max_path_depth:
        raise SandboxError(error_code, "Archive contains an over-deep path")
    return relative


def _mkdir_chain(root: Path, target: Path) -> None:
    if not target.is_relative_to(root):
        raise _snapshot_invalid("Archive path escapes its root")
    relative = target.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        try:
            current.mkdir()
        except FileExistsError:
            metadata = current.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise _snapshot_invalid("Archive has conflicting paths")


def _copy_limited(source, destination, expected_size: int) -> int:  # noqa: ANN001
    remaining = expected_size
    copied = 0
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            break
        destination.write(chunk)
        copied += len(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise _snapshot_invalid("Snapshot archive member exceeds its declared size")
    return copied


def _snapshot_invalid(message: str) -> SandboxError:
    return SandboxError("SANDBOX_SNAPSHOT_INVALID", message)
