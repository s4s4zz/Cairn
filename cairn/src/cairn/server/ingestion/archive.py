from __future__ import annotations

import os
from pathlib import Path, PurePosixPath
import stat
import unicodedata
import zipfile

from cairn.server.ingestion.errors import IngestionFailure
from cairn.server.ingestion.limits import IngestionLimits


_COPY_CHUNK_SIZE = 1024 * 1024


def _normalized_member_path(name: str, limits: IngestionLimits) -> PurePosixPath:
    if "\x00" in name or "\\" in name:
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_INVALID_PATH",
            "Archive contains an invalid member path",
        )
    normalized = unicodedata.normalize("NFC", name)
    if any(ord(character) < 32 for character in normalized):
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_INVALID_PATH",
            "Archive contains control characters in a member path",
        )
    if normalized.startswith("/") or normalized.startswith("//"):
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_PATH_ESCAPE",
            "Archive contains an absolute member path",
        )
    path = PurePosixPath(normalized)
    if (
        not path.parts
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_PATH_ESCAPE",
            "Archive contains a path outside the extraction root",
        )
    rendered = path.as_posix()
    if len(rendered.encode("utf-8")) > limits.max_path_length:
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_PATH_TOO_LONG",
            "Archive member path exceeds the configured length limit",
        )
    if len(path.parts) > limits.max_path_depth:
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_PATH_TOO_DEEP",
            "Archive member path exceeds the configured depth limit",
        )
    return path


def _member_type(info: zipfile.ZipInfo) -> int:
    if info.create_system != 3:
        return 0
    return stat.S_IFMT(info.external_attr >> 16)


def extract_zip_archive(
    archive_path: Path,
    destination: Path,
    limits: IngestionLimits,
) -> None:
    """Extract a ZIP without permitting paths or file types to escape."""
    try:
        archive_size = archive_path.stat().st_size
    except OSError as exc:
        raise IngestionFailure(
            "SNAPSHOT_UPLOAD_UNAVAILABLE",
            "Uploaded archive is unavailable",
            http_status=500,
        ) from exc
    if archive_size > limits.upload_max_bytes:
        raise IngestionFailure(
            "SNAPSHOT_UPLOAD_TOO_LARGE",
            "Uploaded archive exceeds the configured size limit",
            http_status=413,
        )

    destination = destination.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    seen_paths: set[str] = set()
    file_count = 0
    declared_total = 0
    extracted_total = 0
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) > limits.max_files * 2:
                raise IngestionFailure(
                    "SNAPSHOT_ARCHIVE_TOO_MANY_ENTRIES",
                    "Archive exceeds the configured entry count limit",
                    http_status=413,
                )
            for info in members:
                relative_path = _normalized_member_path(info.filename, limits)
                rendered_path = relative_path.as_posix().rstrip("/")
                if not rendered_path:
                    continue
                if rendered_path in seen_paths:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_DUPLICATE_PATH",
                        "Archive contains duplicate normalized paths",
                    )
                seen_paths.add(rendered_path)

                member_type = _member_type(info)
                is_directory = info.is_dir()
                if member_type == stat.S_IFLNK:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_SYMLINK",
                        "Archive contains a symbolic link",
                    )
                if member_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_SPECIAL_FILE",
                        "Archive contains an unsupported special file",
                    )
                if info.flag_bits & 0x1:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_ENCRYPTED",
                        "Encrypted archive members are not supported",
                    )

                target = destination.joinpath(*relative_path.parts)
                if not target.resolve(strict=False).is_relative_to(destination):
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_PATH_ESCAPE",
                        "Archive contains a path outside the extraction root",
                    )
                if is_directory:
                    target.mkdir(parents=True, exist_ok=True)
                    continue

                file_count += 1
                if file_count > limits.max_files:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_TOO_MANY_FILES",
                        "Archive exceeds the configured file count limit",
                        http_status=413,
                    )
                if info.file_size > limits.max_file_bytes:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_FILE_TOO_LARGE",
                        "Archive contains a file larger than the configured limit",
                        http_status=413,
                    )
                declared_total += info.file_size
                if declared_total > limits.max_total_bytes:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_EXPANDED_TOO_LARGE",
                        "Archive expands beyond the configured size limit",
                        http_status=413,
                    )
                if (
                    info.file_size > 0
                    and (
                        info.compress_size == 0
                        or info.file_size
                        > info.compress_size * limits.max_compression_ratio
                    )
                ):
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_COMPRESSION_RATIO",
                        "Archive member exceeds the configured compression ratio",
                        http_status=413,
                    )

                target.parent.mkdir(parents=True, exist_ok=True)
                file_size = 0
                with archive.open(info, "r") as source, target.open("xb") as output:
                    while chunk := source.read(_COPY_CHUNK_SIZE):
                        file_size += len(chunk)
                        extracted_total += len(chunk)
                        if file_size > limits.max_file_bytes:
                            raise IngestionFailure(
                                "SNAPSHOT_ARCHIVE_FILE_TOO_LARGE",
                                "Extracted file exceeds the configured limit",
                                http_status=413,
                            )
                        if extracted_total > limits.max_total_bytes:
                            raise IngestionFailure(
                                "SNAPSHOT_ARCHIVE_EXPANDED_TOO_LARGE",
                                "Archive expands beyond the configured size limit",
                                http_status=413,
                            )
                        output.write(chunk)
                if file_size != info.file_size:
                    raise IngestionFailure(
                        "SNAPSHOT_ARCHIVE_SIZE_MISMATCH",
                        "Archive member size did not match its metadata",
                    )
                executable = bool((info.external_attr >> 16) & 0o111)
                os.chmod(target, 0o700 if executable else 0o600)
    except IngestionFailure:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise IngestionFailure(
            "SNAPSHOT_ARCHIVE_INVALID",
            "Uploaded file is not a valid supported ZIP archive",
        ) from exc
