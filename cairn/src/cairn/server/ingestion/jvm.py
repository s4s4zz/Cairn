from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
import stat
import unicodedata
import zipfile

from cairn.server.ingestion.errors import IngestionFailure
from cairn.server.ingestion.limits import IngestionLimits


_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
_MIN_CLASSFILE_SIZE = 24
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


class JvmArtifactKind(StrEnum):
    CLASS = "class"
    JAR = "jar"
    WAR = "war"
    EAR = "ear"


@dataclass(frozen=True, slots=True)
class JvmArtifact:
    kind: JvmArtifactKind
    media_type: str


def validate_transport_zip(path: Path, limits: IngestionLimits) -> None:
    """Confirm the upload is a bounded ZIP container without extracting it."""

    if not _has_magic(path, _ZIP_MAGICS) or not zipfile.is_zipfile(path):
        raise IngestionFailure(
            "UPLOAD_ARCHIVE_INVALID",
            "Source and directory uploads must be valid ZIP archives",
        )
    try:
        with zipfile.ZipFile(path) as archive:
            if len(archive.infolist()) > limits.max_files * 2:
                raise IngestionFailure(
                    "UPLOAD_ARCHIVE_TOO_MANY_ENTRIES",
                    "Uploaded archive exceeds the configured entry count limit",
                    http_status=413,
                )
    except IngestionFailure:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        raise IngestionFailure(
            "UPLOAD_ARCHIVE_INVALID",
            "Source and directory uploads must be valid ZIP archives",
        ) from exc


def detect_jvm_artifact(
    path: Path,
    limits: IngestionLimits,
    *,
    required: bool = False,
) -> JvmArtifact | None:
    """Recognize one class or ZIP-based JVM artifact without recursive expansion."""

    try:
        size = path.stat().st_size
    except OSError as exc:
        raise IngestionFailure(
            "JVM_INPUT_UNAVAILABLE",
            "JVM input is unavailable",
            http_status=500,
        ) from exc
    if size > limits.max_file_bytes:
        raise IngestionFailure(
            "JVM_INPUT_TOO_LARGE",
            "JVM input exceeds the configured single-file limit",
            http_status=413,
        )

    prefix = _prefix(path, 10)
    if prefix.startswith(_CLASS_MAGIC):
        return _detect_class(prefix, size)
    if prefix.startswith(_ZIP_MAGICS):
        artifact = _detect_zip_artifact(path, limits, required=required)
        if artifact is not None:
            return artifact
    if required:
        raise IngestionFailure(
            "NO_SUPPORTED_JVM_INPUT",
            "Upload is not a supported class, JAR, WAR, or EAR artifact",
        )
    return None


def _detect_class(header: bytes, size: int) -> JvmArtifact:
    if len(header) < 10 or size < _MIN_CLASSFILE_SIZE:
        raise IngestionFailure(
            "JVM_CLASS_INVALID",
            "Class input is truncated",
        )
    major_version = int.from_bytes(header[6:8], "big")
    constant_pool_count = int.from_bytes(header[8:10], "big")
    if major_version < 45 or constant_pool_count < 2:
        raise IngestionFailure(
            "JVM_CLASS_INVALID",
            "Class input has an invalid classfile header",
        )
    return JvmArtifact(JvmArtifactKind.CLASS, "application/java-vm")


def _detect_zip_artifact(
    path: Path,
    limits: IngestionLimits,
    *,
    required: bool,
) -> JvmArtifact | None:
    if not zipfile.is_zipfile(path):
        if required:
            raise IngestionFailure(
                "JVM_ARCHIVE_INVALID",
                "JVM archive has an invalid central directory",
            )
        return None

    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) > limits.max_files:
                raise IngestionFailure(
                    "JVM_ARCHIVE_TOO_MANY_ENTRIES",
                    "JVM archive exceeds the configured entry count limit",
                    http_status=413,
                )
            seen: set[str] = set()
            files: set[str] = set()
            directories: set[str] = set()
            declared_total = 0
            has_manifest = False
            has_class = False
            has_web_layout = False
            has_application_xml = False

            for info in members:
                rendered = _normalized_member_path(info.filename, limits)
                if rendered in seen:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_DUPLICATE_PATH",
                        "JVM archive contains duplicate normalized paths",
                    )
                seen.add(rendered)
                member_type = _member_type(info)
                if member_type == stat.S_IFLNK:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_SYMLINK",
                        "JVM archive contains a symbolic link",
                    )
                if member_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_SPECIAL_FILE",
                        "JVM archive contains an unsupported special file",
                    )
                if info.flag_bits & 0x1:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_ENCRYPTED",
                        "Encrypted JVM archive members are not supported",
                    )

                is_directory = info.is_dir()
                _record_path(rendered, is_directory, files, directories)
                if is_directory:
                    continue
                if info.file_size < 0 or info.file_size > limits.max_file_bytes:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_ENTRY_TOO_LARGE",
                        "JVM archive contains an oversized entry",
                        http_status=413,
                    )
                declared_total += info.file_size
                if declared_total > limits.max_total_bytes:
                    raise IngestionFailure(
                        "JVM_ARCHIVE_EXPANDED_TOO_LARGE",
                        "JVM archive expands beyond the configured size limit",
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
                        "JVM_ARCHIVE_COMPRESSION_RATIO",
                        "JVM archive entry exceeds the configured compression ratio",
                        http_status=413,
                    )

                upper = rendered.upper()
                has_manifest = has_manifest or upper == "META-INF/MANIFEST.MF"
                has_application_xml = (
                    has_application_xml or upper == "META-INF/APPLICATION.XML"
                )
                has_web_layout = has_web_layout or upper.startswith("WEB-INF/")
                if upper.endswith(".CLASS") and not has_class:
                    with archive.open(info, "r") as stream:
                        has_class = stream.read(4) == _CLASS_MAGIC

            if has_application_xml:
                return JvmArtifact(JvmArtifactKind.EAR, "application/java-archive")
            if has_web_layout:
                return JvmArtifact(JvmArtifactKind.WAR, "application/java-archive")
            if has_manifest or has_class:
                return JvmArtifact(JvmArtifactKind.JAR, "application/java-archive")
            if required:
                raise IngestionFailure(
                    "NO_SUPPORTED_JVM_INPUT",
                    "ZIP upload does not have class, JAR, WAR, or EAR structure",
                )
            return None
    except IngestionFailure:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        if required:
            raise IngestionFailure(
                "JVM_ARCHIVE_INVALID",
                "JVM archive has an invalid central directory",
            ) from exc
        return None


def _normalized_member_path(name: str, limits: IngestionLimits) -> str:
    if "\x00" in name or "\\" in name:
        raise IngestionFailure(
            "JVM_ARCHIVE_INVALID_PATH",
            "JVM archive contains an invalid member path",
        )
    normalized = unicodedata.normalize("NFC", name).rstrip("/")
    if not normalized or normalized.startswith("/"):
        raise IngestionFailure(
            "JVM_ARCHIVE_INVALID_PATH",
            "JVM archive contains an invalid member path",
        )
    path = PurePosixPath(normalized)
    if (
        any(ord(character) < 32 for character in normalized)
        or any(part in {"", ".", ".."} for part in path.parts)
        or ":" in path.parts[0]
    ):
        raise IngestionFailure(
            "JVM_ARCHIVE_INVALID_PATH",
            "JVM archive contains an invalid member path",
        )
    rendered = path.as_posix()
    if len(rendered.encode("utf-8")) > limits.max_path_length:
        raise IngestionFailure(
            "JVM_ARCHIVE_PATH_TOO_LONG",
            "JVM archive member path exceeds the configured length limit",
        )
    if len(path.parts) > limits.max_path_depth:
        raise IngestionFailure(
            "JVM_ARCHIVE_PATH_TOO_DEEP",
            "JVM archive member path exceeds the configured depth limit",
        )
    return rendered


def _record_path(
    path: str,
    is_directory: bool,
    files: set[str],
    directories: set[str],
) -> None:
    parents = list(PurePosixPath(path).parents)[:-1]
    if any(parent.as_posix() in files for parent in parents):
        raise IngestionFailure(
            "JVM_ARCHIVE_PATH_COLLISION",
            "JVM archive contains colliding file and directory paths",
        )
    if is_directory:
        if path in files:
            raise IngestionFailure(
                "JVM_ARCHIVE_PATH_COLLISION",
                "JVM archive contains colliding file and directory paths",
            )
        directories.add(path)
        return
    occupied = files | directories
    if path in directories or any(
        item.startswith(f"{path}/") for item in occupied
    ):
        raise IngestionFailure(
            "JVM_ARCHIVE_PATH_COLLISION",
            "JVM archive contains colliding file and directory paths",
        )
    files.add(path)


def _member_type(info: zipfile.ZipInfo) -> int:
    if info.create_system != 3:
        return 0
    return stat.S_IFMT(info.external_attr >> 16)


def _has_magic(path: Path, magics: tuple[bytes, ...]) -> bool:
    return _prefix(path, max(len(magic) for magic in magics)).startswith(magics)


def _prefix(path: Path, size: int) -> bytes:
    try:
        with path.open("rb") as stream:
            return stream.read(size)
    except OSError as exc:
        raise IngestionFailure(
            "JVM_INPUT_UNAVAILABLE",
            "JVM input is unavailable",
            http_status=500,
        ) from exc
