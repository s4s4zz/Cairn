from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
import unicodedata
import zipfile


_CHUNK_SIZE = 1024 * 1024
_CLASS_MAGIC = b"\xca\xfe\xba\xbe"
_ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
@dataclass(frozen=True, slots=True)
class BinaryInventoryLimits:
    max_nesting_depth: int = 4
    max_entries: int = 100_000
    max_total_uncompressed_bytes: int = 512 * 1024 * 1024
    max_entry_bytes: int = 64 * 1024 * 1024
    max_class_bytes: int = 32 * 1024 * 1024
    max_staged_class_bytes: int = 128 * 1024 * 1024
    max_archive_bytes: int = 512 * 1024 * 1024
    max_compression_ratio: int = 200
    max_path_bytes: int = 4096
    max_path_depth: int = 128
    target_java_version: int = 17


class BinaryInventoryFailure(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


@dataclass(slots=True)
class _State:
    limits: BinaryInventoryLimits
    scratch: Path
    class_output: Path | None = None
    entry_count: int = 0
    expanded_bytes: int = 0
    components: list[dict[str, object]] = field(default_factory=list)
    entries: list[dict[str, object]] = field(default_factory=list)
    resources: list[dict[str, object]] = field(default_factory=list)
    coverage_gaps: list[dict[str, object]] = field(default_factory=list)
    logical_paths: set[str] = field(default_factory=set)
    staged_class_bytes: int = 0


@dataclass(frozen=True, slots=True)
class StagedClass:
    staged_name: str
    logical_path: str
    container_path: str | None
    entry_path: str
    sha256: str


def build_binary_inventory(
    root: Path,
    *,
    scratch: Path | None = None,
    limits: BinaryInventoryLimits | None = None,
    class_output: Path | None = None,
) -> dict[str, object]:
    """Inventory JVM inputs without extracting or loading target classes."""

    root = root.resolve()
    if not root.is_dir():
        raise BinaryInventoryFailure(
            "BINARY_INPUT_UNAVAILABLE",
            "binary inventory root is unavailable",
        )
    selected_limits = limits or BinaryInventoryLimits()
    scratch_root = (scratch or root).resolve()
    scratch_root.mkdir(parents=True, exist_ok=True)
    if class_output is not None:
        class_output.mkdir(parents=True, exist_ok=False)
        resolved_class_output = class_output.resolve()
    else:
        resolved_class_output = None
    state = _State(selected_limits, scratch_root, resolved_class_output)

    supported_inputs = 0
    for path in _regular_files(root):
        relative = _relative_path(root, path, selected_limits)
        size = path.stat().st_size
        if size > selected_limits.max_archive_bytes:
            if _peek(path, 4) in _ZIP_MAGICS:
                raise BinaryInventoryFailure(
                    "BINARY_ARCHIVE_TOO_LARGE",
                    "binary archive exceeds the configured size limit",
                )
            continue
        prefix = _peek(path, 10)
        if _class_header(prefix) is not None:
            supported_inputs += 1
            if size > selected_limits.max_class_bytes:
                state.coverage_gaps.append(
                    {
                        "logical_path": relative,
                        "reason_code": "CLASSFILE_SIZE_LIMIT",
                        "detail": "standalone classfile exceeds the indexing size limit",
                    }
                )
                continue
            digest = _sha256_path(path)
            record = _record_class(
                state,
                logical_path=relative,
                container_path=None,
                entry_path=relative,
                sha256=digest,
                size_bytes=size,
                header=prefix,
                archive_depth=0,
            )
            with path.open("rb") as source:
                _stage_class(state, record, source)
            continue
        if prefix[:4] not in _ZIP_MAGICS:
            continue
        try:
            with path.open("rb") as stream:
                if _visit_archive(
                    state,
                    stream,
                    logical_path=relative,
                    sha256=_sha256_path(path),
                    size_bytes=size,
                    depth=0,
                ):
                    supported_inputs += 1
        except zipfile.BadZipFile as exc:
            raise BinaryInventoryFailure(
                "BINARY_ARCHIVE_INVALID",
                "binary input has an invalid ZIP central directory",
            ) from exc

    if supported_inputs == 0:
        raise BinaryInventoryFailure(
            "NO_SUPPORTED_JVM_INPUT",
            "snapshot does not contain a valid classfile or JVM archive",
        )

    components = sorted(
        state.components,
        key=lambda item: str(item["logical_path"]).encode("utf-8"),
    )
    entries = sorted(
        state.entries,
        key=lambda item: str(item["logical_path"]).encode("utf-8"),
    )
    resources = sorted(
        state.resources,
        key=lambda item: str(item["logical_path"]).encode("utf-8"),
    )
    gaps = sorted(
        state.coverage_gaps,
        key=lambda item: (
            str(item.get("logical_path", "")).encode("utf-8"),
            str(item.get("reason_code", "")),
        ),
    )
    return {
        "contract": "cairn-binary-inventory-v1",
        "target_java_version": selected_limits.target_java_version,
        "components": components,
        "entries": entries,
        "resources": resources,
        "coverage_gaps": gaps,
        "archive_count": len(components),
        "class_entry_count": sum(item["kind"] == "class" for item in entries),
        "selected_class_count": sum(
            item["kind"] == "class" and item.get("selected", True)
            for item in entries
        ),
        "expanded_entry_count": state.entry_count,
        "expanded_bytes": state.expanded_bytes,
        "sbom": _cyclonedx(components),
    }


def _regular_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        parent = Path(directory)
        retained: list[str] = []
        for name in directory_names:
            candidate = parent / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise BinaryInventoryFailure(
                    "BINARY_TREE_SPECIAL_FILE",
                    "binary input tree contains an unsupported directory entry",
                )
            retained.append(name)
        directory_names[:] = retained
        for name in file_names:
            candidate = parent / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise BinaryInventoryFailure(
                    "BINARY_TREE_SPECIAL_FILE",
                    "binary input tree contains an unsupported file entry",
                )
            files.append(candidate)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix().encode("utf-8"))


def _relative_path(root: Path, path: Path, limits: BinaryInventoryLimits) -> str:
    raw = path.relative_to(root).as_posix()
    normalized = unicodedata.normalize("NFC", raw)
    if normalized != raw:
        raise BinaryInventoryFailure(
            "BINARY_PATH_NOT_NORMALIZED",
            "binary input path is not NFC-normalized",
        )
    return _validate_path(normalized, limits)


def _validate_path(value: str, limits: BinaryInventoryLimits) -> str:
    if (
        not value
        or value.startswith("/")
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_INVALID_PATH",
            "archive contains an invalid member path",
        )
    path = PurePosixPath(value)
    if (
        any(part in {"", ".", ".."} for part in path.parts)
        or any(part.endswith("!") for part in path.parts)
        or (path.parts and ":" in path.parts[0])
        or path.as_posix() != value
    ):
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_PATH_ESCAPE",
            "archive member path is not a normalized relative path",
        )
    if len(value.encode("utf-8")) > limits.max_path_bytes:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_PATH_TOO_LONG",
            "archive member path exceeds the configured length limit",
        )
    if len(path.parts) > limits.max_path_depth:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_PATH_TOO_DEEP",
            "archive member path exceeds the configured depth limit",
        )
    return value


def _normalized_members(
    archive: zipfile.ZipFile,
    limits: BinaryInventoryLimits,
) -> list[tuple[str, zipfile.ZipInfo]]:
    normalized: list[tuple[str, zipfile.ZipInfo]] = []
    seen: dict[str, bool] = {}
    if len(archive.filelist) > limits.max_entries:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_TOO_MANY_ENTRIES",
            "archive exceeds the configured entry count limit",
        )
    for info in archive.filelist:
        raw = unicodedata.normalize("NFC", info.filename)
        if raw != info.filename:
            rendered = raw[:-1] if raw.endswith("/") else raw
            if rendered in seen:
                raise BinaryInventoryFailure(
                    "BINARY_ARCHIVE_DUPLICATE_PATH",
                    "archive contains duplicate Unicode-normalized paths",
                )
        is_directory = info.is_dir()
        rendered = raw[:-1] if is_directory and raw.endswith("/") else raw
        rendered = _validate_path(rendered, limits)
        if rendered in seen:
            raise BinaryInventoryFailure(
                "BINARY_ARCHIVE_DUPLICATE_PATH",
                "archive contains duplicate normalized paths",
            )
        seen[rendered] = is_directory
        _validate_member_type(info)
        normalized.append((rendered, info))

    files = {path for path, info in normalized if not info.is_dir()}
    directories = {path for path, info in normalized if info.is_dir()}
    for path in files:
        parts = PurePosixPath(path).parts
        for length in range(1, len(parts)):
            parent = "/".join(parts[:length])
            if parent in files:
                raise BinaryInventoryFailure(
                    "BINARY_ARCHIVE_PATH_COLLISION",
                    "archive contains a file/directory path collision",
                )
            directories.add(parent)
        if path in directories:
            raise BinaryInventoryFailure(
                "BINARY_ARCHIVE_PATH_COLLISION",
                "archive contains a file/directory path collision",
            )
    return sorted(normalized, key=lambda item: item[0].encode("utf-8"))


def _validate_member_type(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_ENCRYPTED",
            "encrypted archive members are not supported",
        )
    member_type = stat.S_IFMT(info.external_attr >> 16) if info.create_system == 3 else 0
    if member_type == stat.S_IFLNK:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_SYMLINK",
            "archive contains a symbolic link",
        )
    if member_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_SPECIAL_FILE",
            "archive contains an unsupported special file",
        )


def _visit_archive(
    state: _State,
    stream: io.BufferedIOBase,
    *,
    logical_path: str,
    sha256: str,
    size_bytes: int,
    depth: int,
) -> bool:
    if depth > state.limits.max_nesting_depth:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_NESTING_TOO_DEEP",
            "nested archive exceeds the configured depth limit",
        )
    if size_bytes > state.limits.max_archive_bytes:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_TOO_LARGE",
            "nested archive exceeds the configured size limit",
        )
    component: dict[str, object] = {
        "logical_path": logical_path,
        "sha256": sha256,
        "size_bytes": size_bytes,
        "depth": depth,
        "kind": "zip",
        "manifest": {},
        "coordinates": [],
        "signature_metadata_present": False,
        "signature_verified": False,
        "multi_release": False,
    }
    try:
        with zipfile.ZipFile(stream) as archive:
            members = _normalized_members(archive, state.limits)
            direct_classes: list[dict[str, object]] = []
            manifest: dict[str, str] = {}
            coordinates: list[dict[str, str]] = []
            signed = False
            has_web_inf = False
            has_application_xml = False
            has_supported_descendant = False
            has_class_candidate = False
            for entry_path, info in members:
                state.entry_count += 1
                if state.entry_count > state.limits.max_entries:
                    raise BinaryInventoryFailure(
                        "BINARY_ARCHIVE_TOO_MANY_ENTRIES",
                        "nested archives exceed the configured entry count limit",
                    )
                if info.is_dir():
                    continue
                _validate_declared_size(state, info)
                nested_logical = f"{logical_path}!/{entry_path}"
                lowered = entry_path.lower()
                # Archive type is structural. A Servlet 3+ WAR is allowed to
                # omit web.xml, and its only WEB-INF members may be classes or
                # nested libraries that take an early branch below.
                if lowered.startswith("web-inf/"):
                    has_web_inf = True
                if lowered == "meta-inf/application.xml":
                    has_application_xml = True
                if len(nested_logical.encode("utf-8")) > state.limits.max_path_bytes:
                    raise BinaryInventoryFailure(
                        "BINARY_ARCHIVE_PATH_TOO_LONG",
                        "nested archive logical path exceeds the configured limit",
                    )
                with _read_member(state, archive, info) as payload:
                    prefix = payload.read(10)
                    payload.seek(0)
                    digest = _sha256_stream(payload)
                    payload.seek(0)
                    header = _class_header(prefix)
                    if header is not None:
                        has_class_candidate = True
                        if info.file_size > state.limits.max_class_bytes:
                            state.coverage_gaps.append(
                                {
                                    "logical_path": nested_logical,
                                    "reason_code": "CLASSFILE_SIZE_LIMIT",
                                    "detail": "classfile exceeds the indexing size limit",
                                }
                            )
                            continue
                        record = _record_class(
                            state,
                            logical_path=nested_logical,
                            container_path=logical_path,
                            entry_path=entry_path,
                            sha256=digest,
                            size_bytes=info.file_size,
                            header=prefix,
                            archive_depth=depth,
                        )
                        _stage_class(state, record, payload)
                        direct_classes.append(record)
                        continue
                    if entry_path.lower().endswith(".class"):
                        state.coverage_gaps.append(
                            {
                                "logical_path": nested_logical,
                                "reason_code": "CLASSFILE_INVALID",
                                "detail": "entry has a class suffix but no valid classfile header",
                            }
                        )
                    if prefix[:4] in _ZIP_MAGICS:
                        try:
                            nested_supported = _visit_archive(
                                state,
                                payload,
                                logical_path=nested_logical,
                                sha256=digest,
                                size_bytes=info.file_size,
                                depth=depth + 1,
                            )
                        except zipfile.BadZipFile:
                            state.coverage_gaps.append(
                                {
                                    "logical_path": nested_logical,
                                    "reason_code": "NESTED_ARCHIVE_INVALID",
                                    "detail": "nested ZIP magic has an invalid central directory",
                                }
                            )
                        else:
                            if nested_supported:
                                has_supported_descendant = True
                            else:
                                state.coverage_gaps.append(
                                    {
                                        "logical_path": nested_logical,
                                        "reason_code": "NESTED_ARCHIVE_UNSUPPORTED",
                                        "detail": "nested ZIP contains no supported JVM input",
                                    }
                                )
                        continue
                    if lowered == "meta-inf/manifest.mf":
                        manifest = _manifest(payload.read(state.limits.max_entry_bytes + 1))
                    if lowered.startswith("meta-inf/maven/") and lowered.endswith(
                        "/pom.properties"
                    ):
                        coordinate = _properties(
                            payload.read(state.limits.max_entry_bytes + 1)
                        )
                        if coordinate:
                            coordinates.append(coordinate)
                    if lowered.startswith("meta-inf/") and lowered.endswith(
                        (".sf", ".rsa", ".dsa", ".ec")
                    ):
                        signed = True
                    resource_kind = _resource_kind(entry_path)
                    if resource_kind is not None:
                        outer_container, canonical_entry = _location_parts(
                            nested_logical
                        )
                        resource = {
                            "logical_path": nested_logical,
                            "container_path": outer_container,
                            "entry_path": canonical_entry,
                            "kind": resource_kind,
                            "sha256": digest,
                            "size_bytes": info.file_size,
                        }
                        state.resources.append(resource)
                        _append_entry(
                            state,
                            {
                                **resource,
                                "kind": "resource",
                                "resource_kind": resource_kind,
                                "archive_depth": depth,
                            }
                        )
            multi_release = manifest.get("Multi-Release", "").lower() == "true"
            _select_multi_release(
                state,
                direct_classes,
                enabled=multi_release,
                archive_logical_path=logical_path,
            )
            if has_application_xml:
                archive_kind = "ear"
            elif has_web_inf:
                archive_kind = "war"
            elif has_class_candidate or manifest:
                archive_kind = "jar"
            else:
                archive_kind = "zip"
            component.update(
                {
                    "kind": archive_kind,
                    "manifest": manifest,
                    "coordinates": sorted(
                        coordinates,
                        key=lambda item: (
                            item.get("groupId", ""),
                            item.get("artifactId", ""),
                            item.get("version", ""),
                        ),
                    ),
                    "signature_metadata_present": signed,
                    "signature_verified": False,
                    "multi_release": multi_release,
                }
            )
            supported = bool(
                direct_classes
                or has_class_candidate
                or manifest
                or has_web_inf
                or has_application_xml
                or has_supported_descendant
            )
            if supported:
                _append_component(state, component)
            return supported
    except BinaryInventoryFailure:
        raise
    except NotImplementedError as exc:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_COMPRESSION_UNSUPPORTED",
            "archive uses an unsupported compression method",
        ) from exc
    except MemoryError as exc:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_RESOURCE_LIMIT",
            "archive central directory exceeded the memory budget",
        ) from exc


def _validate_declared_size(state: _State, info: zipfile.ZipInfo) -> None:
    if info.file_size > state.limits.max_entry_bytes:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_ENTRY_TOO_LARGE",
            "archive entry exceeds the configured size limit",
        )
    state.expanded_bytes += info.file_size
    if state.expanded_bytes > state.limits.max_total_uncompressed_bytes:
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_EXPANDED_TOO_LARGE",
            "nested archives exceed the total expanded byte limit",
        )
    if (
        info.file_size > 0
        and (
            info.compress_size == 0
            or info.file_size
            > info.compress_size * state.limits.max_compression_ratio
        )
    ):
        raise BinaryInventoryFailure(
            "BINARY_ARCHIVE_COMPRESSION_RATIO",
            "archive entry exceeds the configured compression ratio",
        )


def _read_member(
    state: _State,
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> tempfile.SpooledTemporaryFile[bytes]:
    payload = tempfile.SpooledTemporaryFile(
        max_size=4 * 1024 * 1024,
        mode="w+b",
        dir=state.scratch,
    )
    size = 0
    try:
        with archive.open(info, "r") as source:
            while chunk := source.read(_CHUNK_SIZE):
                size += len(chunk)
                if size > info.file_size or size > state.limits.max_entry_bytes:
                    raise BinaryInventoryFailure(
                        "BINARY_ARCHIVE_SIZE_MISMATCH",
                        "archive entry exceeded its declared size",
                    )
                payload.write(chunk)
        if size != info.file_size:
            raise BinaryInventoryFailure(
                "BINARY_ARCHIVE_SIZE_MISMATCH",
                "archive entry did not match its declared size",
            )
        payload.seek(0)
        return payload
    except Exception:
        payload.close()
        raise


def _record_class(
    state: _State,
    *,
    logical_path: str,
    container_path: str | None,
    entry_path: str,
    sha256: str,
    size_bytes: int,
    header: bytes,
    archive_depth: int,
) -> dict[str, object]:
    class_header = _class_header(header)
    assert class_header is not None
    minor, major, constant_pool_count = class_header
    canonical_container, canonical_entry = _location_parts(logical_path)
    record: dict[str, object] = {
        "logical_path": logical_path,
        "container_path": canonical_container,
        "entry_path": canonical_entry,
        "kind": "class",
        "sha256": sha256,
        "size_bytes": size_bytes,
        "archive_depth": archive_depth,
        "classfile_major": major,
        "classfile_minor": minor,
        "constant_pool_count": constant_pool_count,
        "validation": "header-only",
        "multi_release_version": None,
        "selected": True,
    }
    _append_entry(state, record)
    return record


def stage_binary_classes(
    root: Path,
    destination: Path,
    *,
    scratch: Path | None = None,
    limits: BinaryInventoryLimits | None = None,
) -> tuple[dict[str, object], list[StagedClass]]:
    inventory = build_binary_inventory(
        root,
        scratch=scratch,
        limits=limits,
        class_output=destination,
    )
    staged: list[StagedClass] = []
    selected_names: set[str] = set()
    for entry in inventory["entries"]:
        if entry["kind"] != "class" or not entry["selected"]:
            continue
        staged_name = _staged_name(str(entry["logical_path"]))
        selected_names.add(staged_name)
        staged.append(
            StagedClass(
                staged_name=staged_name,
                logical_path=str(entry["logical_path"]),
                container_path=(
                    str(entry["container_path"])
                    if entry["container_path"] is not None
                    else None
                ),
                entry_path=str(entry["entry_path"]),
                sha256=str(entry["sha256"]),
            )
        )
    for path in destination.iterdir():
        if path.is_file() and path.name not in selected_names:
            path.unlink()
    return inventory, sorted(staged, key=lambda item: item.logical_path.encode("utf-8"))


def _stage_class(
    state: _State,
    record: dict[str, object],
    source: io.BufferedIOBase,
) -> None:
    if state.class_output is None:
        return
    state.staged_class_bytes += int(record["size_bytes"])
    if state.staged_class_bytes > state.limits.max_staged_class_bytes:
        raise BinaryInventoryFailure(
            "BINARY_CLASS_STAGING_LIMIT",
            "selected classfiles exceed the cumulative staging limit",
        )
    destination = state.class_output / _staged_name(str(record["logical_path"]))
    source.seek(0)
    digest = hashlib.sha256()
    size = 0
    with destination.open("xb") as output:
        while chunk := source.read(_CHUNK_SIZE):
            size += len(chunk)
            if size > state.limits.max_entry_bytes:
                raise BinaryInventoryFailure(
                    "BINARY_CLASS_TOO_LARGE",
                    "classfile exceeds the configured staging size limit",
                )
            digest.update(chunk)
            output.write(chunk)
    source.seek(0)
    if digest.hexdigest() != record["sha256"] or size != record["size_bytes"]:
        raise BinaryInventoryFailure(
            "BINARY_CLASS_STAGING_MISMATCH",
            "staged classfile does not match its inventory identity",
        )


def _staged_name(logical_path: str) -> str:
    return hashlib.sha256(logical_path.encode("utf-8")).hexdigest() + ".class"


def _location_parts(logical_path: str) -> tuple[str | None, str]:
    container, separator, entry = logical_path.partition("!/")
    if not separator:
        return None, logical_path
    return container, entry


def _append_component(state: _State, component: dict[str, object]) -> None:
    _claim_logical_path(state, str(component["logical_path"]))
    state.components.append(component)


def _append_entry(state: _State, entry: dict[str, object]) -> None:
    _claim_logical_path(state, str(entry["logical_path"]))
    state.entries.append(entry)


def _claim_logical_path(state: _State, logical_path: str) -> None:
    if logical_path in state.logical_paths:
        raise BinaryInventoryFailure(
            "BINARY_LOGICAL_PATH_COLLISION",
            "binary inventory produced a duplicate logical path",
        )
    state.logical_paths.add(logical_path)


def _class_header(value: bytes) -> tuple[int, int, int] | None:
    if len(value) < 10 or value[:4] != _CLASS_MAGIC:
        return None
    minor = int.from_bytes(value[4:6], "big")
    major = int.from_bytes(value[6:8], "big")
    constant_pool_count = int.from_bytes(value[8:10], "big")
    if major < 45 or major > 100 or constant_pool_count < 1:
        return None
    return minor, major, constant_pool_count


def _select_multi_release(
    state: _State,
    records: list[dict[str, object]],
    *,
    enabled: bool,
    archive_logical_path: str,
) -> None:
    groups: dict[str, list[tuple[int, dict[str, object]]]] = {}
    bases: dict[str, dict[str, object]] = {}
    prefix = "META-INF/versions/"
    member_prefix = f"{archive_logical_path}!/"
    for record in records:
        logical_path = str(record["logical_path"])
        if not logical_path.startswith(member_prefix):
            raise BinaryInventoryFailure(
                "BINARY_LOGICAL_PATH_MISMATCH",
                "class entry does not belong to its containing archive",
            )
        path = logical_path[len(member_prefix) :]
        if not path.startswith(prefix):
            bases[path] = record
            continue
        remainder = path[len(prefix) :]
        version, separator, base_path = remainder.partition("/")
        if not separator or not version.isdigit() or not base_path:
            record["selected"] = False
            continue
        parsed_version = int(version)
        record["multi_release_version"] = parsed_version
        record["selected"] = False
        groups.setdefault(base_path, []).append((parsed_version, record))

    for base_path, versions in groups.items():
        eligible = [item for item in versions if enabled and item[0] <= state.limits.target_java_version]
        selected_version = max(eligible, default=None, key=lambda item: item[0])
        base = bases.get(base_path)
        if base is not None:
            base["selected"] = selected_version is None
        if selected_version is not None:
            selected_version[1]["selected"] = True
        for version, record in versions:
            if record.get("selected"):
                continue
            state.coverage_gaps.append(
                {
                    "logical_path": record["logical_path"],
                    "reason_code": "MULTI_RELEASE_CLASS_SHADOWED",
                    "detail": (
                        f"class version {version} is not selected for target Java "
                        f"{state.limits.target_java_version}"
                    ),
                }
            )


def _resource_kind(path: str) -> str | None:
    lowered = path.lower()
    if lowered.startswith("meta-inf/services/"):
        return "service-registration"
    if lowered == "meta-inf/manifest.mf":
        return "manifest"
    if lowered.endswith(("web.xml", "application.xml")):
        return "deployment-descriptor"
    if lowered.endswith((".jsp", ".jspx")):
        return "jsp"
    if lowered.endswith(".xml"):
        return "xml"
    if lowered.endswith((".properties", ".yaml", ".yml")):
        return "configuration"
    return None


def _manifest(raw: bytes) -> dict[str, str]:
    if len(raw) == 0 or b"\x00" in raw:
        return {}
    text = raw.decode("utf-8", errors="replace").replace("\r\n", "\n")
    unfolded: list[str] = []
    for line in text.split("\n"):
        if line.startswith(" ") and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    result: dict[str, str] = {}
    for line in unfolded:
        key, separator, value = line.partition(":")
        if separator and key and len(key) <= 128:
            result[key] = value.lstrip()[:4096]
    return dict(sorted(result.items()))


def _properties(raw: bytes) -> dict[str, str]:
    if b"\x00" in raw:
        return {}
    values: dict[str, str] = {}
    for line in raw.decode("iso-8859-1", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "!")):
            continue
        key, separator, value = stripped.partition("=")
        if not separator:
            key, separator, value = stripped.partition(":")
        if separator and key in {"groupId", "artifactId", "version"}:
            values[key] = value.strip()[:512]
    if "artifactId" not in values:
        return {}
    return values


def _cyclonedx(components: list[dict[str, object]]) -> dict[str, object]:
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "components": [
            {
                "type": "library",
                "bom-ref": (
                    f"urn:cairn:component:{component['sha256']}:"
                    f"{hashlib.sha256(str(component['logical_path']).encode('utf-8')).hexdigest()[:16]}"
                ),
                "name": str(component["logical_path"]),
                "hashes": [
                    {"alg": "SHA-256", "content": str(component["sha256"])}
                ],
                "properties": [
                    {
                        "name": "cairn:archive-kind",
                        "value": str(component["kind"]),
                    },
                    {
                        "name": "cairn:logical-path",
                        "value": str(component["logical_path"]),
                    },
                ],
            }
            for component in components
        ],
    }


def _peek(path: Path, size: int) -> bytes:
    with path.open("rb") as stream:
        return stream.read(size)


def _sha256_path(path: Path) -> str:
    with path.open("rb") as stream:
        return _sha256_stream(stream)


def _sha256_stream(stream: io.BufferedIOBase) -> str:
    digest = hashlib.sha256()
    while chunk := stream.read(_CHUNK_SIZE):
        digest.update(chunk)
    return digest.hexdigest()
