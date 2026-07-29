from __future__ import annotations

import base64
from collections.abc import Callable
from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess

from pydantic import ValidationError

from cairn.analysis.binary_inventory import StagedClass, stage_binary_classes
from cairn.analysis.contracts import (
    BytecodeCallRecord,
    BytecodeClassRecord,
    BytecodeFieldAccessRecord,
    BytecodeFieldRecord,
    BytecodeIndexGap,
    BytecodeMethodRecord,
    DecompiledViewRecord,
    ProgramIndexV2,
)


ASM_VERSION = "9.8"
BYTECODE_INDEXER_VERSION = "1.0.0"
CFR_VERSION = "0.152"
_MAX_JSONL_BYTES = 128 * 1024 * 1024
_MAX_JSONL_LINE_BYTES = 1024 * 1024
_MAX_RECORDS = 2_000_000
_MAX_DECOMPILED_CLASSES = 10_000
_MAX_DECOMPILED_VIEW_BYTES = 4 * 1024 * 1024
_MAX_DECOMPILED_TOTAL_BYTES = 128 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class BytecodeToolchain:
    java: str = "/opt/java/openjdk/bin/java"
    asm_jar: Path = Path("/opt/cairn/tools/asm-9.8.jar")
    helper_jar: Path = Path("/opt/cairn/tools/cairn-bytecode-indexer.jar")
    cfr_jar: Path = Path("/opt/cairn/tools/cfr-0.152.jar")


@dataclass(frozen=True, slots=True)
class ToolResult:
    exit_code: int | None
    reason_code: str | None = None


ToolExecutor = Callable[[list[str], Path, Path, int], ToolResult]


class BytecodeIndexFailure(ValueError):
    def __init__(self, reason_code: str, message: str) -> None:
        super().__init__(message)
        self.reason_code = reason_code
        self.message = message


def run_tool(
    argv: list[str],
    cwd: Path,
    log_path: Path,
    timeout_seconds: int,
) -> ToolResult:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    environment = {
        "HOME": str(cwd / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("wb") as log:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
        return ToolResult(completed.returncode)
    except subprocess.TimeoutExpired:
        return ToolResult(None, "BYTECODE_INDEX_TIMEOUT")
    except OSError:
        return ToolResult(None, "BYTECODE_INDEX_EXECUTION_FAILED")


def build_bytecode_index(
    source: Path,
    scratch: Path,
    output: Path,
    *,
    toolchain: BytecodeToolchain | None = None,
    executor: ToolExecutor = run_tool,
    decompiler_executor: ToolExecutor = run_tool,
    generate_decompiled_views: bool = True,
) -> ProgramIndexV2:
    selected_toolchain = toolchain or BytecodeToolchain()
    java = _resolve_java(selected_toolchain.java)
    _require_tool(selected_toolchain.asm_jar, "ASM_UNAVAILABLE")
    _require_tool(selected_toolchain.helper_jar, "BYTECODE_INDEXER_UNAVAILABLE")

    work = scratch / "bytecode-index"
    classes_root = work / "classes"
    work.mkdir(parents=True, exist_ok=False)
    output.mkdir(parents=True, exist_ok=True)
    inventory, staged = stage_binary_classes(
        source,
        classes_root,
        scratch=work,
    )
    mapping_path = work / "classes.tsv"
    mapping_path.write_text(
        "".join(
            "\t".join(
                (
                    item.sha256,
                    _base64url(item.staged_name),
                    _base64url(item.logical_path),
                    _base64url(item.container_path or ""),
                    _base64url(item.entry_path),
                )
            )
            + "\n"
            for item in staged
        ),
        encoding="utf-8",
    )
    raw_path = output / "asm-index.jsonl"
    log_path = output / "asm-index.log"
    classpath = os.pathsep.join(
        (str(selected_toolchain.helper_jar), str(selected_toolchain.asm_jar))
    )
    result = executor(
        [
            java,
            "-Xms32m",
            "-Xmx256m",
            "-cp",
            classpath,
            "dev.cairn.bytecode.BytecodeIndexer",
            str(classes_root),
            str(mapping_path),
            str(raw_path),
        ],
        work,
        log_path,
        900,
    )
    if result.reason_code is not None:
        raise BytecodeIndexFailure(result.reason_code, "ASM indexer did not complete")
    if result.exit_code != 0:
        raise BytecodeIndexFailure(
            "BYTECODE_INDEXER_EXIT_NONZERO",
            "ASM indexer returned a non-zero exit status",
        )
    if not raw_path.is_file() or raw_path.is_symlink():
        raise BytecodeIndexFailure(
            "BYTECODE_INDEX_OUTPUT_MISSING",
            "ASM indexer did not produce its JSONL result",
        )
    if raw_path.stat().st_size > _MAX_JSONL_BYTES:
        raise BytecodeIndexFailure(
            "BYTECODE_INDEX_OUTPUT_TOO_LARGE",
            "ASM index exceeds the configured size limit",
        )
    index = _parse_index(raw_path, staged, inventory)
    if not generate_decompiled_views:
        return index
    return _attach_decompiled_views(
        index,
        staged=staged,
        classes_root=classes_root,
        work=work,
        output=output,
        java=java,
        cfr_jar=selected_toolchain.cfr_jar,
        executor=decompiler_executor,
    )


def _attach_decompiled_views(
    index: ProgramIndexV2,
    *,
    staged: list[StagedClass],
    classes_root: Path,
    work: Path,
    output: Path,
    java: str,
    cfr_jar: Path,
    executor: ToolExecutor,
) -> ProgramIndexV2:
    if not index.classes:
        return index

    staged_by_path = {item.logical_path: item for item in staged}
    views: list[DecompiledViewRecord] = []
    gaps = list(index.coverage_gaps)
    if cfr_jar.is_symlink() or not cfr_jar.is_file():
        for record in index.classes:
            gaps.append(
                BytecodeIndexGap(
                    logical_path=record.logical_path,
                    class_sha256=record.class_sha256,
                    reason_code="CFR_UNAVAILABLE",
                    detail="the fixed CFR decompiler is unavailable",
                )
            )
        return _updated_index(index, views, gaps)

    artifact_root = output / "decompiled" / f"cfr-{CFR_VERSION}"
    scratch_root = work / "cfr"
    artifact_root.mkdir(parents=True, exist_ok=False)
    scratch_root.mkdir(parents=True, exist_ok=False)
    cached: dict[str, str | None] = {}
    total_bytes = 0
    unique_inputs = 0

    for record in index.classes:
        item = staged_by_path.get(record.logical_path)
        if item is None or item.sha256 != record.class_sha256:
            gaps.append(
                BytecodeIndexGap(
                    logical_path=record.logical_path,
                    class_sha256=record.class_sha256,
                    reason_code="DECOMPILATION_IDENTITY_MISMATCH",
                    detail="parsed class does not match its staged input identity",
                )
            )
            continue

        artifact_path = cached.get(record.class_sha256)
        if record.class_sha256 not in cached:
            unique_inputs += 1
            if unique_inputs > _MAX_DECOMPILED_CLASSES:
                cached[record.class_sha256] = None
                artifact_path = None
                reason_code = "DECOMPILATION_CLASS_LIMIT"
            else:
                artifact_path, size_bytes, reason_code = _decompile_class(
                    item,
                    classes_root=classes_root,
                    scratch_root=scratch_root,
                    artifact_root=artifact_root,
                    java=java,
                    cfr_jar=cfr_jar,
                    executor=executor,
                    remaining_bytes=_MAX_DECOMPILED_TOTAL_BYTES - total_bytes,
                )
                if artifact_path is not None:
                    total_bytes += size_bytes
                cached[record.class_sha256] = artifact_path
        else:
            reason_code = "DECOMPILATION_FAILED"

        if artifact_path is None:
            gaps.append(
                BytecodeIndexGap(
                    logical_path=record.logical_path,
                    class_sha256=record.class_sha256,
                    reason_code=reason_code,
                    detail="CFR did not produce a bounded deterministic view",
                )
            )
            continue
        views.append(
            DecompiledViewRecord(
                logical_path=record.logical_path,
                class_sha256=record.class_sha256,
                class_name=record.class_name,
                artifact_path=artifact_path,
                decompiler="cfr",
                decompiler_version=CFR_VERSION,
            )
        )

    return _updated_index(index, views, gaps)


def _decompile_class(
    item: StagedClass,
    *,
    classes_root: Path,
    scratch_root: Path,
    artifact_root: Path,
    java: str,
    cfr_jar: Path,
    executor: ToolExecutor,
    remaining_bytes: int,
) -> tuple[str | None, int, str]:
    if remaining_bytes <= 0:
        return None, 0, "DECOMPILATION_TOTAL_SIZE_LIMIT"
    class_work = scratch_root / item.sha256
    class_work.mkdir(exist_ok=False)
    result = executor(
        [
            java,
            "-Xms32m",
            "-Xmx256m",
            "-jar",
            str(cfr_jar),
            str(classes_root / item.staged_name),
            "--outputdir",
            str(class_work),
            "--silent",
            "true",
            "--comments",
            "false",
            "--clobber",
            "false",
        ],
        class_work,
        scratch_root / f"{item.sha256}.log",
        120,
    )
    if result.reason_code is not None:
        return None, 0, result.reason_code
    if result.exit_code != 0:
        return None, 0, "CFR_EXIT_NONZERO"
    try:
        candidates = _decompiler_outputs(class_work)
        if len(candidates) != 1:
            return None, 0, "CFR_OUTPUT_INVALID"
        source = candidates[0]
        size_bytes = source.stat().st_size
        if size_bytes > _MAX_DECOMPILED_VIEW_BYTES:
            return None, 0, "DECOMPILATION_VIEW_SIZE_LIMIT"
        if size_bytes > remaining_bytes:
            return None, 0, "DECOMPILATION_TOTAL_SIZE_LIMIT"
        payload = source.read_bytes()
        payload.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None, 0, "CFR_OUTPUT_INVALID"

    relative = f"decompiled/cfr-{CFR_VERSION}/{item.sha256}.java"
    destination = artifact_root / f"{item.sha256}.java"
    try:
        with destination.open("xb") as stream:
            stream.write(payload)
        destination.chmod(0o444)
    except OSError:
        return None, 0, "CFR_OUTPUT_UNWRITABLE"
    return relative, size_bytes, ""


def _decompiler_outputs(root: Path) -> list[Path]:
    outputs: list[Path] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        parent = Path(directory)
        retained: list[str] = []
        for name in directory_names:
            candidate = parent / name
            if candidate.is_symlink() or not candidate.is_dir():
                raise OSError("CFR produced an unsafe output directory")
            retained.append(name)
        directory_names[:] = retained
        for name in file_names:
            candidate = parent / name
            if candidate.is_symlink() or not candidate.is_file():
                raise OSError("CFR produced an unsafe output file")
            if candidate.suffix == ".java":
                outputs.append(candidate)
    return sorted(outputs, key=lambda path: path.relative_to(root).as_posix())


def _updated_index(
    index: ProgramIndexV2,
    views: list[DecompiledViewRecord],
    gaps: list[BytecodeIndexGap],
) -> ProgramIndexV2:
    payload = index.model_dump(mode="json")
    payload["decompiled_views"] = [view.model_dump(mode="json") for view in views]
    payload["coverage_gaps"] = [
        gap.model_dump(mode="json")
        for gap in sorted(
            gaps,
            key=lambda value: (
                value.logical_path.encode("utf-8"),
                value.reason_code,
            ),
        )
    ]
    return ProgramIndexV2.model_validate(payload)


def _parse_index(
    path: Path,
    staged: list[object],
    inventory: dict[str, object],
) -> ProgramIndexV2:
    expected = {
        item.logical_path: item
        for item in staged
    }
    classes: list[BytecodeClassRecord] = []
    methods: list[BytecodeMethodRecord] = []
    fields: list[BytecodeFieldRecord] = []
    calls: list[BytecodeCallRecord] = []
    field_accesses: list[BytecodeFieldAccessRecord] = []
    gaps: list[BytecodeIndexGap] = [
        BytecodeIndexGap(
            logical_path=str(item["logical_path"]),
            reason_code=str(item["reason_code"]),
            detail=str(item["detail"]),
        )
        for item in inventory["coverage_gaps"]
    ]
    seen_classes: set[str] = set()
    gap_paths: set[str] = set()
    records = 0
    try:
        with path.open("rb") as stream:
            while True:
                raw = stream.readline(_MAX_JSONL_LINE_BYTES + 1)
                if not raw:
                    break
                records += 1
                if records > _MAX_RECORDS:
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_TOO_MANY_RECORDS",
                        "ASM index exceeds the record count limit",
                    )
                if len(raw) > _MAX_JSONL_LINE_BYTES:
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_LINE_TOO_LARGE",
                        "ASM index contains an oversized record",
                    )
                try:
                    record = json.loads(raw)
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_OUTPUT_INVALID",
                        "ASM index is not valid UTF-8 JSONL",
                    ) from exc
                if not isinstance(record, dict):
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_OUTPUT_INVALID",
                        "ASM index record is not an object",
                    )
                logical_path = record.get("logical_path")
                item = expected.get(logical_path)
                if item is None or any(
                    (
                        record.get("container_path") != item.container_path,
                        record.get("entry_path") != item.entry_path,
                        record.get("class_sha256") != item.sha256,
                    )
                ):
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_IDENTITY_MISMATCH",
                        "ASM index record does not match a staged class identity",
                    )
                kind = record.pop("record_kind", None)
                try:
                    if kind == "class":
                        if logical_path in seen_classes:
                            raise BytecodeIndexFailure(
                                "BYTECODE_INDEX_DUPLICATE_CLASS",
                                "ASM index contains a duplicate class record",
                            )
                        classes.append(BytecodeClassRecord.model_validate(record))
                        seen_classes.add(str(logical_path))
                    elif kind == "method":
                        methods.append(BytecodeMethodRecord.model_validate(record))
                    elif kind == "field":
                        fields.append(BytecodeFieldRecord.model_validate(record))
                    elif kind == "call":
                        calls.append(BytecodeCallRecord.model_validate(record))
                    elif kind == "field-access":
                        field_accesses.append(
                            BytecodeFieldAccessRecord.model_validate(record)
                        )
                    elif kind == "coverage-gap":
                        reason_code = record.get("reason_code")
                        gaps.append(
                            BytecodeIndexGap(
                                logical_path=str(logical_path),
                                class_sha256=item.sha256,
                                reason_code=str(reason_code),
                                detail="ASM could not parse the selected classfile",
                            )
                        )
                        gap_paths.add(str(logical_path))
                    else:
                        raise BytecodeIndexFailure(
                            "BYTECODE_INDEX_RECORD_UNKNOWN",
                            "ASM index contains an unknown record kind",
                        )
                except ValidationError as exc:
                    raise BytecodeIndexFailure(
                        "BYTECODE_INDEX_OUTPUT_INVALID",
                        "ASM index record failed contract validation",
                    ) from exc
    except OSError as exc:
        raise BytecodeIndexFailure(
            "BYTECODE_INDEX_OUTPUT_UNREADABLE",
            "ASM index output could not be read",
        ) from exc

    for logical_path, item in expected.items():
        if logical_path not in seen_classes and logical_path not in gap_paths:
            gaps.append(
                BytecodeIndexGap(
                    logical_path=logical_path,
                    class_sha256=item.sha256,
                    reason_code="CLASS_INDEX_RESULT_MISSING",
                    detail="ASM produced no class record or parse failure",
                )
            )
    key = lambda value: (  # noqa: E731
        value.logical_path.encode("utf-8"),
        getattr(value, "class_name", ""),
        getattr(value, "method_name", ""),
        getattr(value, "method_descriptor", ""),
        getattr(value, "bytecode_offset", -1),
        getattr(value, "name", ""),
    )
    return ProgramIndexV2(
        contract="cairn-program-index-v2",
        asm_version=ASM_VERSION,
        target_java_version=int(inventory["target_java_version"]),
        components=inventory["components"],
        resources=inventory["resources"],
        classes=sorted(classes, key=key),
        methods=sorted(methods, key=key),
        fields=sorted(fields, key=key),
        calls=sorted(calls, key=key),
        field_accesses=sorted(field_accesses, key=key),
        decompiled_views=[],
        coverage_gaps=sorted(
            gaps,
            key=lambda item: (
                item.logical_path.encode("utf-8"),
                item.reason_code,
            ),
        ),
        classes_total=len(staged),
        classes_parsed=len(classes),
    )


def _resolve_java(value: str) -> str:
    if "/" in value:
        try:
            path = Path(value).resolve(strict=True)
        except OSError as exc:
            raise BytecodeIndexFailure(
                "JAVA_RUNTIME_UNAVAILABLE",
                "fixed Java runtime is unavailable",
            ) from exc
        if not path.is_file():
            raise BytecodeIndexFailure(
                "JAVA_RUNTIME_UNAVAILABLE",
                "fixed Java runtime is unavailable",
            )
        return str(path)
    resolved = shutil.which(value)
    if resolved is None:
        raise BytecodeIndexFailure(
            "JAVA_RUNTIME_UNAVAILABLE",
            "Java runtime is unavailable",
        )
    return resolved


def _require_tool(path: Path, reason_code: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BytecodeIndexFailure(reason_code, "fixed bytecode tool is unavailable")


def _base64url(value: str) -> str:
    return base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii")
