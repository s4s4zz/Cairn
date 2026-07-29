from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

from cairn.analysis.bytecode_index import (
    BytecodeIndexFailure,
    BytecodeToolchain,
    ToolResult,
    build_bytecode_index,
)


@pytest.fixture
def compiled_class(tmp_path: Path) -> Path:
    javac = shutil.which("javac")
    if javac is None:
        pytest.skip("javac is required for the bytecode index tests")
    source = tmp_path / "Fixture.java"
    source.write_text(
        """public final class Fixture {
    public void run() {
        System.out.println("fixture");
    }
}
"""
    )
    subprocess.run(
        [javac, "--release", "17", "-g:none", str(source)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        timeout=30,
    )
    return tmp_path / "Fixture.class"


def _toolchain(tmp_path: Path, *, java: str = sys.executable) -> BytecodeToolchain:
    asm = tmp_path / "asm.jar"
    helper = tmp_path / "helper.jar"
    cfr = tmp_path / "cfr.jar"
    for path in (asm, helper, cfr):
        path.write_bytes(b"fixture")
    return BytecodeToolchain(java=java, asm_jar=asm, helper_jar=helper, cfr_jar=cfr)


def _mapping(argv: list[str]) -> dict[str, str | None]:
    fields = Path(argv[-2]).read_text().strip().split("\t")
    decode = lambda value: base64.urlsafe_b64decode(value).decode()  # noqa: E731
    return {
        "sha256": fields[0],
        "logical_path": decode(fields[2]),
        "container_path": decode(fields[3]) or None,
        "entry_path": decode(fields[4]),
    }


def _record(identity: dict[str, str | None], kind: str, **values: object) -> dict[str, object]:
    return {
        "record_kind": kind,
        "logical_path": identity["logical_path"],
        "container_path": identity["container_path"],
        "entry_path": identity["entry_path"],
        "class_sha256": identity["sha256"],
        "class_name": "Fixture",
        **values,
    }


def test_bytecode_index_validates_helper_output_and_preserves_absent_lines(
    tmp_path: Path,
    compiled_class: Path,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "opaque.bin").write_bytes(compiled_class.read_bytes())
    toolchain = _toolchain(tmp_path)

    def fake_executor(argv: list[str], cwd: Path, log: Path, timeout: int) -> ToolResult:
        del cwd, timeout
        identity = _mapping(argv)
        records = [
            _record(
                identity,
                "call",
                method_name="run",
                method_descriptor="()V",
                bytecode_offset=3,
                source_line=None,
                opcode=182,
                edge_kind="inferred",
                target_owner="java.io.PrintStream",
                target_name="println",
                target_descriptor="(Ljava/lang/String;)V",
                interface=False,
                callsite_name=None,
                callsite_descriptor=None,
                bootstrap_owner=None,
                bootstrap_name=None,
                bootstrap_descriptor=None,
            ),
            _record(
                identity,
                "method",
                method_name="run",
                method_descriptor="()V",
                access=1,
                signature=None,
                exceptions=[],
                annotations=[],
                start_line=None,
                end_line=None,
                first_bytecode_offset=0,
                last_bytecode_offset=6,
            ),
            _record(
                identity,
                "class",
                super_name="java.lang.Object",
                interfaces=[],
                access=49,
                classfile_major=61,
                signature=None,
                source_file=None,
                annotations=[],
            ),
        ]
        Path(argv[-1]).write_text(
            "".join(json.dumps(item) + "\n" for item in records)
        )
        log.write_text("fake ASM helper completed\n")
        return ToolResult(0)

    def fake_decompiler(
        argv: list[str], cwd: Path, log: Path, timeout: int
    ) -> ToolResult:
        del cwd, timeout
        output_dir = Path(argv[argv.index("--outputdir") + 1])
        (output_dir / "Fixture.java").write_text(
            "public final class Fixture {}\n",
            encoding="utf-8",
        )
        log.write_text("fake CFR completed\n")
        return ToolResult(0)

    index = build_bytecode_index(
        source,
        tmp_path / "scratch",
        tmp_path / "output",
        toolchain=toolchain,
        executor=fake_executor,
        decompiler_executor=fake_decompiler,
    )

    assert index.classes_total == index.classes_parsed == 1
    assert index.methods[0].start_line is None
    assert index.calls[0].bytecode_offset == 3
    assert index.calls[0].target_owner == "java.io.PrintStream"
    assert index.coverage_gaps == []
    assert len(index.decompiled_views) == 1
    view = index.decompiled_views[0]
    assert view.decompiler_version == "0.152"
    assert view.artifact_path == (
        f"decompiled/cfr-0.152/{identity_sha256(compiled_class)}.java"
    )
    assert (tmp_path / "output" / view.artifact_path).read_text() == (
        "public final class Fixture {}\n"
    )


def test_bytecode_index_rejects_helper_identity_spoofing(
    tmp_path: Path,
    compiled_class: Path,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "Type.class").write_bytes(compiled_class.read_bytes())
    toolchain = _toolchain(tmp_path)

    def spoofing_executor(
        argv: list[str], cwd: Path, log: Path, timeout: int
    ) -> ToolResult:
        del cwd, log, timeout
        identity = _mapping(argv)
        identity["logical_path"] = "different.class"
        Path(argv[-1]).write_text(
            json.dumps(
                _record(
                    identity,
                    "class",
                    super_name="java.lang.Object",
                    interfaces=[],
                    access=1,
                    classfile_major=61,
                    signature=None,
                    source_file=None,
                    annotations=[],
                )
            )
            + "\n"
        )
        return ToolResult(0)

    with pytest.raises(BytecodeIndexFailure) as captured:
        build_bytecode_index(
            source,
            tmp_path / "scratch",
            tmp_path / "output",
            toolchain=toolchain,
            executor=spoofing_executor,
        )

    assert captured.value.reason_code == "BYTECODE_INDEX_IDENTITY_MISMATCH"


def test_bytecode_index_reports_missing_pinned_tool(
    tmp_path: Path,
    compiled_class: Path,
) -> None:
    source = tmp_path / "input"
    source.mkdir()
    (source / "Type.class").write_bytes(compiled_class.read_bytes())
    toolchain = BytecodeToolchain(
        java=sys.executable,
        asm_jar=tmp_path / "missing-asm.jar",
        helper_jar=tmp_path / "missing-helper.jar",
        cfr_jar=tmp_path / "missing-cfr.jar",
    )

    with pytest.raises(BytecodeIndexFailure) as captured:
        build_bytecode_index(
            source,
            tmp_path / "scratch",
            tmp_path / "output",
            toolchain=toolchain,
        )

    assert captured.value.reason_code == "ASM_UNAVAILABLE"


def test_real_asm_helper_indexes_offsets_without_source_lines(
    tmp_path: Path,
    compiled_class: Path,
) -> None:
    asm_value = os.environ.get("CAIRN_TEST_ASM_JAR")
    if not asm_value:
        pytest.skip("set CAIRN_TEST_ASM_JAR to run the real ASM integration")
    asm = Path(asm_value).resolve()
    if not asm.is_file():
        pytest.skip("CAIRN_TEST_ASM_JAR is unavailable")
    javac = shutil.which("javac")
    jar = shutil.which("jar")
    java = shutil.which("java")
    if None in {javac, jar, java}:
        pytest.skip("JDK tools are required for the real ASM integration")

    repository_root = Path(__file__).resolve().parents[3]
    helper_source = (
        repository_root
        / "sandbox-images/java/dev/cairn/bytecode/BytecodeIndexer.java"
    )
    helper_classes = tmp_path / "helper-classes"
    helper_classes.mkdir()
    subprocess.run(
        [
            str(javac),
            "--release",
            "17",
            "-encoding",
            "UTF-8",
            "-cp",
            str(asm),
            "-d",
            str(helper_classes),
            str(helper_source),
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    helper = tmp_path / "helper.jar"
    subprocess.run(
        [
            str(jar),
            "--create",
            "--file",
            str(helper),
            "--main-class",
            "dev.cairn.bytecode.BytecodeIndexer",
            "-C",
            str(helper_classes),
            ".",
        ],
        check=True,
        capture_output=True,
        timeout=30,
    )
    cfr_value = os.environ.get("CAIRN_TEST_CFR_JAR")
    cfr = Path(cfr_value).resolve() if cfr_value else tmp_path / "unused-cfr.jar"
    if not cfr_value:
        cfr.write_bytes(b"unused")
    source = tmp_path / "input"
    source.mkdir()
    (source / "opaque.bin").write_bytes(compiled_class.read_bytes())

    index = build_bytecode_index(
        source,
        tmp_path / "scratch",
        tmp_path / "output",
        toolchain=BytecodeToolchain(
            java=str(java),
            asm_jar=asm,
            helper_jar=helper,
            cfr_jar=cfr,
        ),
        generate_decompiled_views=bool(cfr_value),
    )

    println = next(call for call in index.calls if call.target_name == "println")
    assert println.bytecode_offset >= 0
    assert println.source_line is None
    assert next(method for method in index.methods if method.method_name == "run").start_line is None
    if cfr_value:
        assert len(index.decompiled_views) == 1
        view_path = tmp_path / "output" / index.decompiled_views[0].artifact_path
        assert "public final class Fixture" in view_path.read_text(encoding="utf-8")


def identity_sha256(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()
