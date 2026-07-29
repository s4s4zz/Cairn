from io import BytesIO
from pathlib import Path
import zipfile

import pytest

from cairn.server.ingestion import (
    IngestionFailure,
    IngestionLimits,
    JvmArtifactKind,
    detect_jvm_artifact,
    validate_transport_zip,
)


def _limits() -> IngestionLimits:
    return IngestionLimits(
        upload_max_bytes=1024 * 1024,
        max_files=100,
        max_total_bytes=1024 * 1024,
        max_file_bytes=512 * 1024,
        max_compression_ratio=200,
        max_path_length=256,
        max_path_depth=16,
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


def _archive(entries: dict[str, bytes]) -> bytes:
    output = BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)
    return output.getvalue()


@pytest.mark.parametrize(
    ("entries", "expected"),
    [
        (
            {
                "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\r\n\r\n",
                "dev/cairn/Demo.class": _classfile(),
            },
            JvmArtifactKind.JAR,
        ),
        (
            {
                "WEB-INF/web.xml": b"<web-app />",
                "WEB-INF/classes/dev/cairn/Demo.class": _classfile(),
            },
            JvmArtifactKind.WAR,
        ),
        (
            {
                "META-INF/application.xml": b"<application />",
                "app.war": b"nested bytes are inventoried in the sandbox",
            },
            JvmArtifactKind.EAR,
        ),
    ],
)
def test_detects_zip_based_jvm_artifacts_by_structure_not_filename(
    tmp_path: Path,
    entries: dict[str, bytes],
    expected: JvmArtifactKind,
) -> None:
    artifact_path = tmp_path / "deliberately-wrong.txt"
    artifact_path.write_bytes(_archive(entries))

    detected = detect_jvm_artifact(artifact_path, _limits(), required=True)

    assert detected is not None
    assert detected.kind is expected
    assert detected.media_type == "application/java-archive"


def test_detects_classfile_magic_without_trusting_filename(tmp_path: Path) -> None:
    artifact_path = tmp_path / "not-a-class.txt"
    artifact_path.write_bytes(_classfile())

    detected = detect_jvm_artifact(artifact_path, _limits(), required=True)

    assert detected is not None
    assert detected.kind is JvmArtifactKind.CLASS
    assert detected.media_type == "application/java-vm"


def test_rejects_truncated_classfile(tmp_path: Path) -> None:
    artifact_path = tmp_path / "truncated.class"
    artifact_path.write_bytes(b"\xca\xfe\xba\xbe\x00\x00\x00\x3d\x00\x02")

    with pytest.raises(IngestionFailure) as captured:
        detect_jvm_artifact(artifact_path, _limits(), required=True)

    assert captured.value.error_code == "JVM_CLASS_INVALID"


def test_rejects_generic_or_malformed_zip_as_required_jvm_input(
    tmp_path: Path,
) -> None:
    generic = tmp_path / "generic.zip"
    generic.write_bytes(_archive({"README.md": b"not a JVM artifact"}))
    malformed = tmp_path / "malformed.bin"
    malformed.write_bytes(b"PK\x03\x04truncated")

    with pytest.raises(IngestionFailure) as generic_error:
        detect_jvm_artifact(generic, _limits(), required=True)
    with pytest.raises(IngestionFailure) as malformed_error:
        detect_jvm_artifact(malformed, _limits(), required=True)

    assert generic_error.value.error_code == "NO_SUPPORTED_JVM_INPUT"
    assert malformed_error.value.error_code == "JVM_ARCHIVE_INVALID"


def test_transport_upload_requires_zip_magic_and_structure(tmp_path: Path) -> None:
    archive = tmp_path / "transport.bin"
    archive.write_bytes(_archive({"src/Demo.java": b"class Demo {}"}))
    invalid = tmp_path / "invalid.zip"
    invalid.write_bytes(b"plain text")

    validate_transport_zip(archive, _limits())
    with pytest.raises(IngestionFailure) as captured:
        validate_transport_zip(invalid, _limits())

    assert captured.value.error_code == "UPLOAD_ARCHIVE_INVALID"
