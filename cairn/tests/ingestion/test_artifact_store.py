from io import BytesIO

import pytest

from cairn.server.artifacts import ArtifactIntegrityError, LocalArtifactStore


def test_local_store_is_content_addressed_and_deduplicates_bytes(tmp_path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")

    first = store.put_stream(BytesIO(b"same bytes"))
    second = store.put_stream(BytesIO(b"same bytes"))

    assert first == second
    assert first.storage_key == f"sha256/{first.sha256[:2]}/{first.sha256}"
    assert store.resolve(
        first.storage_key,
        expected_sha256=first.sha256,
        expected_size=first.size_bytes,
    ).read_bytes() == b"same bytes"


def test_local_store_rejects_invalid_keys_and_tampered_objects(tmp_path) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    stored = store.put_stream(BytesIO(b"original"))

    with pytest.raises(ArtifactIntegrityError):
        store.resolve("../../etc/passwd")

    object_path = store.resolve(stored.storage_key)
    object_path.chmod(0o600)
    object_path.write_bytes(b"tampered")
    with pytest.raises(ArtifactIntegrityError):
        store.resolve(
            stored.storage_key,
            expected_sha256=stored.sha256,
            expected_size=stored.size_bytes,
        )
