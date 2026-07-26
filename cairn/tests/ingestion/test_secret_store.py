import base64

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.persistence.base import Base
from cairn.server.secret_store import (
    DatabaseSecretStore,
    SecretStoreUnavailable,
    load_master_key,
)


def test_raw_master_key_preserves_leading_and_trailing_whitespace(tmp_path) -> None:
    key = b"\n" + (b"k" * 30) + b" "
    key_file = tmp_path / "master.key"
    key_file.write_bytes(key)

    assert len(key) == 32
    assert load_master_key(key_file) == key


def test_base64_master_key_is_supported(tmp_path) -> None:
    key = b"k" * 32
    key_file = tmp_path / "master.key"
    key_file.write_bytes(base64.b64encode(key) + b"\n")

    assert load_master_key(key_file) == key


def test_wrong_master_key_cannot_decrypt_credential() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        secret = DatabaseSecretStore(session, b"a" * 32).create(
            GitCredentialKind.HTTPS_TOKEN,
            {"username": "bot", "token": "secret"},
        )

        with pytest.raises(SecretStoreUnavailable):
            DatabaseSecretStore(session, b"b" * 32).read(secret.reference)
