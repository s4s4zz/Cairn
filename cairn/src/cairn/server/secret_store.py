from __future__ import annotations

import base64
import binascii
import json
import os
from pathlib import Path
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy.orm import Session

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.errors import ConflictError, DomainError, NotFoundError
from cairn.server.persistence.models import EncryptedSecret, Repository


class SecretStoreUnavailable(DomainError):
    def __init__(self, message: str = "Git credential store is unavailable") -> None:
        super().__init__("secret_store_unavailable", message, 503)


def load_master_key(path: Path | None) -> bytes:
    if path is None:
        raise SecretStoreUnavailable("CAIRN_SECRET_KEY_FILE is not configured")
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise SecretStoreUnavailable("Git credential master key cannot be read") from exc
    if len(encoded) == 32:
        return encoded
    encoded = encoded.strip()
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise SecretStoreUnavailable("Git credential master key is invalid") from exc
    if len(decoded) != 32:
        raise SecretStoreUnavailable(
            "Git credential master key must contain exactly 32 bytes"
        )
    return decoded


class DatabaseSecretStore:
    """AES-256-GCM encrypted secrets backed by the audit database."""

    def __init__(self, session: Session, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte master key")
        self.session = session
        self.cipher = AESGCM(master_key)

    def create(
        self,
        kind: GitCredentialKind,
        payload: dict[str, str],
    ) -> EncryptedSecret:
        reference = f"git_{secrets.token_hex(16)}"
        nonce = os.urandom(12)
        plaintext = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        secret = EncryptedSecret(
            reference=reference,
            kind=kind.value,
            nonce=nonce,
            ciphertext=self.cipher.encrypt(
                nonce,
                plaintext,
                self._associated_data(reference, kind.value),
            ),
            key_version=1,
        )
        self.session.add(secret)
        self.session.flush()
        return secret

    def read(self, reference: str) -> tuple[GitCredentialKind, dict[str, str]]:
        secret = self._get(reference)
        try:
            plaintext = self.cipher.decrypt(
                secret.nonce,
                secret.ciphertext,
                self._associated_data(secret.reference, secret.kind),
            )
            raw_payload: Any = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SecretStoreUnavailable(
                "Git credential could not be decrypted"
            ) from exc
        if not isinstance(raw_payload, dict) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in raw_payload.items()
        ):
            raise SecretStoreUnavailable("Git credential payload is invalid")
        return GitCredentialKind(secret.kind), raw_payload

    def delete(self, reference: str) -> None:
        secret = self._get(reference)
        repository = (
            self.session.query(Repository.id)
            .filter(Repository.credential_ref == reference)
            .first()
        )
        if repository is not None:
            raise ConflictError(
                "Git credential is referenced by a repository",
                error_code="credential_in_use",
            )
        self.session.delete(secret)
        self.session.flush()

    def _get(self, reference: str) -> EncryptedSecret:
        secret = (
            self.session.query(EncryptedSecret)
            .filter(EncryptedSecret.reference == reference)
            .one_or_none()
        )
        if secret is None:
            raise NotFoundError("git_credential", reference)
        return secret

    @staticmethod
    def _associated_data(reference: str, kind: str) -> bytes:
        return f"cairn-git-credential-v1\0{reference}\0{kind}".encode()
