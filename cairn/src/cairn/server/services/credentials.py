from pathlib import Path

from sqlalchemy.orm import Session

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.persistence.models import EncryptedSecret
from cairn.server.schemas.credentials import (
    GitCredentialCreate,
    HttpsTokenCredentialCreate,
    SshKeyCredentialCreate,
)
from cairn.server.secret_store import DatabaseSecretStore, load_master_key


class GitCredentialService:
    def __init__(self, session: Session, key_file: Path | None) -> None:
        self.store = DatabaseSecretStore(session, load_master_key(key_file))

    def create(self, request: GitCredentialCreate) -> EncryptedSecret:
        if isinstance(request, HttpsTokenCredentialCreate):
            kind = GitCredentialKind.HTTPS_TOKEN
        elif isinstance(request, SshKeyCredentialCreate):
            kind = GitCredentialKind.SSH_KEY
        else:
            raise AssertionError("unsupported Git credential kind")
        return self.store.create(kind, request.secret_payload())

    def delete(self, reference: str) -> None:
        self.store.delete(reference)
