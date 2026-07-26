from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import Field, SecretStr, model_validator

from cairn.server.domain.enums import GitCredentialKind
from cairn.server.schemas.common import StrictModel


class HttpsTokenCredentialCreate(StrictModel):
    type: Literal["https_token"]
    username: str = Field(default="oauth2", min_length=1, max_length=255)
    token: SecretStr = Field(min_length=1, max_length=16_384)

    def secret_payload(self) -> dict[str, str]:
        return {
            "username": self.username,
            "token": self.token.get_secret_value(),
        }


class SshKeyCredentialCreate(StrictModel):
    type: Literal["ssh_key"]
    private_key: SecretStr = Field(min_length=1, max_length=128 * 1024)
    known_hosts: SecretStr = Field(min_length=1, max_length=1024 * 1024)

    @model_validator(mode="after")
    def validate_private_key(self) -> "SshKeyCredentialCreate":
        if "PRIVATE KEY" not in self.private_key.get_secret_value()[:128]:
            raise ValueError("private_key must be a PEM or OpenSSH private key")
        return self

    def secret_payload(self) -> dict[str, str]:
        return {
            "private_key": self.private_key.get_secret_value(),
            "known_hosts": self.known_hosts.get_secret_value(),
        }


GitCredentialCreate = Annotated[
    HttpsTokenCredentialCreate | SshKeyCredentialCreate,
    Field(discriminator="type"),
]


class GitCredentialResponse(StrictModel):
    id: UUID
    reference: str
    kind: GitCredentialKind
    created_at: datetime
