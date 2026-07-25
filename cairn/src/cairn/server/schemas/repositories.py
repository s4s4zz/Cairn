from datetime import datetime
import re
from typing import Self
from urllib.parse import urlparse
from uuid import UUID

from pydantic import Field, model_validator

from cairn.server.domain.enums import SourceType
from cairn.server.schemas.common import Page, StrictModel


_SCP_STYLE_SSH_URL = re.compile(r"^[^@\s]+@[^:\s]+:.+$")


def _is_supported_git_url(value: str) -> bool:
    if _SCP_STYLE_SSH_URL.fullmatch(value):
        return True
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"https", "ssh"}
        or not parsed.hostname
        or not parsed.path
    ):
        return False
    if parsed.password is not None:
        return False
    if parsed.scheme == "https" and parsed.username is not None:
        return False
    return True


class RepositoryCreate(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    source_type: SourceType
    remote_url: str | None = Field(default=None, max_length=4096)
    credential_ref: str | None = Field(default=None, min_length=1, max_length=255)
    default_branch: str | None = Field(default=None, min_length=1, max_length=255)

    @model_validator(mode="after")
    def validate_source_fields(self) -> Self:
        if self.source_type is SourceType.GIT:
            if self.remote_url is None:
                raise ValueError("Git repositories require remote_url")
            if not _is_supported_git_url(self.remote_url):
                raise ValueError("remote_url must use HTTPS or SSH")
            return self

        if self.remote_url is not None:
            raise ValueError("upload repositories cannot define remote_url")
        if self.credential_ref is not None:
            raise ValueError("upload repositories cannot define credential_ref")
        if self.default_branch is not None:
            raise ValueError("upload repositories cannot define default_branch")
        return self


class RepositoryResponse(StrictModel):
    id: UUID
    name: str
    source_type: SourceType
    remote_url: str | None
    credential_ref: str | None
    default_branch: str | None
    created_by: str
    created_at: datetime
    updated_at: datetime


class RepositoryFilters(StrictModel):
    source_type: SourceType | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


RepositoryPage = Page[RepositoryResponse]
