from datetime import datetime
from uuid import UUID

from pydantic import Field

from cairn.server.domain.enums import AuditLogAction, UserRole
from cairn.server.schemas.common import Page, StrictModel


class LoginRequest(StrictModel):
    username: str = Field(min_length=1, max_length=64)
    # Not length-validated downward here: a short password is a failed login,
    # not a validation error that tells the caller the rule.
    password: str = Field(min_length=1, max_length=1024)


class UserResponse(StrictModel):
    id: UUID
    username: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class LoginResponse(StrictModel):
    """The login body carries the CSRF token as well as the cookie.

    A single-page app cannot read the session cookie (HttpOnly, by design) and
    should not have to parse ``document.cookie`` to find the CSRF one; handing
    it back here lets the client hold it in memory for the tab's lifetime.
    """

    user: UserResponse
    csrf_token: str
    expires_at: datetime


class UserCreate(StrictModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: UserRole


class UserUpdate(StrictModel):
    role: UserRole | None = None
    is_active: bool | None = None


class PasswordUpdate(StrictModel):
    new_password: str = Field(min_length=12, max_length=1024)


class SelfPasswordUpdate(StrictModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class UserFiltersQuery(StrictModel):
    role: UserRole | None = None
    is_active: bool | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


UserPage = Page[UserResponse]


class AuditLogEntryResponse(StrictModel):
    id: UUID
    actor_username: str
    actor_role: str | None
    action: str
    target_type: str | None
    target_id: str | None
    outcome: str
    http_status: int | None
    request_id: str | None
    client_ip: str | None
    detail: dict[str, object]
    created_at: datetime


class AuditLogFilters(StrictModel):
    action: AuditLogAction | None = None
    actor_username: str | None = Field(default=None, max_length=64)
    target_type: str | None = Field(default=None, max_length=64)
    target_id: str | None = Field(default=None, max_length=128)
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


AuditLogPage = Page[AuditLogEntryResponse]
