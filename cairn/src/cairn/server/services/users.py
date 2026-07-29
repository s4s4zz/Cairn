"""Local account management (§9.8).

Authentication lives here rather than in the router so the CLI (``cairn
create-user``) and the API share one implementation of what a valid account is:
the same username rules, the same Argon2id parameters, the same refusal to
store a weak hash.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.auth.passwords import (
    Argon2Parameters,
    hash_password,
    needs_rehash,
    verify_password,
)
from cairn.server.domain.enums import UserRole
from cairn.server.errors import ConflictError, DomainError, NotFoundError
from cairn.server.persistence.base import utcnow
from cairn.server.persistence.models.identity import User


USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024


class InvalidCredentialsError(DomainError):
    """One error for every way a login can fail.

    Wrong password, unknown username and disabled account are indistinguishable
    to the caller: anything finer is a user-enumeration oracle.
    """

    def __init__(self) -> None:
        super().__init__("invalid_credentials", "invalid username or password", 401)


class WeakPasswordError(DomainError):
    def __init__(self, message: str) -> None:
        super().__init__("password_too_weak", message, 422)


class InvalidUsernameError(DomainError):
    def __init__(self) -> None:
        super().__init__(
            "invalid_username",
            "username must be 3-64 characters of a-z, 0-9, dot, dash or underscore",
            422,
        )


@dataclass(frozen=True, slots=True)
class UserFilters:
    role: UserRole | None = None
    is_active: bool | None = None
    limit: int = 50
    offset: int = 0


def validate_password(password: str) -> None:
    if len(password) < MIN_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise WeakPasswordError(
            f"password must be at most {MAX_PASSWORD_LENGTH} characters"
        )


class UserService:
    def __init__(
        self,
        session: Session,
        *,
        password_parameters: Argon2Parameters | None = None,
    ) -> None:
        self.session = session
        self.password_parameters = password_parameters or Argon2Parameters()

    def create(self, username: str, password: str, role: UserRole) -> User:
        normalized = username.strip().lower()
        if not USERNAME_PATTERN.match(normalized):
            raise InvalidUsernameError()
        validate_password(password)
        user = User(
            username=normalized,
            password_hash=hash_password(password, self.password_parameters),
            role=role.value,
            is_active=True,
        )
        self.session.add(user)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                f"username {normalized!r} already exists",
                error_code="username_conflict",
            ) from exc
        return user

    def authenticate(self, username: str, password: str) -> User:
        """Verify a password, rehashing it if the parameters have moved on.

        The hash is computed even when the username is unknown, against a
        throwaway hash: without it the response time tells an attacker which
        usernames exist.
        """

        normalized = username.strip().lower()
        user = self.session.scalar(
            select(User).where(func.lower(User.username) == normalized)
        )
        if user is None:
            hash_password(password, self.password_parameters)
            raise InvalidCredentialsError()
        if not verify_password(password, user.password_hash):
            raise InvalidCredentialsError()
        if not user.is_active:
            raise InvalidCredentialsError()
        if needs_rehash(user.password_hash, self.password_parameters):
            user.password_hash = hash_password(password, self.password_parameters)
        user.last_login_at = utcnow()
        return user

    def get(self, user_id: UUID) -> User:
        user = self.session.get(User, user_id)
        if user is None:
            raise NotFoundError("user", user_id)
        return user

    def by_username(self, username: str) -> User | None:
        return self.session.scalar(
            select(User).where(func.lower(User.username) == username.strip().lower())
        )

    def list(self, filters: UserFilters) -> tuple[list[User], int]:
        conditions = []
        if filters.role is not None:
            conditions.append(User.role == filters.role.value)
        if filters.is_active is not None:
            conditions.append(User.is_active.is_(filters.is_active))
        total = self.session.scalar(
            select(func.count()).select_from(User).where(*conditions)
        )
        users = list(
            self.session.scalars(
                select(User)
                .where(*conditions)
                .order_by(User.username)
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return users, int(total or 0)

    def set_password(self, user: User, password: str) -> User:
        validate_password(password)
        user.password_hash = hash_password(password, self.password_parameters)
        return user

    def update(
        self,
        user: User,
        *,
        role: UserRole | None = None,
        is_active: bool | None = None,
    ) -> User:
        """Change role or activation, refusing to remove the last live admin.

        Single-tenant means there is no second way in: an instance whose only
        admin has been demoted or disabled can no longer manage users,
        credentials or policies at all.
        """

        if role is not None or is_active is not None:
            becoming_non_admin = role is not None and role is not UserRole.ADMIN
            becoming_inactive = is_active is False
            if (becoming_non_admin or becoming_inactive) and self._is_last_admin(user):
                raise ConflictError(
                    "the last active admin cannot be demoted or disabled",
                    error_code="last_admin_protected",
                )
        if role is not None:
            user.role = role.value
        if is_active is not None:
            user.is_active = is_active
        return user

    def _is_last_admin(self, user: User) -> bool:
        if user.role != UserRole.ADMIN.value or not user.is_active:
            return False
        active_admin_ids = list(
            self.session.scalars(
                select(User.id)
                .where(
                    User.role == UserRole.ADMIN.value,
                    User.is_active.is_(True),
                )
                .order_by(User.id)
                .with_for_update()
            )
        )
        return all(admin_id == user.id for admin_id in active_admin_ids)
