"""Browser session issue, lookup and revocation (§9.8).

Cookie values are random 256-bit tokens, stored only as SHA-256. A session is
usable only while three things hold — it has not expired, it has not been
revoked, and its user is still active — and all three are checked on every
request rather than baked into the cookie at login, so disabling an account
ends its live sessions immediately.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import secrets
from uuid import UUID

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from cairn.server.persistence.base import utcnow
from cairn.server.persistence.models.identity import User, UserSession


SESSION_COOKIE_NAME = "cairn_session"
CSRF_COOKIE_NAME = "cairn_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"
TOKEN_BYTES = 32


def token_digest(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


@dataclass(frozen=True, slots=True)
class IssuedSession:
    """The only moment the plaintext tokens exist server-side."""

    session_id: UUID
    token: str
    csrf_token: str
    expires_at: datetime


class SessionService:
    def __init__(self, session: Session, *, ttl: timedelta) -> None:
        self.session = session
        self.ttl = ttl

    def issue(
        self,
        user: User,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> IssuedSession:
        token = secrets.token_urlsafe(TOKEN_BYTES)
        csrf_token = secrets.token_urlsafe(TOKEN_BYTES)
        expires_at = utcnow() + self.ttl
        record = UserSession(
            user_id=user.id,
            token_sha256=token_digest(token),
            csrf_sha256=token_digest(csrf_token),
            expires_at=expires_at,
            client_ip=(client_ip or None),
            user_agent=(user_agent or None) and user_agent[:255],
        )
        self.session.add(record)
        self.session.flush()
        return IssuedSession(
            session_id=record.id,
            token=token,
            csrf_token=csrf_token,
            expires_at=expires_at,
        )

    def resolve(self, token: str) -> tuple[UserSession, User] | None:
        """Return the live session and its user, or None for any failure.

        One return value for "no such session", "expired", "revoked" and
        "disabled user": the caller answers 401 in every case, and a caller that
        cannot tell them apart cannot leak the difference either.
        """

        if not token:
            return None
        record = self.session.scalar(
            select(UserSession).where(UserSession.token_sha256 == token_digest(token))
        )
        if record is None or record.revoked_at is not None:
            return None
        if _aware(record.expires_at) <= utcnow():
            return None
        user = self.session.get(User, record.user_id)
        if user is None or not user.is_active:
            return None
        record.last_seen_at = utcnow()
        return record, user

    def revoke(self, record: UserSession) -> None:
        if record.revoked_at is None:
            record.revoked_at = utcnow()

    def revoke_all_for_user(self, user_id: UUID) -> int:
        """Used when a password changes or an account is disabled."""

        result = self.session.execute(
            update(UserSession)
            .where(
                UserSession.user_id == user_id,
                UserSession.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )
        return int(result.rowcount or 0)

    def purge_expired(self, *, older_than: timedelta = timedelta(days=7)) -> int:
        cutoff = utcnow() - older_than
        result = self.session.execute(
            delete(UserSession).where(UserSession.expires_at < cutoff)
        )
        return int(result.rowcount or 0)
