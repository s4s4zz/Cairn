"""FastAPI dependencies that answer "who is calling" and "may they" (§9.8).

Three checks, in this order, on every request that carries them:

1. the session cookie resolves to a live session and an active user;
2. for anything that is not a read, the ``X-CSRF-Token`` header matches the
   token minted with that session — the cookie alone is never enough, which is
   what stops a cross-site form post from acting as the logged-in operator;
3. the user's role is in the endpoint's explicit allow-set.

A refused request is itself an event worth keeping: role denials are committed
to the audit log before the error is raised, because the request transaction is
rolled back on the way out and an uncommitted row would leave exactly the
attempted-privilege-escalation case unrecorded.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
import hmac
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService, Principal
from cairn.server.auth.sessions import (
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    SessionService,
    token_digest,
)
from cairn.server.domain.enums import AuditLogAction, UserRole
from cairn.server.errors import DomainError, ensure_request_id
from cairn.server.persistence.session import get_db_session


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class AuthenticationRequiredError(DomainError):
    def __init__(self, message: str = "authentication is required") -> None:
        super().__init__("authentication_required", message, 401)


class CsrfTokenError(DomainError):
    def __init__(self) -> None:
        super().__init__(
            "csrf_token_invalid",
            f"{CSRF_HEADER_NAME} is missing or does not match the session",
            403,
        )


class InsufficientRoleError(DomainError):
    def __init__(self, required: tuple[UserRole, ...]) -> None:
        allowed = ", ".join(role.value for role in required)
        super().__init__(
            "insufficient_role",
            f"this operation requires one of: {allowed}",
            403,
        )


DatabaseSession = Annotated[Session, Depends(get_db_session)]


def client_ip(request: Request) -> str | None:
    """The peer address, taken from the socket only.

    ``X-Forwarded-For`` is deliberately ignored: the deployment binds to
    loopback behind an operator-controlled proxy, and trusting the header
    without a trusted-proxy list would let any caller write whatever address
    they like into the audit log.
    """

    return request.client.host if request.client else None


def _session_service(request: Request, session: Session) -> SessionService:
    settings = request.app.state.settings
    return SessionService(
        session,
        ttl=timedelta(minutes=settings.session_ttl_minutes),
    )


def authenticate(request: Request, session: DatabaseSession) -> Principal:
    resolved = _session_service(request, session).resolve(
        request.cookies.get(SESSION_COOKIE_NAME, "")
    )
    if resolved is None:
        raise AuthenticationRequiredError()
    record, user = resolved
    if request.method.upper() not in SAFE_METHODS:
        supplied = request.headers.get(CSRF_HEADER_NAME, "")
        if not supplied or not hmac.compare_digest(
            token_digest(supplied),
            record.csrf_sha256,
        ):
            raise CsrfTokenError()
    principal = Principal(id=user.id, username=user.username, role=UserRole(user.role))
    request.state.principal = principal
    return principal


CurrentPrincipal = Annotated[Principal, Depends(authenticate)]


def require_roles(*roles: UserRole) -> Callable[..., Principal]:
    """Build a dependency that admits only the listed roles.

    Membership in an explicit set, never an ordering comparison: adding a role
    to ``UserRole`` grants it nothing until an endpoint names it.
    """

    if not roles:
        raise ValueError("require_roles needs at least one role")
    allowed = frozenset(roles)

    def dependency(
        request: Request,
        session: DatabaseSession,
        principal: CurrentPrincipal,
    ) -> Principal:
        if principal.role not in allowed:
            # Recorded under one action with the endpoint as the target, rather
            # than guessed at from the path: "what was refused" is the path and
            # method, and inventing a per-endpoint action here would put a
            # guess in the audit trail.
            AuditLogService(session).record(
                AuditLogAction.ACCESS_DENIED,
                actor=principal,
                target_type="endpoint",
                target_id=request.url.path,
                outcome="denied",
                http_status=403,
                request_id=ensure_request_id(request),
                client_ip=client_ip(request),
                detail={
                    "method": request.method.upper(),
                    "required": sorted(role.value for role in allowed),
                },
            )
            session.commit()
            raise InsufficientRoleError(tuple(roles))
        return principal

    return dependency


RequireAdmin = Annotated[Principal, Depends(require_roles(UserRole.ADMIN))]
RequireAuditor = Annotated[
    Principal,
    Depends(require_roles(UserRole.ADMIN, UserRole.AUDITOR)),
]
RequireReviewer = Annotated[
    Principal,
    Depends(require_roles(UserRole.ADMIN, UserRole.REVIEWER)),
]
RequireAnyRole = Annotated[
    Principal,
    Depends(
        require_roles(
            UserRole.ADMIN,
            UserRole.AUDITOR,
            UserRole.REVIEWER,
            UserRole.VIEWER,
        )
    ),
]
