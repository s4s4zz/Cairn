from datetime import timedelta
from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService, Principal
from cairn.server.auth.cookies import clear_session_cookies, set_session_cookies
from cairn.server.auth.dependencies import (
    CurrentPrincipal,
    RequireAnyRole,
    client_ip,
)
from cairn.server.auth.passwords import Argon2Parameters
from cairn.server.auth.sessions import SESSION_COOKIE_NAME, SessionService
from cairn.server.config import ServerSettings
from cairn.server.domain.enums import AuditLogAction, UserRole
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.auth import (
    LoginRequest,
    LoginResponse,
    SelfPasswordUpdate,
    UserResponse,
)
from cairn.server.services.users import InvalidCredentialsError, UserService


router = APIRouter(prefix="/auth", tags=["auth"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def password_parameters(settings: ServerSettings) -> Argon2Parameters:
    return Argon2Parameters(
        memory_kib=settings.password_hash_memory_kib,
        iterations=settings.password_hash_iterations,
        lanes=settings.password_hash_lanes,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: DatabaseSession,
) -> LoginResponse:
    """Exchange a username and password for a session.

    Both outcomes are audited. A failed attempt is committed before the error
    is raised, because the request transaction is rolled back on the way out
    and an uncommitted row would lose exactly the brute-force evidence the log
    exists to keep.
    """

    settings: ServerSettings = request.app.state.settings
    log = AuditLogService(session)
    service = UserService(session, password_parameters=password_parameters(settings))
    try:
        user = service.authenticate(payload.username, payload.password)
    except InvalidCredentialsError:
        log.record(
            AuditLogAction.LOGIN_FAILED,
            actor=Principal(id=None, username=payload.username[:64], role=None),
            outcome="denied",
            http_status=401,
            request_id=ensure_request_id(request),
            client_ip=client_ip(request),
        )
        session.commit()
        raise

    ttl = timedelta(minutes=settings.session_ttl_minutes)
    issued = SessionService(session, ttl=ttl).issue(
        user,
        client_ip=client_ip(request),
        user_agent=request.headers.get("User-Agent"),
    )
    log.record(
        AuditLogAction.LOGIN_SUCCEEDED,
        actor=Principal(
            id=user.id,
            username=user.username,
            role=UserRole(user.role),
        ),
        target_type="user",
        target_id=user.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
    )
    session.commit()
    set_session_cookies(
        response,
        issued,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
        ttl_seconds=int(ttl.total_seconds()),
    )
    return LoginResponse(
        user=UserResponse.model_validate(user),
        csrf_token=issued.csrf_token,
        expires_at=issued.expires_at,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    response: Response,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> Response:
    settings: ServerSettings = request.app.state.settings
    service = SessionService(
        session,
        ttl=timedelta(minutes=settings.session_ttl_minutes),
    )
    resolved = service.resolve(request.cookies.get(SESSION_COOKIE_NAME, ""))
    if resolved is not None:
        service.revoke(resolved[0])
    AuditLogService(session).record(
        AuditLogAction.LOGOUT,
        actor=principal,
        target_type="user",
        target_id=principal.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
    )
    session.commit()
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(
        result,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )
    return result


@router.get("/me", response_model=UserResponse)
def current_user(
    session: DatabaseSession,
    principal: CurrentPrincipal,
) -> UserResponse:
    user = UserService(session).get(principal.id)
    return UserResponse.model_validate(user)


@router.post("/password", status_code=status.HTTP_204_NO_CONTENT)
def change_own_password(
    payload: SelfPasswordUpdate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> Response:
    """Change one's own password, proving knowledge of the current one.

    Every other session of this user is revoked: a password change is the
    action taken when a session is believed stolen, and leaving the thief's
    session alive would defeat it.
    """

    settings: ServerSettings = request.app.state.settings
    service = UserService(session, password_parameters=password_parameters(settings))
    user = service.get(principal.id)
    service.authenticate(user.username, payload.current_password)
    service.set_password(user, payload.new_password)
    sessions = SessionService(
        session,
        ttl=timedelta(minutes=settings.session_ttl_minutes),
    )
    sessions.revoke_all_for_user(user.id)
    AuditLogService(session).record(
        AuditLogAction.USER_PASSWORD_CHANGED,
        actor=principal,
        target_type="user",
        target_id=user.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"self_service": True},
    )
    session.commit()
    result = Response(status_code=status.HTTP_204_NO_CONTENT)
    clear_session_cookies(
        result,
        secure=settings.session_cookie_secure,
        samesite=settings.session_cookie_samesite,
    )
    return result
