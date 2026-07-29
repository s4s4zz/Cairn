from datetime import timedelta
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAdmin, client_ip
from cairn.server.auth.sessions import SessionService
from cairn.server.config import ServerSettings
from cairn.server.domain.enums import AuditLogAction, UserRole
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.routers.auth import password_parameters
from cairn.server.schemas.auth import (
    PasswordUpdate,
    UserCreate,
    UserPage,
    UserResponse,
    UserUpdate,
)
from cairn.server.schemas.common import PageMeta
from cairn.server.services.users import UserFilters, UserService


router = APIRouter(prefix="/users", tags=["users"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def _service(request: Request, session: Session) -> UserService:
    settings: ServerSettings = request.app.state.settings
    return UserService(session, password_parameters=password_parameters(settings))


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> UserResponse:
    user = _service(request, session).create(
        payload.username,
        payload.password,
        payload.role,
    )
    AuditLogService(session).record(
        AuditLogAction.USER_CREATED,
        actor=principal,
        target_type="user",
        target_id=user.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        # The role is the point of the record; the password is never referenced
        # here in any form, hashed or otherwise.
        detail={"username": user.username, "role": user.role},
    )
    session.commit()
    return UserResponse.model_validate(user)


@router.get("", response_model=UserPage)
def list_users(
    session: DatabaseSession,
    principal: RequireAdmin,
    role: UserRole | None = None,
    is_active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> UserPage:
    del principal
    users, total = UserService(session).list(
        UserFilters(role=role, is_active=is_active, limit=limit, offset=offset)
    )
    return UserPage(
        items=[UserResponse.model_validate(user) for user in users],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{user_id}", response_model=UserResponse)
def get_user(
    user_id: UUID,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> UserResponse:
    del principal
    return UserResponse.model_validate(UserService(session).get(user_id))


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: UUID,
    payload: UserUpdate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> UserResponse:
    service = _service(request, session)
    user = service.get(user_id)
    service.update(user, role=payload.role, is_active=payload.is_active)
    if payload.is_active is False or payload.role is not None:
        # A demotion or a deactivation has to reach the sessions already open,
        # or the old privileges live on until the cookie expires.
        settings: ServerSettings = request.app.state.settings
        SessionService(
            session,
            ttl=timedelta(minutes=settings.session_ttl_minutes),
        ).revoke_all_for_user(user.id)
    AuditLogService(session).record(
        AuditLogAction.USER_UPDATED,
        actor=principal,
        target_type="user",
        target_id=user.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"role": user.role, "is_active": user.is_active},
    )
    session.commit()
    session.refresh(user)
    return UserResponse.model_validate(user)


@router.post("/{user_id}/password", status_code=status.HTTP_204_NO_CONTENT)
def set_user_password(
    user_id: UUID,
    payload: PasswordUpdate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> Response:
    settings: ServerSettings = request.app.state.settings
    service = _service(request, session)
    user = service.get(user_id)
    service.set_password(user, payload.new_password)
    SessionService(
        session,
        ttl=timedelta(minutes=settings.session_ttl_minutes),
    ).revoke_all_for_user(user.id)
    AuditLogService(session).record(
        AuditLogAction.USER_PASSWORD_CHANGED,
        actor=principal,
        target_type="user",
        target_id=user.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"self_service": False},
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
