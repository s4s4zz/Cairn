from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAnyRole, RequireAuditor, client_ip
from cairn.server.domain.enums import AuditLogAction, SourceType
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.repositories import (
    RepositoryCreate,
    RepositoryFilters,
    RepositoryPage,
    RepositoryResponse,
)
from cairn.server.services.repositories import RepositoryService


router = APIRouter(prefix="/repositories", tags=["repositories"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "",
    response_model=RepositoryResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_repository(
    payload: RepositoryCreate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> RepositoryResponse:
    repository = RepositoryService(session).create(payload, actor=principal.username)
    AuditLogService(session).record(
        AuditLogAction.REPOSITORY_CREATED,
        actor=principal,
        target_type="repository",
        target_id=repository.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"name": repository.name, "source_type": repository.source_type},
    )
    session.commit()
    return RepositoryResponse.model_validate(repository)


@router.get("", response_model=RepositoryPage)
def list_repositories(
    session: DatabaseSession,
    principal: RequireAnyRole,
    source_type: SourceType | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RepositoryPage:
    del principal
    filters = RepositoryFilters(
        source_type=source_type,
        limit=limit,
        offset=offset,
    )
    repositories, total = RepositoryService(session).list(filters)
    return RepositoryPage(
        items=[RepositoryResponse.model_validate(item) for item in repositories],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{repository_id}", response_model=RepositoryResponse)
def get_repository(
    repository_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> RepositoryResponse:
    del principal
    repository = RepositoryService(session).get(repository_id)
    return RepositoryResponse.model_validate(repository)


@router.delete("/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_repository(
    repository_id: UUID,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> Response:
    RepositoryService(session).delete(repository_id)
    AuditLogService(session).record(
        AuditLogAction.REPOSITORY_DELETED,
        actor=principal,
        target_type="repository",
        target_id=repository_id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
