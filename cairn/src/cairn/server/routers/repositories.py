from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.orm import Session

from cairn.server.domain.enums import SourceType
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
    request: RepositoryCreate,
    session: DatabaseSession,
) -> RepositoryResponse:
    repository = RepositoryService(session).create(request, actor="system")
    return RepositoryResponse.model_validate(repository)


@router.get("", response_model=RepositoryPage)
def list_repositories(
    session: DatabaseSession,
    source_type: SourceType | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> RepositoryPage:
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
) -> RepositoryResponse:
    repository = RepositoryService(session).get(repository_id)
    return RepositoryResponse.model_validate(repository)


@router.delete("/{repository_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_repository(repository_id: UUID, session: DatabaseSession) -> Response:
    RepositoryService(session).delete(repository_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
