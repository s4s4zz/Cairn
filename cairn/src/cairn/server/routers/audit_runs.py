from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from cairn.server.domain.enums import AuditRunStatus
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.audit_runs import (
    AuditRunCreate,
    AuditRunFilters,
    AuditRunPage,
    AuditRunResponse,
)
from cairn.server.schemas.common import PageMeta
from cairn.server.services.audit_runs import AuditRunService


router = APIRouter(prefix="/audit-runs", tags=["audit-runs"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "",
    response_model=AuditRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_audit_run(
    request: AuditRunCreate,
    session: DatabaseSession,
) -> AuditRunResponse:
    audit_run = AuditRunService(session).create(request, actor="system")
    return AuditRunResponse.model_validate(audit_run)


@router.get("", response_model=AuditRunPage)
def list_audit_runs(
    session: DatabaseSession,
    repository_id: UUID | None = None,
    run_status: Annotated[AuditRunStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditRunPage:
    filters = AuditRunFilters(
        repository_id=repository_id,
        status=run_status,
        limit=limit,
        offset=offset,
    )
    runs, total = AuditRunService(session).list(filters)
    return AuditRunPage(
        items=[AuditRunResponse.model_validate(item) for item in runs],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{run_id}", response_model=AuditRunResponse)
def get_audit_run(run_id: UUID, session: DatabaseSession) -> AuditRunResponse:
    audit_run = AuditRunService(session).get(run_id)
    return AuditRunResponse.model_validate(audit_run)


@router.post("/{run_id}/cancel", response_model=AuditRunResponse)
def cancel_audit_run(run_id: UUID, session: DatabaseSession) -> AuditRunResponse:
    audit_run = AuditRunService(session).request_cancel(run_id, actor="system")
    return AuditRunResponse.model_validate(audit_run)
