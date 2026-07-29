from typing import Annotated

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAdmin
from cairn.server.domain.enums import AuditLogAction
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.auth import AuditLogEntryResponse, AuditLogPage
from cairn.server.schemas.common import PageMeta


router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=AuditLogPage)
def list_audit_logs(
    session: DatabaseSession,
    principal: RequireAdmin,
    action: AuditLogAction | None = None,
    actor_username: Annotated[str | None, Query(max_length=64)] = None,
    target_type: Annotated[str | None, Query(max_length=64)] = None,
    target_id: Annotated[str | None, Query(max_length=128)] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditLogPage:
    """Read the operator audit log.

    Read-only by construction: there is no write, edit or delete endpoint for
    this table anywhere in the API, so the log cannot be curated by the people
    it records.
    """

    del principal
    entries, total = AuditLogService(session).list(
        action=action,
        actor_username=actor_username,
        target_type=target_type,
        target_id=target_id,
        limit=limit,
        offset=offset,
    )
    return AuditLogPage(
        items=[AuditLogEntryResponse.model_validate(entry) for entry in entries],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )
