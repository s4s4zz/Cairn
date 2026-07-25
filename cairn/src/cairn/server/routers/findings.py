from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from cairn.server.domain.enums import FindingSeverity, FindingStatus
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.findings import (
    FindingDetail,
    FindingFilters,
    FindingPage,
    FindingResponse,
)
from cairn.server.services.findings import FindingService


router = APIRouter(prefix="/findings", tags=["findings"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=FindingPage)
def list_findings(
    session: DatabaseSession,
    audit_run_id: UUID | None = None,
    cwe_id: Annotated[
        str | None,
        Query(pattern=r"^CWE-[0-9]+$"),
    ] = None,
    severity: FindingSeverity | None = None,
    finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingPage:
    filters = FindingFilters(
        audit_run_id=audit_run_id,
        cwe_id=cwe_id,
        severity=severity,
        status=finding_status,
        limit=limit,
        offset=offset,
    )
    findings, total = FindingService(session).list(filters)
    return FindingPage(
        items=[FindingResponse.model_validate(item) for item in findings],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{finding_id}", response_model=FindingDetail)
def get_finding(finding_id: UUID, session: DatabaseSession) -> FindingDetail:
    finding = FindingService(session).get(finding_id)
    return FindingDetail.model_validate(finding)
