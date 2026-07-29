from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import (
    RequireAnyRole,
    RequireAuditor,
    RequireReviewer,
    client_ip,
)
from cairn.server.domain.enums import AuditLogAction, FindingSeverity, FindingStatus
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.findings import (
    FindingDetail,
    FindingFilters,
    FindingPage,
    FindingReviewRequest,
    FindingReverifyRequest,
    FindingReverifyResponse,
    FindingResponse,
    HumanReviewSummary,
)
from cairn.server.services.findings import FindingService


router = APIRouter(prefix="/findings", tags=["findings"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.get("", response_model=FindingPage)
def list_findings(
    session: DatabaseSession,
    principal: RequireAnyRole,
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
    del principal
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
def get_finding(
    finding_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> FindingDetail:
    del principal
    finding = FindingService(session).get(finding_id)
    return FindingDetail.model_validate(finding)


@router.post("/{finding_id}/review", response_model=FindingDetail)
def review_finding(
    finding_id: UUID,
    payload: FindingReviewRequest,
    request: Request,
    session: DatabaseSession,
    principal: RequireReviewer,
) -> FindingDetail:
    service = FindingService(session)
    finding, review = service.review(
        finding_id,
        payload,
        reviewer_id=principal.id,
    )
    AuditLogService(session).record(
        AuditLogAction.FINDING_REVIEWED,
        actor=principal,
        target_type="finding",
        target_id=finding.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "audit_run_id": str(finding.audit_run_id),
            "verdict": review.verdict,
            "original_severity": review.original_severity,
            "final_severity": review.final_severity,
        },
    )
    session.commit()
    return FindingDetail.model_validate(service.get(finding.id))


@router.post("/{finding_id}/reverify", response_model=FindingReverifyResponse)
def reverify_finding(
    finding_id: UUID,
    payload: FindingReverifyRequest,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> FindingReverifyResponse:
    service = FindingService(session)
    finding, review, task = service.request_reverification(
        finding_id,
        payload,
        reviewer_id=principal.id,
    )
    AuditLogService(session).record(
        AuditLogAction.FINDING_REVERIFY_REQUESTED,
        actor=principal,
        target_type="finding",
        target_id=finding.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "audit_run_id": str(finding.audit_run_id),
            "method": payload.method,
            "task_id": str(task.id),
        },
    )
    session.commit()
    return FindingReverifyResponse(
        finding=FindingResponse.model_validate(finding),
        review=HumanReviewSummary.model_validate(review),
        task_id=task.id,
    )
