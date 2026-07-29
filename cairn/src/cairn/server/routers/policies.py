from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAdmin, RequireAnyRole, client_ip
from cairn.server.domain.enums import AuditLogAction
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.policies import (
    AuditPolicyCreate,
    AuditPolicyFilters,
    AuditPolicyPage,
    AuditPolicyResponse,
)
from cairn.server.services.policies import AuditPolicyService


router = APIRouter(prefix="/audit-policies", tags=["audit-policies"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "",
    response_model=AuditPolicyResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_policy(
    payload: AuditPolicyCreate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> AuditPolicyResponse:
    """Create a policy version.

    Admin-only per §9.8: a policy decides which scanners run and whether
    dynamic verification may be switched off, so it is a security control, not
    a per-run preference.
    """

    policy = AuditPolicyService(session).create_version(payload)
    AuditLogService(session).record(
        AuditLogAction.POLICY_CREATED,
        actor=principal,
        target_type="audit_policy",
        target_id=policy.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"name": policy.name, "version": policy.version},
    )
    session.commit()
    return AuditPolicyResponse.model_validate(policy)


@router.get("", response_model=AuditPolicyPage)
def list_policies(
    session: DatabaseSession,
    principal: RequireAnyRole,
    name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditPolicyPage:
    del principal
    filters = AuditPolicyFilters(
        name=name,
        active=active,
        limit=limit,
        offset=offset,
    )
    policies, total = AuditPolicyService(session).list(filters)
    return AuditPolicyPage(
        items=[AuditPolicyResponse.model_validate(item) for item in policies],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{policy_id}", response_model=AuditPolicyResponse)
def get_policy(
    policy_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> AuditPolicyResponse:
    del principal
    policy = AuditPolicyService(session).get(policy_id)
    return AuditPolicyResponse.model_validate(policy)
