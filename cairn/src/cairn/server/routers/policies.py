from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

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
    request: AuditPolicyCreate,
    session: DatabaseSession,
) -> AuditPolicyResponse:
    policy = AuditPolicyService(session).create_version(request)
    return AuditPolicyResponse.model_validate(policy)


@router.get("", response_model=AuditPolicyPage)
def list_policies(
    session: DatabaseSession,
    name: Annotated[str | None, Query(min_length=1, max_length=255)] = None,
    active: bool | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditPolicyPage:
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
def get_policy(policy_id: UUID, session: DatabaseSession) -> AuditPolicyResponse:
    policy = AuditPolicyService(session).get(policy_id)
    return AuditPolicyResponse.model_validate(policy)
