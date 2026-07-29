from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAdmin, client_ip
from cairn.server.domain.enums import AuditLogAction
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.credentials import (
    GitCredentialCreate,
    GitCredentialResponse,
)
from cairn.server.services.credentials import GitCredentialService


router = APIRouter(prefix="/git-credentials", tags=["source-ingestion"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "",
    response_model=GitCredentialResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_git_credential(
    credential: GitCredentialCreate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> GitCredentialResponse:
    secret = GitCredentialService(
        session,
        request.app.state.settings.secret_key_file,
    ).create(credential)
    AuditLogService(session).record(
        AuditLogAction.CREDENTIAL_CREATED,
        actor=principal,
        target_type="git_credential",
        target_id=secret.reference,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        # Reference and kind only. The token or key itself exists in one place,
        # encrypted, and the audit log is not going to become a second one.
        detail={"kind": secret.kind},
    )
    session.commit()
    return GitCredentialResponse.model_validate(secret)


@router.delete(
    "/{reference}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_git_credential(
    reference: str,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> Response:
    GitCredentialService(
        session,
        request.app.state.settings.secret_key_file,
    ).delete(reference)
    AuditLogService(session).record(
        AuditLogAction.CREDENTIAL_DELETED,
        actor=principal,
        target_type="git_credential",
        target_id=reference,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
