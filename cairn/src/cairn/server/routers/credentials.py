from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

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
) -> GitCredentialResponse:
    secret = GitCredentialService(
        session,
        request.app.state.settings.secret_key_file,
    ).create(credential)
    return GitCredentialResponse.model_validate(secret)


@router.delete(
    "/{reference}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def delete_git_credential(
    reference: str,
    request: Request,
    session: DatabaseSession,
) -> Response:
    GitCredentialService(
        session,
        request.app.state.settings.secret_key_file,
    ).delete(reference)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
