from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAdmin, client_ip
from cairn.server.domain.enums import AuditLogAction
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.model_settings import (
    ModelDiscoveryRequest,
    ModelDiscoveryResponse,
    ModelProviderStatus,
    ModelProviderUpdate,
)
from cairn.server.services.model_settings import ModelSettingsService


router = APIRouter(prefix="/model-provider", tags=["system-settings"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


def _service(request: Request) -> ModelSettingsService:
    settings = request.app.state.settings
    return ModelSettingsService(
        settings.llm_provider_config_file,
        settings.secret_key_file,
        timeout_seconds=settings.llm_provider_timeout_seconds,
    )


@router.get("", response_model=ModelProviderStatus)
def get_model_provider(
    request: Request,
    principal: RequireAdmin,
) -> ModelProviderStatus:
    del principal
    return _service(request).status()


@router.put("", response_model=ModelProviderStatus)
def update_model_provider(
    command: ModelProviderUpdate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> ModelProviderStatus:
    result = _service(request).update(command)
    AuditLogService(session).record(
        AuditLogAction.MODEL_PROVIDER_UPDATED,
        actor=principal,
        target_type="model_provider",
        target_id=command.provider.value,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "provider": command.provider.value,
            "base_url": command.base_url,
            "model": command.model,
        },
    )
    session.commit()
    return result


@router.post("/models", response_model=ModelDiscoveryResponse)
def discover_models(
    command: ModelDiscoveryRequest,
    request: Request,
    principal: RequireAdmin,
) -> ModelDiscoveryResponse:
    del principal
    return _service(request).discover(command)
