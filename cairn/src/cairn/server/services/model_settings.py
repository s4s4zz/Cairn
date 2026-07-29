from datetime import UTC, datetime
from pathlib import Path

from cairn.gateway.upstream import ModelListError, list_provider_models
from cairn.model_provider import (
    ModelProviderConfiguration,
    ModelProviderConfigError,
    ModelProviderConfigStore,
    ModelProviderMetadata,
    ModelProviderNotConfigured,
    load_model_config_key,
)
from cairn.server.errors import DomainError
from cairn.server.schemas.model_settings import (
    ModelDiscoveryRequest,
    ModelDiscoveryResponse,
    ModelProviderStatus,
    ModelProviderUpdate,
    ModelSummary,
)


class ModelSettingsService:
    def __init__(
        self,
        config_file: Path | None,
        key_file: Path | None,
        *,
        timeout_seconds: float = 30.0,
    ) -> None:
        if config_file is None:
            raise DomainError(
                "model_provider_store_unavailable",
                "Model provider storage is not configured",
                503,
            )
        try:
            key = load_model_config_key(key_file)
        except ModelProviderConfigError as exc:
            raise DomainError(
                "model_provider_store_unavailable",
                "Model provider encryption key is unavailable",
                503,
            ) from exc
        self.store = ModelProviderConfigStore(config_file, key)
        self.timeout_seconds = timeout_seconds

    def status(self) -> ModelProviderStatus:
        try:
            metadata = self.store.read_metadata()
        except ModelProviderNotConfigured:
            return ModelProviderStatus(configured=False)
        except ModelProviderConfigError as exc:
            raise DomainError(
                "model_provider_store_unavailable",
                "Model provider configuration is unavailable",
                503,
            ) from exc
        return ModelProviderStatus(
            configured=True,
            provider=metadata.provider,
            base_url=metadata.base_url,
            model=metadata.model,
            api_key_configured=True,
            updated_at=metadata.updated_at,
        )

    def update(self, request: ModelProviderUpdate) -> ModelProviderStatus:
        api_key = self._api_key(
            request.provider,
            request.base_url,
            request.api_key.get_secret_value() if request.api_key is not None else None,
        )
        try:
            metadata = self.store.write(
                provider=request.provider,
                base_url=request.base_url,
                model=request.model,
                api_key=api_key,
            )
        except ModelProviderConfigError as exc:
            raise DomainError(
                "model_provider_store_unavailable",
                "Model provider configuration could not be saved",
                503,
            ) from exc
        return ModelProviderStatus(
            configured=True,
            provider=metadata.provider,
            base_url=metadata.base_url,
            model=metadata.model,
            api_key_configured=True,
            updated_at=metadata.updated_at,
        )

    def discover(self, request: ModelDiscoveryRequest) -> ModelDiscoveryResponse:
        api_key = self._api_key(
            request.provider,
            request.base_url,
            request.api_key.get_secret_value() if request.api_key is not None else None,
        )
        configuration = ModelProviderConfiguration(
            metadata=ModelProviderMetadata(
                revision="0" * 32,
                provider=request.provider,
                base_url=request.base_url,
                model="model-discovery",
                updated_at=datetime.now(UTC),
            ),
            api_key=api_key,
        )
        try:
            models = list_provider_models(
                configuration,
                timeout_seconds=self.timeout_seconds,
            )
        except ModelListError as exc:
            raise DomainError(exc.code, exc.message, exc.http_status) from exc
        return ModelDiscoveryResponse(
            models=[ModelSummary.model_validate(model) for model in models]
        )

    def _api_key(self, provider, base_url: str, supplied: str | None) -> str:  # noqa: ANN001
        if supplied is not None and supplied.strip():
            return supplied.strip()
        try:
            current = self.store.read()
        except ModelProviderNotConfigured as exc:
            raise DomainError(
                "model_provider_key_required",
                "An API key is required for the model provider",
                422,
            ) from exc
        except ModelProviderConfigError as exc:
            raise DomainError(
                "model_provider_store_unavailable",
                "Stored model provider key is unavailable",
                503,
            ) from exc
        metadata = current.metadata
        if metadata.provider != provider or metadata.base_url != base_url:
            raise DomainError(
                "model_provider_key_required",
                "A new API key is required when the provider or Base URL changes",
                422,
            )
        return current.api_key.get_secret_value()
