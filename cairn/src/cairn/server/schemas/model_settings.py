from datetime import datetime

from pydantic import Field, SecretStr, field_validator

from cairn.model_provider import ModelProvider, normalize_provider_base_url
from cairn.server.schemas.common import StrictModel


class ModelProviderUpdate(StrictModel):
    provider: ModelProvider
    base_url: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=255)
    api_key: SecretStr | None = Field(default=None, max_length=16_384)

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str) -> str:
        return normalize_provider_base_url(value)

    @field_validator("model")
    @classmethod
    def normalize_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(character.isspace() for character in normalized):
            raise ValueError("model must be a non-empty single token")
        if not normalized.isascii():
            raise ValueError("model must contain ASCII characters only")
        return normalized


class ModelDiscoveryRequest(StrictModel):
    provider: ModelProvider
    base_url: str = Field(min_length=1, max_length=2048)
    api_key: SecretStr | None = Field(default=None, max_length=16_384)

    @field_validator("base_url")
    @classmethod
    def normalize_base_url(cls, value: str) -> str:
        return normalize_provider_base_url(value)


class ModelSummary(StrictModel):
    id: str = Field(min_length=1, max_length=255)
    display_name: str | None = Field(default=None, max_length=255)


class ModelDiscoveryResponse(StrictModel):
    models: list[ModelSummary] = Field(max_length=5000)


class ModelProviderStatus(StrictModel):
    configured: bool
    provider: ModelProvider | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_configured: bool = False
    updated_at: datetime | None = None
