from __future__ import annotations

from functools import lru_cache
import json
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from cairn.model_provider import normalize_provider_base_url

DEFAULT_MODEL_ALLOWLIST = ("claude-opus-5", "claude-opus-4-8")
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "::1", "localhost"})


class GatewaySettings(BaseSettings):
    """Configuration owned by the independently deployed LLM Gateway.

    The Gateway is the only component allowed to use the long-term model API
    key for inference (design spec §5.1 / §9.5). The trusted Admin API may
    decrypt it only to update configuration or enumerate models. The Gateway
    never touches PostgreSQL: the per-run budget ceiling travels inside the
    signed grant, so it can enforce policy without control-plane reachability.
    """

    model_config = SettingsConfigDict(env_prefix="CAIRN_LLM_", extra="ignore")

    # Legacy static Anthropic configuration remains supported for deployments
    # that have not adopted the workbench-managed provider file yet.
    api_key_file: Path | None = None
    grant_key_file: Path
    provider_config_file: Path | None = None
    config_key_file: Path | None = None
    # NoDecode keeps pydantic-settings from JSON-decoding the env value, so
    # CAIRN_LLM_MODEL_ALLOWLIST can be a plain comma-separated list.
    model_allowlist: Annotated[tuple[str, ...], NoDecode] = DEFAULT_MODEL_ALLOWLIST
    upstream_base_url: str = "https://api.anthropic.com"
    anthropic_version: str = "2023-06-01"
    max_request_bytes: int = Field(
        default=4 * 1024 * 1024,
        ge=1024,
        le=64 * 1024 * 1024,
    )
    max_output_tokens: int = Field(default=32_000, ge=1, le=1_000_000)
    request_timeout_seconds: float = Field(default=600.0, ge=1.0, le=3600.0)
    circuit_failure_threshold: int = Field(default=5, ge=1, le=1000)
    circuit_reset_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)
    refusal_fallback: bool = True
    # §9.5 requires the worker's token to be short-lived. The issuer sets the
    # expiry, but the verifier is the trust boundary, so it caps the remaining
    # lifetime it is willing to honour rather than trusting the minter.
    max_grant_lifetime_seconds: float = Field(default=3600.0, ge=60.0, le=86_400.0)

    @field_validator("model_allowlist", mode="before")
    @classmethod
    def split_model_allowlist(cls, value: object) -> object:
        if isinstance(value, str):
            candidate = value.strip()
            if candidate.startswith("["):
                # Tolerate a JSON array too, since that is what
                # pydantic-settings would otherwise have accepted.
                try:
                    decoded = json.loads(candidate)
                except json.JSONDecodeError as exc:
                    raise ValueError("model_allowlist is not a valid JSON array") from exc
                if not isinstance(decoded, list):
                    raise ValueError("model_allowlist must be a list of model names")
                return tuple(decoded)
            return tuple(part.strip() for part in candidate.split(",") if part.strip())
        return value

    @field_validator("model_allowlist")
    @classmethod
    def validate_model_allowlist(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("model_allowlist must name at least one model")
        for model in value:
            if not model or any(character.isspace() for character in model):
                raise ValueError("model_allowlist entries must be non-empty single tokens")
            if len(model) > 255:
                raise ValueError("model_allowlist entries must be at most 255 characters")
        if len(set(value)) != len(value):
            raise ValueError("model_allowlist entries must be distinct")
        return value

    @field_validator("upstream_base_url")
    @classmethod
    def validate_upstream_base_url(cls, value: str) -> str:
        return normalize_provider_base_url(value)

    @field_validator("anthropic_version")
    @classmethod
    def validate_anthropic_version(cls, value: str) -> str:
        value = value.strip()
        if not value or len(value) > 64 or any(character.isspace() for character in value):
            raise ValueError("anthropic_version must be a non-empty single token")
        if any(not (character.isascii() and (character.isalnum() or character in "-_.")) for character in value):
            raise ValueError("anthropic_version has invalid characters")
        return value

    @model_validator(mode="after")
    def validate_key_files(self) -> "GatewaySettings":
        if self.api_key_file is not None and self.api_key_file.resolve() == self.grant_key_file.resolve():
            raise ValueError("api_key_file and grant_key_file must be distinct")
        if (self.provider_config_file is None) != (self.config_key_file is None):
            raise ValueError(
                "provider_config_file and config_key_file must be configured together"
            )
        if self.provider_config_file is None and self.api_key_file is None:
            raise ValueError(
                "either provider_config_file or api_key_file must be configured"
            )
        return self


def read_key_file(path: Path) -> bytes:
    """Read a Gateway key file, rejecting anything unusable as a secret."""
    try:
        key = path.read_bytes().strip()
    except OSError as exc:
        raise ValueError("gateway key file is unavailable") from exc
    if not 32 <= len(key) <= 512:
        raise ValueError("gateway key must contain 32 to 512 bytes")
    if any(byte < 33 or byte > 126 for byte in key):
        raise ValueError("gateway key must contain printable ASCII bytes")
    return key


@lru_cache
def get_gateway_settings() -> GatewaySettings:
    return GatewaySettings()
