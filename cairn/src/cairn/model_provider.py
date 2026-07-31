from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from enum import StrEnum
import json
import os
from pathlib import Path
import secrets
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ConfigDict, Field, SecretStr, field_validator
from pydantic import BaseModel


class ModelProvider(StrEnum):
    OPENAI = "openai"
    # The Anthropic Messages API reached with `Authorization: Bearer`, which is
    # the ANTHROPIC_AUTH_TOKEN convention every compatible third-party gateway
    # speaks.
    ANTHROPIC = "anthropic"
    # The official API's own scheme, `x-api-key`, i.e. ANTHROPIC_API_KEY.
    ANTHROPIC_KEY = "anthropic-key"


DEFAULT_PROVIDER_URLS: dict[ModelProvider, str] = {
    ModelProvider.OPENAI: "https://api.openai.com",
    # Bearer-authenticated deployments are third-party gateways with no
    # canonical host, so the operator always supplies the URL.
    ModelProvider.ANTHROPIC: "",
    ModelProvider.ANTHROPIC_KEY: "https://api.anthropic.com",
}

_CONFIG_VERSION = 1
_KEY_VERSION = 1


class ModelProviderConfigError(ValueError):
    pass


class ModelProviderNotConfigured(ModelProviderConfigError):
    pass


def load_model_config_key(path: Path | None) -> bytes:
    if path is None:
        raise ModelProviderConfigError("model provider master key is not configured")
    try:
        encoded = path.read_bytes()
    except OSError as exc:
        raise ModelProviderConfigError("model provider master key is unavailable") from exc
    if len(encoded) == 32:
        return encoded
    stripped = encoded.strip()
    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModelProviderConfigError("model provider master key is invalid") from exc
    if len(decoded) != 32:
        raise ModelProviderConfigError("model provider master key must contain 32 bytes")
    return decoded


def normalize_provider_base_url(value: str) -> str:
    """Validate and canonicalize a provider origin.

    Plaintext `http://` is accepted at any host: self-hosted gateways commonly
    listen on a LAN address without a certificate, and rejecting them made the
    workbench unusable against them. The API key and every prompt therefore
    ride whatever transport the operator names, so a plaintext origin must be
    reachable only over a network the deployment already trusts.

    The remaining checks stand — an origin carrying embedded credentials, a
    query, a fragment, or a traversable path is a misconfiguration whatever the
    scheme.
    """

    normalized = value.strip().rstrip("/")
    parsed = urlsplit(normalized)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("base_url must be an HTTP(S) service URL")
    if any(part in {".", ".."} for part in parsed.path.split("/")):
        raise ValueError("base_url path must be normalized")
    return normalized


def provider_endpoint(base_url: str, path: str) -> str:
    """Join a provider base URL with a canonical `/v1/...` endpoint.

    OpenAI-compatible deployments commonly expose either the service origin or
    an origin already ending in `/v1`. Supporting both avoids accidental
    `/v1/v1/...` requests while keeping the stored URL explicit.
    """

    normalized = normalize_provider_base_url(base_url)
    if normalized.endswith("/v1") and path.startswith("/v1/"):
        path = path[3:]
    return f"{normalized}{path}"


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ModelProviderMetadata(_StrictModel):
    version: int = Field(default=_CONFIG_VERSION, ge=1, le=1)
    revision: str = Field(pattern=r"^[0-9a-f]{32}$")
    provider: ModelProvider
    base_url: str = Field(min_length=1, max_length=2048)
    model: str = Field(min_length=1, max_length=255)
    updated_at: datetime

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return normalize_provider_base_url(value)

    @field_validator("model")
    @classmethod
    def validate_model(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(character.isspace() for character in normalized):
            raise ValueError("model must be a non-empty single token")
        if not normalized.isascii():
            raise ValueError("model must contain ASCII characters only")
        return normalized

    @field_validator("updated_at")
    @classmethod
    def normalize_updated_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=UTC)
        return value.astimezone(UTC)


class ModelProviderConfiguration(_StrictModel):
    metadata: ModelProviderMetadata
    api_key: SecretStr = Field(min_length=1, max_length=16_384)

    @field_validator("api_key")
    @classmethod
    def validate_api_key(cls, value: SecretStr) -> SecretStr:
        raw = value.get_secret_value().strip()
        if not raw:
            raise ValueError("api_key must not be blank")
        if not raw.isascii() or any(ord(character) < 33 or ord(character) > 126 for character in raw):
            raise ValueError("api_key must contain printable ASCII characters only")
        return SecretStr(raw)


class _EncryptedProviderFile(_StrictModel):
    metadata: ModelProviderMetadata
    key_version: int = Field(default=_KEY_VERSION, ge=1, le=1)
    nonce: str = Field(min_length=16, max_length=16)
    ciphertext: str = Field(min_length=24, max_length=65_536)


def _canonical_metadata(metadata: ModelProviderMetadata) -> bytes:
    return json.dumps(
        metadata.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ModelProviderConfigError("model provider configuration is corrupt") from exc


class ModelProviderConfigStore:
    """Atomic AES-256-GCM storage for the active model deployment.

    Provider metadata remains readable by the Orchestrator so it can bind the
    selected model into a short-lived grant. The API key is authenticated and
    encrypted; only the trusted API and Gateway receive the master key needed
    to decrypt it.
    """

    def __init__(self, path: Path, master_key: bytes | None = None) -> None:
        self.path = Path(path)
        if master_key is not None and len(master_key) != 32:
            raise ValueError("model provider storage requires a 32-byte master key")
        self._master_key = master_key

    def configured(self) -> bool:
        return self.path.is_file()

    def read_metadata(self) -> ModelProviderMetadata:
        return self._read_envelope().metadata

    def read(self) -> ModelProviderConfiguration:
        if self._master_key is None:
            raise ModelProviderConfigError("model provider master key is unavailable")
        envelope = self._read_envelope()
        nonce = _decode_base64(envelope.nonce)
        ciphertext = _decode_base64(envelope.ciphertext)
        if len(nonce) != 12:
            raise ModelProviderConfigError("model provider configuration is corrupt")
        try:
            plaintext = AESGCM(self._master_key).decrypt(
                nonce,
                ciphertext,
                _canonical_metadata(envelope.metadata),
            )
            payload = json.loads(plaintext)
        except (InvalidTag, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ModelProviderConfigError("model provider configuration cannot be decrypted") from exc
        if not isinstance(payload, dict) or set(payload) != {"api_key"}:
            raise ModelProviderConfigError("model provider configuration is corrupt")
        try:
            return ModelProviderConfiguration(
                metadata=envelope.metadata,
                api_key=payload["api_key"],
            )
        except (TypeError, ValueError) as exc:
            raise ModelProviderConfigError("model provider configuration is invalid") from exc

    def write(
        self,
        *,
        provider: ModelProvider,
        base_url: str,
        model: str,
        api_key: str,
    ) -> ModelProviderMetadata:
        if self._master_key is None:
            raise ModelProviderConfigError("model provider master key is unavailable")
        metadata = ModelProviderMetadata(
            revision=secrets.token_hex(16),
            provider=provider,
            base_url=base_url,
            model=model,
            updated_at=datetime.now(UTC),
        )
        configuration = ModelProviderConfiguration(
            metadata=metadata,
            api_key=api_key,
        )
        plaintext = json.dumps(
            {"api_key": configuration.api_key.get_secret_value()},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        nonce = os.urandom(12)
        envelope = _EncryptedProviderFile(
            metadata=metadata,
            nonce=base64.b64encode(nonce).decode("ascii"),
            ciphertext=base64.b64encode(
                AESGCM(self._master_key).encrypt(
                    nonce,
                    plaintext,
                    _canonical_metadata(metadata),
                )
            ).decode("ascii"),
        )
        self._atomic_write(
            json.dumps(
                envelope.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        )
        return metadata

    def _read_envelope(self) -> _EncryptedProviderFile:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ModelProviderNotConfigured("model provider is not configured") from exc
        except OSError as exc:
            raise ModelProviderConfigError("model provider configuration is unavailable") from exc
        try:
            payload = json.loads(raw)
            return _EncryptedProviderFile.model_validate(payload)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ModelProviderConfigError("model provider configuration is invalid") from exc

    def _atomic_write(self, content: str) -> None:
        try:
            self.path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
            temporary = self.path.with_name(
                f".{self.path.name}.{secrets.token_hex(8)}.tmp"
            )
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(temporary, self.path)
                os.chmod(self.path, 0o600)
            finally:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass
        except OSError as exc:
            raise ModelProviderConfigError("model provider configuration cannot be stored") from exc
