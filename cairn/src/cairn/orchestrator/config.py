from pathlib import Path
from urllib.parse import urlsplit

from pydantic import Field, field_validator

from cairn.server.config import ServerSettings


class OrchestratorSettings(ServerSettings):
    """Configuration for the standalone deterministic-analysis worker."""

    sandbox_api_url: str = "http://cairn-sandbox-manager:8001"
    sandbox_auth_token_file: Path
    orchestrator_poll_interval_seconds: float = Field(
        default=1.0,
        ge=0.1,
        le=60,
    )
    orchestrator_wait_seconds: float = Field(default=5.0, ge=0.1, le=30)
    orchestrator_worker_name: str = Field(
        default="deterministic-orchestrator",
        min_length=1,
        max_length=255,
    )
    # The Orchestrator mints the short-lived model grants, so it holds the
    # grant SIGNING key. It deliberately has neither the provider decryption
    # key nor a plaintext API key; only public provider metadata is mounted.
    llm_gateway_url: str = "http://cairn-llm-gateway:8002"
    llm_grant_key_file: Path | None = None
    llm_grant_ttl_margin_seconds: float = Field(default=120.0, ge=10, le=3600)

    @field_validator("sandbox_api_url", "llm_gateway_url")
    @classmethod
    def validate_sandbox_api_url(cls, value: str) -> str:
        value = value.strip().rstrip("/")
        parsed = urlsplit(value)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/"}
        ):
            raise ValueError("sandbox_api_url must be an HTTP(S) service origin")
        return value
