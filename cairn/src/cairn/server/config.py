from functools import lru_cache
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class ServerSettings(BaseSettings):
    """Environment-backed configuration for the audit API server."""

    model_config = SettingsConfigDict(env_prefix="CAIRN_", extra="ignore")

    database_url: str = Field(min_length=1)
    api_prefix: str = "/api/v1"
    sql_echo: bool = False
    artifact_root: Path = Path("/tmp/cairn-artifacts")
    ingestion_work_root: Path = Path("/tmp/cairn-ingestion")
    secret_key_file: Path | None = None
    # Workbench-managed model configuration. Metadata is readable by the
    # Orchestrator; the API key inside the file is AES-GCM encrypted with the
    # same deployment master key used by other stored credentials.
    llm_provider_config_file: Path | None = None
    llm_provider_timeout_seconds: float = Field(default=30.0, ge=1.0, le=60.0)
    git_allowed_hosts: Annotated[list[str], NoDecode] = Field(default_factory=list)
    git_clone_timeout_seconds: int = Field(default=300, ge=10, le=3600)
    upload_max_bytes: int = Field(default=100 * 1024 * 1024, ge=1)
    snapshot_max_files: int = Field(default=100_000, ge=1)
    snapshot_max_total_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=1,
    )
    snapshot_max_file_bytes: int = Field(default=100 * 1024 * 1024, ge=1)
    snapshot_max_compression_ratio: int = Field(default=200, ge=1)
    snapshot_max_path_length: int = Field(default=1024, ge=64, le=4096)
    snapshot_max_path_depth: int = Field(default=64, ge=1, le=256)
    # Source viewing for the workbench (§10.6). Bounded independently of the
    # snapshot limits: a 100 MB file may live in a snapshot legitimately, but
    # nothing that size should ever be shipped to a browser tab.
    source_view_max_file_bytes: int = Field(default=2 * 1024 * 1024, ge=1024)
    source_view_max_lines: int = Field(default=4000, ge=1, le=100_000)
    # Session and password settings (§9.8). `session_cookie_secure` defaults to
    # True; a local HTTP development run has to turn it off explicitly, which
    # makes an insecure deployment a deliberate act rather than a default.
    session_ttl_minutes: int = Field(default=720, ge=5, le=43_200)
    session_cookie_secure: bool = True
    session_cookie_samesite: Literal["strict", "lax"] = "strict"
    password_hash_memory_kib: int = Field(default=65_536, ge=8, le=4_194_304)
    password_hash_iterations: int = Field(default=3, ge=1, le=64)
    password_hash_lanes: int = Field(default=4, ge=1, le=64)
    # Health probes shown on the dashboard (§10.2). Empty means "not
    # configured", which the dashboard reports as unknown rather than down.
    sandbox_manager_url: str = ""
    llm_gateway_url: str = ""
    health_probe_timeout_seconds: float = Field(default=1.5, ge=0.1, le=10.0)
    # Built by `npm run build` in cairn/web. Absent in a pure-API deployment,
    # in which case no static routes are registered at all.
    static_root: Path = Path(__file__).resolve().parent / "static"

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("database_url must not be empty")
        return value

    @field_validator("git_allowed_hosts", mode="before")
    @classmethod
    def parse_git_allowed_hosts(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip().lower() for item in value.split(",") if item.strip()]
        return value


@lru_cache
def get_settings() -> ServerSettings:
    return ServerSettings()
