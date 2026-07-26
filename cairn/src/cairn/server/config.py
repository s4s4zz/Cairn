from functools import lru_cache
from pathlib import Path
from typing import Annotated

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
