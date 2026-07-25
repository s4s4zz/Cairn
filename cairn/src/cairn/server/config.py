from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerSettings(BaseSettings):
    """Environment-backed configuration for the audit API server."""

    model_config = SettingsConfigDict(env_prefix="CAIRN_", extra="ignore")

    database_url: str = Field(min_length=1)
    api_prefix: str = "/api/v1"
    sql_echo: bool = False

    @field_validator("database_url")
    @classmethod
    def validate_database_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("database_url must not be empty")
        return value


@lru_cache
def get_settings() -> ServerSettings:
    return ServerSettings()
