import pytest
from pydantic import ValidationError

from cairn.server.config import ServerSettings


def test_database_url_is_required() -> None:
    with pytest.raises(ValidationError):
        ServerSettings(database_url="")


def test_settings_accept_postgresql_url() -> None:
    settings = ServerSettings(
        database_url="postgresql+psycopg://cairn:secret@db/cairn"
    )

    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.api_prefix == "/api/v1"
