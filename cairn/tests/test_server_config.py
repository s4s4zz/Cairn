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


def test_git_allowlist_accepts_comma_separated_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CAIRN_DATABASE_URL", "postgresql+psycopg://cairn@db/cairn")
    monkeypatch.setenv(
        "CAIRN_GIT_ALLOWED_HOSTS",
        "git.example.com, *.corp.example.com",
    )

    settings = ServerSettings()

    assert settings.git_allowed_hosts == [
        "git.example.com",
        "*.corp.example.com",
    ]
