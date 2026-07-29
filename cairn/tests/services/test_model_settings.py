from pathlib import Path

import pytest

from cairn.model_provider import ModelProvider
from cairn.server.errors import DomainError
from cairn.server.schemas.model_settings import (
    ModelDiscoveryRequest,
    ModelProviderUpdate,
)
from cairn.server.services.model_settings import ModelSettingsService


def service(tmp_path: Path) -> ModelSettingsService:
    key_file = tmp_path / "master.key"
    key_file.write_bytes(b"s" * 32)
    return ModelSettingsService(tmp_path / "provider.json", key_file)


def test_status_update_and_key_reuse_never_return_the_secret(tmp_path) -> None:
    settings = service(tmp_path)
    assert settings.status().model_dump(mode="json") == {
        "configured": False,
        "provider": None,
        "base_url": None,
        "model": None,
        "api_key_configured": False,
        "updated_at": None,
    }

    created = settings.update(
        ModelProviderUpdate(
            provider=ModelProvider.OPENAI,
            base_url="https://api.openai.com",
            model="gpt-5",
            api_key="sk-service-secret",
        )
    )
    updated = settings.update(
        ModelProviderUpdate(
            provider=ModelProvider.OPENAI,
            base_url="https://api.openai.com",
            model="gpt-5-mini",
        )
    )

    assert created.configured is True
    assert updated.model == "gpt-5-mini"
    assert "api_key" not in updated.model_dump(mode="json")
    assert settings.store.read().api_key.get_secret_value() == "sk-service-secret"


def test_provider_or_base_url_change_requires_a_new_key(tmp_path) -> None:
    settings = service(tmp_path)
    settings.update(
        ModelProviderUpdate(
            provider=ModelProvider.OPENAI,
            base_url="https://api.openai.com",
            model="gpt-5",
            api_key="sk-service-secret",
        )
    )

    with pytest.raises(DomainError) as raised:
        settings.update(
            ModelProviderUpdate(
                provider=ModelProvider.ANTHROPIC,
                base_url="https://api.anthropic.com",
                model="claude-opus-4-1",
            )
        )

    assert raised.value.error_code == "model_provider_key_required"
    assert raised.value.http_status == 422


def test_discovery_can_use_the_stored_key_without_exposing_it(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = service(tmp_path)
    settings.update(
        ModelProviderUpdate(
            provider=ModelProvider.ANTHROPIC,
            base_url="https://api.anthropic.com",
            model="claude-opus-4-1",
            api_key="sk-ant-service-secret",
        )
    )
    captured = {}

    def fake_list(configuration, *, timeout_seconds):  # noqa: ANN001
        captured["key"] = configuration.api_key.get_secret_value()
        captured["timeout"] = timeout_seconds
        return [{"id": "claude-opus-4-1", "display_name": "Claude Opus"}]

    monkeypatch.setattr(
        "cairn.server.services.model_settings.list_provider_models",
        fake_list,
    )

    result = settings.discover(
        ModelDiscoveryRequest(
            provider=ModelProvider.ANTHROPIC,
            base_url="https://api.anthropic.com",
        )
    )

    assert result.models[0].id == "claude-opus-4-1"
    assert captured == {"key": "sk-ant-service-secret", "timeout": 30.0}
    assert "sk-ant-service-secret" not in repr(result)
