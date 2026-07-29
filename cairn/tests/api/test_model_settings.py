from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.persistence.models.identity import AuditLogEntry


def test_admin_can_save_provider_without_ever_receiving_the_api_key(
    admin_client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    before = admin_client.get("/api/v1/model-provider")
    saved = admin_client.put(
        "/api/v1/model-provider",
        json={
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-5",
            "api_key": "sk-api-endpoint-secret",
        },
    )
    after = admin_client.get("/api/v1/model-provider")

    assert before.status_code == 200
    assert before.json()["configured"] is False
    assert saved.status_code == 200
    assert after.status_code == 200
    assert after.json() == saved.json()
    assert saved.json()["api_key_configured"] is True
    assert "api_key" not in saved.json()
    assert "sk-api-endpoint-secret" not in saved.text
    assert "sk-api-endpoint-secret" not in after.text

    session = session_factory()
    try:
        entry = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "model_provider_updated"
            )
        ).one()
        assert entry.detail == {
            "provider": "openai",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-5",
        }
        assert "sk-api-endpoint-secret" not in repr(entry.detail)
    finally:
        session.close()


def test_admin_can_enumerate_models_with_an_unsaved_key(
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {}

    def fake_list(configuration, *, timeout_seconds):  # noqa: ANN001
        captured["provider"] = configuration.metadata.provider.value
        captured["key"] = configuration.api_key.get_secret_value()
        captured["timeout"] = timeout_seconds
        return [
            {"id": "gpt-5-mini", "display_name": None},
            {"id": "gpt-5", "display_name": "GPT-5"},
        ]

    monkeypatch.setattr(
        "cairn.server.services.model_settings.list_provider_models",
        fake_list,
    )

    response = admin_client.post(
        "/api/v1/model-provider/models",
        json={
            "provider": "openai",
            "base_url": "https://api.openai.com",
            "api_key": "sk-discovery-only-secret",
        },
    )

    assert response.status_code == 200
    assert response.json() == {
        "models": [
            {"id": "gpt-5-mini", "display_name": None},
            {"id": "gpt-5", "display_name": "GPT-5"},
        ]
    }
    assert captured == {
        "provider": "openai",
        "key": "sk-discovery-only-secret",
        "timeout": 30.0,
    }
    assert "sk-discovery-only-secret" not in response.text
