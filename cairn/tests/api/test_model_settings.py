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


@pytest.mark.parametrize(
    ("base_url", "reason"),
    [
        ("", "at least 1 character"),
        ("api.example.com", "must be an HTTP(S) service URL"),
        ("https://gateway.example.com/v1?beta=1", "must be an HTTP(S) service URL"),
        ("http://user:pw@gateway.example.com", "must be an HTTP(S) service URL"),
    ],
)
def test_rejected_discovery_names_the_base_url_it_could_not_accept(
    admin_client: TestClient,
    base_url: str,
    reason: str,
) -> None:
    response = admin_client.post(
        "/api/v1/model-provider/models",
        json={
            "provider": "anthropic",
            "base_url": base_url,
            "api_key": "sk-discovery-only-secret",
        },
    )

    assert response.status_code == 422
    body = response.json()
    assert body["error_code"] == "invalid_request"
    # A bare "request validation failed" left an operator no way to tell a
    # blank field from a rejected scheme.
    assert "base_url" in body["message"]
    assert reason in body["message"]
    assert "sk-discovery-only-secret" not in response.text


def test_rejected_discovery_never_echoes_the_key_that_failed_validation(
    admin_client: TestClient,
) -> None:
    response = admin_client.post(
        "/api/v1/model-provider/models",
        json={
            "provider": "anthropic",
            "base_url": "https://api.anthropic.com",
            "api_key": "sk-far-too-long-secret" + "x" * 16_384,
        },
    )

    assert response.status_code == 422
    assert "sk-far-too-long-secret" not in response.text
    assert "api_key" in response.json()["message"]


def test_a_plaintext_lan_gateway_can_be_enumerated_and_saved(
    admin_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Self-hosted gateways rarely hold a certificate for their LAN address."""

    captured = {}

    def fake_list(configuration, *, timeout_seconds):  # noqa: ANN001
        del timeout_seconds
        captured["base_url"] = configuration.metadata.base_url
        return [{"id": "qwen3-coder", "display_name": None}]

    monkeypatch.setattr(
        "cairn.server.services.model_settings.list_provider_models",
        fake_list,
    )

    discovered = admin_client.post(
        "/api/v1/model-provider/models",
        json={
            "provider": "anthropic",
            "base_url": "http://192.168.1.9:3000/",
            "api_key": "sk-lan-gateway-secret",
        },
    )
    saved = admin_client.put(
        "/api/v1/model-provider",
        json={
            "provider": "anthropic",
            "base_url": "http://192.168.1.9:3000",
            "model": "qwen3-coder",
            "api_key": "sk-lan-gateway-secret",
        },
    )

    assert discovered.status_code == 200
    assert discovered.json() == {"models": [{"id": "qwen3-coder", "display_name": None}]}
    # The trailing slash is normalized away before the origin is used or stored.
    assert captured["base_url"] == "http://192.168.1.9:3000"
    assert saved.status_code == 200
    assert saved.json()["base_url"] == "http://192.168.1.9:3000"
