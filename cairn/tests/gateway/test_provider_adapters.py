from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from cairn.gateway.app import create_gateway_app
from cairn.gateway.config import GatewaySettings
from cairn.gateway.tokens import ModelGrant, mint_grant
from cairn.gateway.upstream import UpstreamClient, list_provider_models
from cairn.model_provider import (
    ModelProvider,
    ModelProviderConfiguration,
    ModelProviderConfigStore,
    ModelProviderMetadata,
)


API_KEY = "sk-openai-provider-adapter-secret"
GRANT_KEY = b"provider-adapter-grant-signing-key"


class StubResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.payload = payload

    def json(self) -> object:
        return self.payload


class RecordingSession:
    def __init__(self) -> None:
        self.get_response = StubResponse(200, {"data": []})
        self.post_response = StubResponse(200, openai_response())
        self.get_calls: list[dict[str, Any]] = []
        self.post_calls: list[dict[str, Any]] = []

    def get(self, url: str, **kwargs: Any) -> StubResponse:
        self.get_calls.append({"url": url, **kwargs})
        return self.get_response

    def post(self, url: str, **kwargs: Any) -> StubResponse:
        self.post_calls.append({"url": url, **kwargs})
        return self.post_response

    def close(self) -> None:
        pass


def configuration(
    provider: ModelProvider,
    *,
    base_url: str | None = None,
    model: str = "gpt-5",
) -> ModelProviderConfiguration:
    return ModelProviderConfiguration(
        metadata=ModelProviderMetadata(
            revision="a" * 32,
            provider=provider,
            base_url=base_url
            or (
                "https://api.openai.invalid/v1"
                if provider is ModelProvider.OPENAI
                else "https://api.anthropic.invalid"
            ),
            model=model,
            updated_at=datetime.now(UTC),
        ),
        api_key=API_KEY,
    )


def openai_response() -> dict[str, object]:
    return {
        "id": "chatcmpl-cairn",
        "model": "gpt-5",
        "choices": [
            {
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": "I will inspect the symbol.",
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "read_symbol",
                                "arguments": '{"symbol":"demo.Action.run"}',
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 41,
            "completion_tokens": 17,
            "prompt_tokens_details": {"cached_tokens": 9},
        },
    }


def test_openai_chat_completions_adapter_preserves_tools_and_usage(tmp_path) -> None:
    api_key_file = tmp_path / "legacy.key"
    api_key_file.write_text("x" * 32, encoding="ascii")
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    settings = GatewaySettings(
        api_key_file=api_key_file,
        grant_key_file=grant_key_file,
        upstream_base_url="https://api.anthropic.invalid",
    )
    session = RecordingSession()
    client = UpstreamClient(settings, session=session)

    result = client.forward(
        {
            "model": "gpt-5",
            "system": "Review only the supplied source.",
            "max_tokens": 2048,
            "messages": [
                {"role": "user", "content": "Inspect demo.Action.run"},
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "call_0",
                            "name": "read_symbol",
                            "input": {"symbol": "demo.Action.run"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "call_0",
                            "content": "public void run() {}",
                        }
                    ],
                },
            ],
            "tools": [
                {
                    "name": "read_symbol",
                    "description": "Read one symbol",
                    "input_schema": {
                        "type": "object",
                        "properties": {"symbol": {"type": "string"}},
                        "required": ["symbol"],
                    },
                }
            ],
            "tool_choice": {"type": "tool", "name": "read_symbol"},
            "output_config": {
                "effort": "high",
                "format": {
                    "type": "json_schema",
                    "schema": {"type": "object", "properties": {}},
                },
            },
        },
        configuration(ModelProvider.OPENAI),
    )

    call = session.post_calls[-1]
    assert call["url"] == "https://api.openai.invalid/v1/chat/completions"
    assert call["headers"]["authorization"] == f"Bearer {API_KEY}"
    assert call["allow_redirects"] is False
    payload = call["json"]
    assert payload["max_completion_tokens"] == 2048
    assert [message["role"] for message in payload["messages"]] == [
        "system",
        "user",
        "assistant",
        "tool",
    ]
    assert payload["messages"][2]["tool_calls"][0]["function"]["name"] == (
        "read_symbol"
    )
    assert payload["tools"][0]["type"] == "function"
    assert payload["tool_choice"]["function"]["name"] == "read_symbol"
    assert payload["reasoning_effort"] == "high"
    assert payload["response_format"]["type"] == "json_schema"

    assert result["stop_reason"] == "tool_use"
    assert result["usage"] == {
        "input_tokens": 41,
        "output_tokens": 17,
        "cache_read_input_tokens": 9,
        "cache_creation_input_tokens": 0,
    }
    assert result["content"][0]["type"] == "text"
    assert result["content"][1] == {
        "type": "tool_use",
        "id": "call_1",
        "name": "read_symbol",
        "input": {"symbol": "demo.Action.run"},
    }


def test_model_enumeration_uses_the_selected_provider_auth_and_sorts() -> None:
    session = RecordingSession()
    session.get_response = StubResponse(
        200,
        {
            "data": [
                {"id": "z-model", "display_name": "Zulu"},
                {"id": "A-model"},
                {"id": "z-model", "display_name": "Latest Zulu"},
                {"not": "a model"},
            ]
        },
    )

    models = list_provider_models(
        configuration(ModelProvider.OPENAI),
        session=session,
    )

    assert models == [
        {"id": "A-model", "display_name": None},
        {"id": "z-model", "display_name": "Latest Zulu"},
    ]
    call = session.get_calls[-1]
    assert call["url"] == "https://api.openai.invalid/v1/models"
    assert call["headers"]["authorization"] == f"Bearer {API_KEY}"
    assert "x-api-key" not in call["headers"]
    assert call["allow_redirects"] is False

    session.get_calls.clear()
    list_provider_models(
        configuration(ModelProvider.ANTHROPIC, model="claude-opus-4-1"),
        session=session,
    )
    # A compatible gateway takes the key as a bearer token, the
    # ANTHROPIC_AUTH_TOKEN convention, over the same Messages wire format.
    bearer_call = session.get_calls[-1]
    assert bearer_call["headers"]["authorization"] == f"Bearer {API_KEY}"
    assert bearer_call["headers"]["anthropic-version"] == "2023-06-01"
    assert "x-api-key" not in bearer_call["headers"]

    session.get_calls.clear()
    list_provider_models(
        configuration(ModelProvider.ANTHROPIC_KEY, model="claude-opus-4-1"),
        session=session,
    )
    anthropic_call = session.get_calls[-1]
    assert anthropic_call["headers"]["x-api-key"] == API_KEY
    assert anthropic_call["headers"]["anthropic-version"] == "2023-06-01"
    assert "authorization" not in anthropic_call["headers"]


def test_messages_forwarding_picks_the_auth_header_the_deployment_expects(
    tmp_path,
) -> None:
    """Both Anthropic variants speak Messages; only the auth header differs."""

    api_key_file = tmp_path / "legacy.key"
    api_key_file.write_text("x" * 32, encoding="ascii")
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    settings = GatewaySettings(
        api_key_file=api_key_file,
        grant_key_file=grant_key_file,
        upstream_base_url="https://api.anthropic.invalid",
    )
    session = RecordingSession()
    session.post_response = StubResponse(
        200,
        {
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": "ok"}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 3, "output_tokens": 2},
        },
    )
    client = UpstreamClient(settings, session=session)
    body = {
        "model": "claude-opus-4-1",
        "max_tokens": 16,
        "messages": [{"role": "user", "content": "hi"}],
    }

    client.forward(body, configuration(ModelProvider.ANTHROPIC))
    bearer_call = session.post_calls[-1]
    assert bearer_call["url"] == "https://api.anthropic.invalid/v1/messages"
    assert bearer_call["headers"]["authorization"] == f"Bearer {API_KEY}"
    assert "x-api-key" not in bearer_call["headers"]

    client.forward(body, configuration(ModelProvider.ANTHROPIC_KEY))
    key_call = session.post_calls[-1]
    assert key_call["url"] == "https://api.anthropic.invalid/v1/messages"
    assert key_call["headers"]["x-api-key"] == API_KEY
    assert "authorization" not in key_call["headers"]


def test_gateway_reloads_workbench_provider_configuration_for_each_request(
    tmp_path: Path,
) -> None:
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    config_key_file = tmp_path / "master.key"
    config_key_file.write_bytes(b"m" * 32)
    provider_file = tmp_path / "provider.json"
    store = ModelProviderConfigStore(provider_file, b"m" * 32)
    store.write(
        provider=ModelProvider.OPENAI,
        base_url="https://api.openai.invalid",
        model="gpt-5",
        api_key=API_KEY,
    )
    settings = GatewaySettings(
        grant_key_file=grant_key_file,
        provider_config_file=provider_file,
        config_key_file=config_key_file,
        request_timeout_seconds=30,
    )
    session = RecordingSession()
    upstream = UpstreamClient(settings, session=session)
    grant = mint_grant(
        ModelGrant(
            audit_run_id="run-provider",
            task_id="task-provider",
            worker="semantic",
            model="gpt-5",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            max_requests=2,
            max_output_tokens=4096,
        ),
        GRANT_KEY,
    )

    with TestClient(create_gateway_app(settings, upstream=upstream)) as client:
        assert client.get("/health/ready").status_code == 200
        response = client.post(
            "/v1/messages",
            headers={"x-api-key": grant},
            json={
                "model": "gpt-5",
                "max_tokens": 1024,
                "messages": [{"role": "user", "content": "Review this"}],
            },
        )

    assert response.status_code == 200
    assert session.post_calls[-1]["url"] == (
        "https://api.openai.invalid/v1/chat/completions"
    )
    assert session.post_calls[-1]["headers"]["authorization"] == (
        f"Bearer {API_KEY}"
    )
