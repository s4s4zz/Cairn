from __future__ import annotations

import json
import logging
from typing import Any

import requests

from cairn.gateway.config import GatewaySettings
from cairn.gateway.errors import upstream_timeout, upstream_unavailable
from cairn.model_provider import (
    ModelProvider,
    ModelProviderConfiguration,
    ModelProviderMetadata,
    provider_endpoint,
)

LOG = logging.getLogger(__name__)

FALLBACK_BETA_HEADER = "server-side-fallback-2026-07-01"
MESSAGES_PATH = "/v1/messages"
OPENAI_CHAT_PATH = "/v1/chat/completions"
MODELS_PATH = "/v1/models"

STRIPPED_CLIENT_HEADERS = (
    "x-api-key",
    "authorization",
    "anthropic-beta",
)


class ModelListError(RuntimeError):
    def __init__(self, code: str, message: str, *, http_status: int = 502) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def anthropic_auth_headers(
    provider: ModelProvider,
    api_key: str,
    anthropic_version: str,
) -> dict[str, str]:
    """Auth headers for the Anthropic Messages API.

    Compatible gateways authenticate with `Authorization: Bearer` — the
    ANTHROPIC_AUTH_TOKEN convention — while the official API takes the key in
    `x-api-key`. Both speak the same wire format, so only the header differs.
    """

    headers = {"anthropic-version": anthropic_version}
    if provider is ModelProvider.ANTHROPIC_KEY:
        headers["x-api-key"] = api_key
    else:
        headers["authorization"] = f"Bearer {api_key}"
    return headers


def list_provider_models(
    configuration: ModelProviderConfiguration,
    *,
    session: requests.Session | None = None,
    timeout_seconds: float = 30.0,
    anthropic_version: str = "2023-06-01",
) -> list[dict[str, str | None]]:
    owned_session = session is None
    active_session = session or requests.Session()
    metadata = configuration.metadata
    headers = {"accept": "application/json"}
    if metadata.provider is ModelProvider.OPENAI:
        headers["authorization"] = f"Bearer {configuration.api_key.get_secret_value()}"
    else:
        headers.update(
            anthropic_auth_headers(
                metadata.provider,
                configuration.api_key.get_secret_value(),
                anthropic_version,
            )
        )
    try:
        response = active_session.get(
            provider_endpoint(metadata.base_url, MODELS_PATH),
            headers=headers,
            timeout=min(timeout_seconds, 30.0),
            allow_redirects=False,
        )
    except requests.Timeout as exc:
        raise ModelListError(
            "model_provider_timeout",
            "Model provider timed out",
            http_status=504,
        ) from exc
    except requests.RequestException as exc:
        raise ModelListError(
            "model_provider_unavailable",
            "Model provider is unavailable",
        ) from exc
    finally:
        if owned_session:
            active_session.close()
    if response.status_code in {401, 403}:
        raise ModelListError(
            "model_provider_auth_failed",
            "Model provider rejected the API key",
            http_status=422,
        )
    if not 200 <= response.status_code < 300:
        raise ModelListError(
            "model_provider_unavailable",
            "Model provider is unavailable",
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise ModelListError(
            "model_provider_invalid_response",
            "Model provider returned invalid JSON",
        ) from exc
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        raise ModelListError(
            "model_provider_invalid_response",
            "Model provider returned no model list",
        )
    models: dict[str, str | None] = {}
    for item in data[:5000]:
        if not isinstance(item, dict):
            continue
        identifier = item.get("id")
        if not isinstance(identifier, str) or not identifier or len(identifier) > 255:
            continue
        display_name = item.get("display_name")
        models[identifier] = (
            display_name
            if isinstance(display_name, str) and 0 < len(display_name) <= 255
            else None
        )
    return [
        {"id": identifier, "display_name": models[identifier]}
        for identifier in sorted(models, key=str.casefold)
    ]


def _text_content(content: object) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: list[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "text" and isinstance(block.get("text"), str):
            parts.append(str(block["text"]))
    return "\n".join(parts)


def _tool_result_content(block: dict[str, object]) -> str:
    content = block.get("content")
    if isinstance(content, str):
        return content
    return _text_content(content)


def _openai_messages(body: dict[str, object]) -> list[dict[str, object]]:
    converted: list[dict[str, object]] = []
    system = body.get("system")
    system_text = _text_content(system)
    if system_text:
        converted.append({"role": "system", "content": system_text})

    raw_messages = body.get("messages")
    if not isinstance(raw_messages, list):
        return converted
    for message in raw_messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        content = message.get("content")
        if role in {"system", "developer"}:
            text = _text_content(content)
            if text:
                converted.append({"role": "system", "content": text})
            continue
        if role == "assistant":
            if isinstance(content, str):
                converted.append({"role": "assistant", "content": content})
                continue
            text_parts: list[str] = []
            tool_calls: list[dict[str, object]] = []
            for block in content if isinstance(content, list) else []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and isinstance(block.get("text"), str):
                    text_parts.append(str(block["text"]))
                if block.get("type") != "tool_use":
                    continue
                identifier = block.get("id")
                name = block.get("name")
                arguments = block.get("input", {})
                if not isinstance(identifier, str) or not isinstance(name, str):
                    continue
                tool_calls.append(
                    {
                        "id": identifier,
                        "type": "function",
                        "function": {
                            "name": name,
                            "arguments": json.dumps(
                                arguments if isinstance(arguments, dict) else {},
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        },
                    }
                )
            entry: dict[str, object] = {
                "role": "assistant",
                "content": "\n".join(text_parts) or None,
            }
            if tool_calls:
                entry["tool_calls"] = tool_calls
            converted.append(entry)
            continue
        if role != "user":
            continue
        if isinstance(content, str):
            converted.append({"role": "user", "content": content})
            continue
        text_parts: list[str] = []
        for block in content if isinstance(content, list) else []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "tool_result":
                tool_use_id = block.get("tool_use_id")
                if isinstance(tool_use_id, str) and tool_use_id:
                    converted.append(
                        {
                            "role": "tool",
                            "tool_call_id": tool_use_id,
                            "content": _tool_result_content(block),
                        }
                    )
                continue
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                text_parts.append(str(block["text"]))
        if text_parts:
            converted.append({"role": "user", "content": "\n".join(text_parts)})
    return converted


def _openai_tools(body: dict[str, object]) -> list[dict[str, object]] | None:
    raw_tools = body.get("tools")
    if not isinstance(raw_tools, list):
        return None
    tools: list[dict[str, object]] = []
    for tool in raw_tools:
        if not isinstance(tool, dict):
            continue
        name = tool.get("name")
        schema = tool.get("input_schema")
        if not isinstance(name, str) or not isinstance(schema, dict):
            continue
        function: dict[str, object] = {
            "name": name,
            "parameters": schema,
        }
        description = tool.get("description")
        if isinstance(description, str):
            function["description"] = description
        if tool.get("strict") is True:
            function["strict"] = True
        tools.append({"type": "function", "function": function})
    return tools


def _to_openai_request(body: dict[str, object]) -> dict[str, object]:
    payload: dict[str, object] = {
        "model": body.get("model"),
        "messages": _openai_messages(body),
    }
    max_tokens = body.get("max_tokens")
    if isinstance(max_tokens, int) and not isinstance(max_tokens, bool):
        payload["max_completion_tokens"] = max_tokens
    tools = _openai_tools(body)
    if tools:
        payload["tools"] = tools
    tool_choice = body.get("tool_choice")
    if isinstance(tool_choice, dict):
        choice_type = tool_choice.get("type")
        if choice_type == "none":
            payload["tool_choice"] = "none"
        elif choice_type == "auto":
            payload["tool_choice"] = "auto"
        elif choice_type == "tool" and isinstance(tool_choice.get("name"), str):
            payload["tool_choice"] = {
                "type": "function",
                "function": {"name": tool_choice["name"]},
            }
    output_config = body.get("output_config")
    if isinstance(output_config, dict):
        effort = output_config.get("effort")
        if isinstance(effort, str):
            payload["reasoning_effort"] = effort
        output_format = output_config.get("format")
        if isinstance(output_format, dict) and output_format.get("type") == "json_schema":
            schema = output_format.get("schema")
            if isinstance(schema, dict):
                payload["response_format"] = {
                    "type": "json_schema",
                    "json_schema": {
                        "name": "cairn_result",
                        "strict": True,
                        "schema": schema,
                    },
                }
    return payload


def _openai_stop_reason(choice: dict[str, object], message: dict[str, object]) -> str:
    if message.get("refusal"):
        return "refusal"
    finish_reason = choice.get("finish_reason")
    return {
        "tool_calls": "tool_use",
        "length": "max_tokens",
        "content_filter": "refusal",
        "stop": "end_turn",
    }.get(str(finish_reason), "end_turn")


def _from_openai_response(payload: dict[str, object]) -> dict[str, object]:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise ValueError("OpenAI response contains no completion choice")
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, dict):
        raise ValueError("OpenAI response contains no assistant message")
    content: list[dict[str, object]] = []
    text = message.get("content")
    if isinstance(text, str) and text:
        content.append({"type": "text", "text": text})
    tool_calls = message.get("tool_calls")
    if isinstance(tool_calls, list):
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            function = call.get("function")
            identifier = call.get("id")
            if not isinstance(function, dict) or not isinstance(identifier, str):
                continue
            name = function.get("name")
            arguments = function.get("arguments", "{}")
            if not isinstance(name, str):
                continue
            try:
                decoded_arguments = json.loads(arguments) if isinstance(arguments, str) else {}
            except json.JSONDecodeError:
                decoded_arguments = {}
            if not isinstance(decoded_arguments, dict):
                decoded_arguments = {}
            content.append(
                {
                    "type": "tool_use",
                    "id": identifier,
                    "name": name,
                    "input": decoded_arguments,
                }
            )
    usage = payload.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    prompt_details = usage.get("prompt_tokens_details")
    prompt_details = prompt_details if isinstance(prompt_details, dict) else {}
    stop_reason = _openai_stop_reason(choice, message)
    response: dict[str, object] = {
        "id": str(payload.get("id") or "openai-message"),
        "type": "message",
        "role": "assistant",
        "model": str(payload.get("model") or "unknown"),
        "content": content,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": int(usage.get("prompt_tokens") or 0),
            "output_tokens": int(usage.get("completion_tokens") or 0),
            "cache_read_input_tokens": int(prompt_details.get("cached_tokens") or 0),
            "cache_creation_input_tokens": 0,
        },
    }
    if stop_reason == "refusal":
        response["stop_details"] = {"category": "provider_refusal"}
    return response


class UpstreamClient:
    """Provider-aware egress leg with a stable Anthropic-shaped downstream."""

    def __init__(
        self,
        settings: GatewaySettings,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.settings = settings
        self.url = f"{settings.upstream_base_url}{MESSAGES_PATH}"
        self.session = session or requests.Session()

    def _legacy_configuration(
        self,
        body: dict[str, object],
        api_key: bytes,
    ) -> ModelProviderConfiguration:
        model = body.get("model")
        if not isinstance(model, str) or not model:
            model = self.settings.model_allowlist[0]
        return ModelProviderConfiguration(
            metadata=ModelProviderMetadata(
                revision="0" * 32,
                # The legacy path carries a bare official-API key, which
                # authenticates through `x-api-key`.
                provider=ModelProvider.ANTHROPIC_KEY,
                base_url=self.settings.upstream_base_url,
                model=model,
                updated_at="1970-01-01T00:00:00Z",
            ),
            api_key=api_key.decode("ascii"),
        )

    def forward(
        self,
        body: dict[str, object],
        configuration: ModelProviderConfiguration | bytes,
    ) -> dict[str, object]:
        if isinstance(configuration, bytes):
            configuration = self._legacy_configuration(body, configuration)
        if configuration.metadata.provider is ModelProvider.OPENAI:
            return self._forward_openai(body, configuration)
        return self._forward_anthropic(body, configuration)

    def _forward_anthropic(
        self,
        body: dict[str, object],
        configuration: ModelProviderConfiguration,
    ) -> dict[str, object]:
        payload = dict(body)
        payload.pop("stream", None)
        headers = {
            **anthropic_auth_headers(
                configuration.metadata.provider,
                configuration.api_key.get_secret_value(),
                self.settings.anthropic_version,
            ),
            "content-type": "application/json",
            "accept": "application/json",
        }
        if self.settings.refusal_fallback and "fallbacks" not in payload:
            payload["fallbacks"] = "default"
            headers["anthropic-beta"] = FALLBACK_BETA_HEADER
        decoded = self._post_json(
            provider_endpoint(configuration.metadata.base_url, MESSAGES_PATH),
            payload,
            headers,
        )
        return decoded

    def _forward_openai(
        self,
        body: dict[str, object],
        configuration: ModelProviderConfiguration,
    ) -> dict[str, object]:
        decoded = self._post_json(
            provider_endpoint(configuration.metadata.base_url, OPENAI_CHAT_PATH),
            _to_openai_request(body),
            {
                "authorization": f"Bearer {configuration.api_key.get_secret_value()}",
                "content-type": "application/json",
                "accept": "application/json",
            },
        )
        try:
            return _from_openai_response(decoded)
        except (TypeError, ValueError) as exc:
            raise upstream_unavailable() from exc

    def list_models(
        self,
        configuration: ModelProviderConfiguration,
    ) -> list[dict[str, str | None]]:
        return list_provider_models(
            configuration,
            session=self.session,
            timeout_seconds=self.settings.request_timeout_seconds,
            anthropic_version=self.settings.anthropic_version,
        )

    def _post_json(
        self,
        url: str,
        payload: dict[str, object],
        headers: dict[str, str],
    ) -> dict[str, object]:
        try:
            response = self.session.post(
                url,
                json=payload,
                headers=headers,
                timeout=self.settings.request_timeout_seconds,
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise upstream_timeout() from exc
        except requests.RequestException as exc:
            raise upstream_unavailable() from exc
        if not 200 <= response.status_code < 300:
            LOG.warning(
                "upstream model API rejected the request",
                extra={"upstream_status": response.status_code},
            )
            if response.status_code in {408, 504}:
                raise upstream_timeout()
            raise upstream_unavailable()
        try:
            decoded = response.json()
        except ValueError as exc:
            raise upstream_unavailable() from exc
        if not isinstance(decoded, dict):
            raise upstream_unavailable()
        return decoded

    def close(self) -> None:
        self.session.close()
