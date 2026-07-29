from __future__ import annotations

from collections import deque
from collections.abc import Generator, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
import logging
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest
import requests
from pydantic import ValidationError

from cairn.gateway.app import create_gateway_app
from cairn.gateway.config import GatewaySettings
from cairn.gateway.tokens import ModelGrant, mint_grant
from cairn.gateway.upstream import FALLBACK_BETA_HEADER, UpstreamClient

# Distinctive, greppable strings so the log-hygiene sweeps cannot pass by
# accident on a substring that happens to be absent anyway.
API_KEY = "sk-ant-cairn-REALUPSTREAMKEY-8f2c1d4b9e7a6350"
GRANT_KEY = b"gateway-grant-signing-key-abcdef01"
PROMPT_MARKER = "SOURCE-PROMPT-MARKER-c0ffee-do-not-log"
COMPLETION_MARKER = "MODEL-COMPLETION-MARKER-decafbad-do-not-log"


class StubResponse:
    def __init__(
        self,
        status_code: int,
        payload: object = None,
        *,
        body_is_not_json: bool = False,
    ) -> None:
        self.status_code = status_code
        self._payload = payload
        self._body_is_not_json = body_is_not_json

    def json(self) -> object:
        if self._body_is_not_json:
            raise ValueError("upstream returned a non-JSON body")
        return self._payload


class RecordingSession:
    """Stands in for ``requests.Session`` on the Gateway's egress leg."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.responses: deque[StubResponse | Exception] = deque()
        self.default_response: StubResponse | Exception = StubResponse(
            200,
            message_payload(),
        )
        self.closed = False

    def queue(self, *responses: StubResponse | Exception) -> None:
        self.responses.extend(responses)

    def post(
        self,
        url: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        allow_redirects: bool = True,
    ) -> StubResponse:
        self.calls.append(
            {
                "url": url,
                "json": json,
                "headers": dict(headers or {}),
                "timeout": timeout,
                "allow_redirects": allow_redirects,
            }
        )
        outcome = self.responses.popleft() if self.responses else self.default_response
        if isinstance(outcome, Exception):
            raise outcome
        return outcome

    def close(self) -> None:
        self.closed = True

    @property
    def last(self) -> dict[str, Any]:
        return self.calls[-1]


def message_payload(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "model": "claude-opus-5",
        "content": [{"type": "text", "text": COMPLETION_MARKER}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 120, "output_tokens": 34},
    }
    payload.update(overrides)
    return payload


def make_settings(tmp_path: Path, **overrides: Any) -> GatewaySettings:
    api_key_file = tmp_path / "api.key"
    api_key_file.write_text(API_KEY)
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    values: dict[str, Any] = {
        "api_key_file": api_key_file,
        "grant_key_file": grant_key_file,
        "model_allowlist": ("claude-opus-5", "claude-opus-4-8"),
        "upstream_base_url": "https://api.anthropic.invalid",
        "max_request_bytes": 8192,
        "max_output_tokens": 8_000,
        "circuit_failure_threshold": 3,
        "circuit_reset_seconds": 60.0,
    }
    values.update(overrides)
    return GatewaySettings(**values)


@contextmanager
def gateway_app(
    tmp_path: Path,
    **overrides: Any,
) -> Iterator[tuple[TestClient, RecordingSession, GatewaySettings]]:
    settings = make_settings(tmp_path, **overrides)
    session = RecordingSession()
    upstream = UpstreamClient(settings, session=session)
    with TestClient(create_gateway_app(settings, upstream=upstream)) as client:
        yield client, session, settings


@pytest.fixture
def gateway(
    tmp_path: Path,
) -> Generator[tuple[TestClient, RecordingSession, GatewaySettings], None, None]:
    with gateway_app(tmp_path) as active:
        yield active


def grant_token(**overrides: Any) -> str:
    defaults: dict[str, Any] = {
        "audit_run_id": "run-a1",
        "task_id": "task-3",
        "worker": "semantic-reviewer-1",
        "model": "claude-opus-5",
        "expires_at": datetime.now(UTC) + timedelta(minutes=30),
        "max_requests": 20,
        "max_output_tokens": 6_000,
    }
    defaults.update(overrides)
    return mint_grant(ModelGrant(**defaults), GRANT_KEY)


def request_body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": "claude-opus-5",
        "max_tokens": 1_024,
        "messages": [{"role": "user", "content": PROMPT_MARKER}],
    }
    payload.update(overrides)
    return payload


def render_logs(caplog: pytest.LogCaptureFixture) -> str:
    """Every byte a log record could plausibly carry, as one blob."""
    formatter = logging.Formatter("%(name)s %(levelname)s %(message)s")
    chunks: list[str] = []
    for record in caplog.records:
        chunks.append(formatter.format(record))
        for key, value in record.__dict__.items():
            chunks.append(f"{key}={value!r}")
    return "\n".join(chunks)


def test_grant_supplied_as_x_api_key_reaches_the_upstream_model(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 200
    assert response.json()["content"][0]["text"] == COMPLETION_MARKER
    assert response.json()["stop_reason"] == "end_turn"
    assert len(session.calls) == 1
    assert session.last["url"] == "https://api.anthropic.invalid/v1/messages"


def test_grant_supplied_as_bearer_authorization_is_accepted(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"Authorization": f"Bearer {grant_token()}"},
        json=request_body(),
    )

    assert response.status_code == 200
    assert len(session.calls) == 1


def test_missing_grant_is_unauthorized(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    response = client.post("/v1/messages", json=request_body())

    assert response.status_code == 401
    assert response.json()["error_code"] == "LLM_GRANT_INVALID"
    assert session.calls == []


def test_upstream_receives_the_real_key_and_never_the_grant(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway
    token = grant_token()

    client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())

    forwarded = session.last
    assert forwarded["headers"]["x-api-key"] == API_KEY
    assert forwarded["headers"]["anthropic-version"] == settings.anthropic_version
    assert forwarded["timeout"] == settings.request_timeout_seconds
    assert token not in str(forwarded["headers"])
    assert token not in str(forwarded["json"])


def test_client_supplied_credential_and_beta_headers_are_stripped(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    fake_upstream_key = "sk-ant-ATTACKER-SUPPLIED-KEY-0000000000"

    response = client.post(
        "/v1/messages",
        headers={
            "x-api-key": grant_token(),
            "Authorization": f"Bearer {fake_upstream_key}",
            "anthropic-beta": "attacker-beta-2020-01-01",
            "anthropic-version": "1999-01-01",
            "x-forwarded-for": "203.0.113.9",
        },
        json=request_body(),
    )

    assert response.status_code == 200
    forwarded = session.last
    # The egress header set is rebuilt from scratch, so it is exactly this and
    # nothing the client sent survives the hop.
    assert set(forwarded["headers"]) == {
        "x-api-key",
        "anthropic-version",
        "content-type",
        "accept",
        "anthropic-beta",
    }
    assert forwarded["headers"]["anthropic-beta"] == FALLBACK_BETA_HEADER
    assert forwarded["headers"]["anthropic-version"] != "1999-01-01"
    assert fake_upstream_key not in str(forwarded["headers"])
    assert fake_upstream_key not in str(forwarded["json"])
    assert "203.0.113.9" not in str(forwarded["headers"])


def test_refusal_fallback_adds_the_body_field_and_the_beta_header(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway
    assert settings.refusal_fallback is True

    client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert session.last["json"]["fallbacks"] == "default"
    assert session.last["headers"]["anthropic-beta"] == FALLBACK_BETA_HEADER


def test_refusal_fallback_disabled_sends_neither_field_nor_beta_header(
    tmp_path: Path,
) -> None:
    with gateway_app(tmp_path, refusal_fallback=False) as (client, session, _settings):
        client.post(
            "/v1/messages",
            headers={"x-api-key": grant_token()},
            json=request_body(),
        )

    assert "fallbacks" not in session.last["json"]
    assert "anthropic-beta" not in session.last["headers"]


def test_refusal_is_passed_through_verbatim_and_is_not_an_error(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    refusal = message_payload(
        content=[],
        stop_reason="refusal",
        stop_details={"category": "cyber"},
        usage={"input_tokens": 90, "output_tokens": 0},
    )
    session.queue(StubResponse(200, refusal))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 200
    assert response.json() == refusal
    assert response.json()["stop_reason"] == "refusal"
    assert response.json()["stop_details"]["category"] == "cyber"


def test_repeated_refusals_do_not_trip_the_circuit_breaker(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway
    refusal = message_payload(
        content=[],
        stop_reason="refusal",
        stop_details={"category": "cyber"},
    )
    token = grant_token()
    session.queue(
        *[
            StubResponse(200, refusal)
            for _ in range(settings.circuit_failure_threshold + 1)
        ]
    )

    statuses = [
        client.post(
            "/v1/messages",
            headers={"x-api-key": token},
            json=request_body(),
        ).status_code
        for _ in range(settings.circuit_failure_threshold + 1)
    ]

    assert statuses == [200] * (settings.circuit_failure_threshold + 1)
    assert len(session.calls) == settings.circuit_failure_threshold + 1


def test_upstream_timeout_is_reported_as_gateway_timeout(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(requests.Timeout("upstream took too long"))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 504
    assert response.json()["error_code"] == "LLM_UPSTREAM_TIMEOUT"


def test_upstream_connection_failure_is_reported_as_bad_gateway(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(requests.ConnectionError("no route to the model API"))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 502
    assert response.json()["error_code"] == "LLM_UPSTREAM_UNAVAILABLE"


def test_upstream_server_error_is_reported_as_bad_gateway(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(StubResponse(500, {"error": {"message": "internal"}}))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 502
    assert response.json()["error_code"] == "LLM_UPSTREAM_UNAVAILABLE"


def test_upstream_gateway_timeout_status_maps_to_the_timeout_code(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(StubResponse(504, {"error": {"message": "timeout"}}))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 504
    assert response.json()["error_code"] == "LLM_UPSTREAM_TIMEOUT"


def test_upstream_body_that_is_not_a_json_object_is_not_passed_through(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(StubResponse(200, ["not", "an", "object"]))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 502
    assert response.json()["error_code"] == "LLM_UPSTREAM_UNAVAILABLE"


def test_consecutive_upstream_failures_open_the_circuit(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway
    token = grant_token()
    session.queue(
        *[
            StubResponse(500, {"error": {"message": "internal"}})
            for _ in range(settings.circuit_failure_threshold)
        ]
    )

    for _ in range(settings.circuit_failure_threshold):
        failed = client.post(
            "/v1/messages",
            headers={"x-api-key": token},
            json=request_body(),
        )
        assert failed.status_code == 502

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": token},
        json=request_body(),
    )

    assert response.status_code == 503
    assert response.json()["error_code"] == "LLM_CIRCUIT_OPEN"
    assert len(session.calls) == settings.circuit_failure_threshold


def test_model_outside_the_grant_is_refused_before_egress(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token(model="claude-opus-4-8")},
        json=request_body(model="claude-opus-5"),
    )

    assert response.status_code == 403
    assert response.json()["error_code"] == "LLM_MODEL_NOT_ALLOWED"
    assert session.calls == []


def test_oversized_body_is_refused_with_the_size_code(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(
            messages=[{"role": "user", "content": "z" * (settings.max_request_bytes + 1)}]
        ),
    )

    assert response.status_code == 413
    assert response.json()["error_code"] == "LLM_REQUEST_TOO_LARGE"
    assert session.calls == []


def test_request_budget_exhaustion_is_reported_as_too_many_requests(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    token = grant_token(max_requests=2)

    for _ in range(2):
        assert (
            client.post(
                "/v1/messages",
                headers={"x-api-key": token},
                json=request_body(),
            ).status_code
            == 200
        )

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": token},
        json=request_body(),
    )

    assert response.status_code == 429
    assert response.json()["error_code"] == "LLM_BUDGET_EXHAUSTED"
    assert len(session.calls) == 2


def test_forwarded_max_tokens_is_clamped_to_the_grant_ceiling(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token(max_output_tokens=2_000)},
        json=request_body(max_tokens=999_999),
    )

    assert session.last["json"]["max_tokens"] == 2_000


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        ("[1, 2, 3]", "json list"),
        ('"a bare string"', "json string"),
        ("not json at all", "not json"),
        ('{"messages": [{"role": "user"}]}', "missing model"),
        ('{"model": "claude-opus-5"}', "missing messages"),
        ('{"model": "claude-opus-5", "messages": []}', "empty messages"),
    ],
)
def test_malformed_request_bodies_are_reported_as_request_invalid(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
    payload: str,
    label: str,
) -> None:
    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token(), "content-type": "application/json"},
        content=payload.encode("utf-8"),
    )

    assert response.status_code == 422, label
    assert response.json()["error_code"] == "LLM_REQUEST_INVALID", label
    assert session.calls == []


def test_liveness_and_readiness_are_uncredentialed(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, _session, _settings = gateway

    live = client.get("/health/live")
    ready = client.get("/health/ready")

    assert live.status_code == 200
    assert live.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json() == {"status": "ready"}


def test_readiness_fails_when_the_gateway_is_holding_no_key(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, _session, _settings = gateway
    client.app.state.api_key = b""

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["error_code"] == "LLM_GATEWAY_NOT_READY"


@pytest.mark.parametrize("path", ["/openapi.json", "/docs", "/redoc"])
def test_gateway_publishes_no_schema_or_docs_endpoints(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
    path: str,
) -> None:
    client, _session, _settings = gateway

    assert client.get(path).status_code == 404


def test_health_responses_do_not_leak_the_api_key(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, _session, _settings = gateway

    for path in ("/health/live", "/health/ready"):
        response = client.get(path)
        assert API_KEY not in response.text
        assert API_KEY not in str(dict(response.headers))


def test_api_key_never_appears_in_a_response_body_or_header(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    token = grant_token()
    session.queue(
        StubResponse(200, message_payload()),
        StubResponse(500, {"error": {"message": "internal"}}),
        requests.Timeout("upstream took too long"),
    )

    responses = [
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body()),
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body()),
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body()),
        client.post("/v1/messages", json=request_body()),
        client.post(
            "/v1/messages",
            headers={"x-api-key": token},
            content=b"not json",
        ),
    ]

    for response in responses:
        assert API_KEY not in response.text
        assert API_KEY not in str(dict(response.headers))


def test_api_key_never_reaches_a_log_record(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with gateway_app(tmp_path) as (client, session, _settings):
        token = grant_token()
        session.queue(
            StubResponse(200, message_payload()),
            StubResponse(500, {"error": {"message": "internal"}}),
            requests.Timeout("upstream took too long"),
        )
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())
        client.get("/health/ready")

    rendered = render_logs(caplog)

    assert caplog.records, "the exchange should have produced at least one log record"
    assert API_KEY not in rendered
    assert "sk-ant" not in rendered
    # The grant is a credential too; it must not be logged either.
    assert token not in rendered


def test_prompt_and_completion_never_reach_a_log_record(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    with gateway_app(tmp_path) as (client, session, _settings):
        token = grant_token()
        session.queue(
            StubResponse(200, message_payload()),
            StubResponse(500, {"error": {"message": "internal"}}),
        )
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())
        client.post("/v1/messages", headers={"x-api-key": token}, json=request_body())

    rendered = render_logs(caplog)

    # §5.1: the full source prompt is never retained in ordinary logs, and the
    # model's answer is not either.
    assert PROMPT_MARKER not in rendered
    assert COMPLETION_MARKER not in rendered


def test_completed_exchange_logs_only_metering_fields(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.INFO, logger="cairn.gateway.app")
    with gateway_app(tmp_path) as (client, session, _settings):
        session.queue(StubResponse(200, message_payload()))
        client.post(
            "/v1/messages",
            headers={"x-api-key": grant_token(worker="semantic-reviewer-7")},
            json=request_body(),
        )

    exchanges = [
        record for record in caplog.records if record.name == "cairn.gateway.app"
    ]

    assert len(exchanges) == 1
    record = exchanges[0]
    assert record.model == "claude-opus-5"
    assert record.input_tokens == 120
    assert record.output_tokens == 34
    assert record.stop_reason == "end_turn"
    assert record.worker == "semantic-reviewer-7"
    assert record.audit_run_id == "run-a1"
    assert isinstance(record.latency_ms, int)


def test_upstream_call_never_follows_a_redirect(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    """`requests` strips Authorization across hosts but not a custom x-api-key
    header, so following a 307 would re-POST the prompt and the long-term key
    to whatever the redirect names."""

    client, session, _settings = gateway

    client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert session.last["allow_redirects"] is False


def test_an_upstream_redirect_is_an_error_rather_than_a_second_request(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    session.queue(StubResponse(307, {}))

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(),
    )

    assert response.status_code == 502
    assert response.json()["error_code"] == "LLM_UPSTREAM_UNAVAILABLE"
    assert len(session.calls) == 1


def test_a_plaintext_upstream_origin_is_refused_outside_loopback(
    tmp_path: Path,
) -> None:
    """The long-term key rides this leg, and cairn-llm-egress is not internal."""

    with pytest.raises(ValidationError):
        make_settings(tmp_path, upstream_base_url="http://api.anthropic.com")


def test_a_loopback_plaintext_origin_is_permitted(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, upstream_base_url="http://127.0.0.1:8999")

    assert settings.upstream_base_url == "http://127.0.0.1:8999"


def test_server_side_tools_are_refused_before_any_egress(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    """§13.5 #5 end to end: the reviewer cannot buy itself an internet
    connection through Anthropic's server-side tools, which would run the
    outbound request from Anthropic's infrastructure and never touch the
    internal analysis bridge at all."""

    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(
            tools=[{"type": "web_search_20260209", "name": "web_search"}],
        ),
    )

    assert response.status_code == 403
    assert response.json()["error_code"] == "LLM_TOOL_NOT_ALLOWED"
    assert session.calls == []


def test_an_mcp_server_is_refused_before_any_egress(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        json=request_body(
            mcp_servers=[
                {"type": "url", "url": "https://attacker.example/mcp", "name": "e"}
            ],
        ),
    )

    assert response.status_code == 403
    assert session.calls == []


def test_an_oversized_body_is_refused_without_being_buffered(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    """This service holds model-egress key material, and anything
    on the internal analysis network can reach it without a valid grant, so the
    size cap has to bite before the bytes are accepted."""

    client, session, settings = gateway

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant_token()},
        content=b"x" * (settings.max_request_bytes + 1),
    )

    assert response.status_code == 413
    assert response.json()["error_code"] == "LLM_REQUEST_TOO_LARGE"
    assert session.calls == []


def test_an_oversized_body_is_refused_without_a_credential(
    gateway: tuple[TestClient, RecordingSession, GatewaySettings],
) -> None:
    client, session, settings = gateway

    response = client.post(
        "/v1/messages",
        content=b"x" * (settings.max_request_bytes + 1),
    )

    assert response.status_code == 413
    assert session.calls == []
