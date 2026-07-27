"""The whole semantic chain, with only the model itself replaced.

Everything between the Orchestrator and `api.anthropic.com` runs for real here:
the Orchestrator mints a grant, the reviewer constructs its client against the
Gateway origin, the actual `create_gateway_app` verifies the grant and enforces
policy, and only the upstream HTTP call is a stub. That is the furthest this
suite can go without a live model key; `cairn semantic-smoke` closes the last
hop.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest

from cairn.gateway.app import create_gateway_app
from cairn.gateway.config import GatewaySettings
from cairn.gateway.tokens import ModelGrant, mint_grant
from cairn.gateway.upstream import UpstreamClient
from cairn.semantic.broker import ToolBroker
from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
from cairn.semantic.contracts import ToolStatus
from cairn.semantic.findings import ReviewScope, to_candidates
from cairn.semantic.review import SemanticReviewer

FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "injected-app"
REAL_API_KEY = "sk-ant-cairn-REAL-UPSTREAM-KEY-0123456789ab"
GRANT_KEY = b"integration-grant-signing-key-abc"
SNAPSHOT_SHA = "d" * 64


class StubUpstreamSession:
    """Stands in for `requests.Session` on the Gateway's egress leg only."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.default = responses[-1]
        self.calls: list[dict[str, Any]] = []
        self.closed = False

    def post(
        self,
        url: str,
        json: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        allow_redirects: bool = True,
    ) -> Any:
        self.calls.append({"url": url, "json": json, "headers": dict(headers or {})})
        payload = self.responses.pop(0) if self.responses else self.default
        return _StubResponse(payload)

    def close(self) -> None:
        self.closed = True


class _StubResponse:
    status_code = 200

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload


class GatewayTransport:
    """Routes the reviewer's SDK-shaped calls at the real Gateway app."""

    def __init__(self, client: TestClient, grant: str) -> None:
        self._client = client
        self._grant = grant

    def create(self, **payload: Any) -> Any:
        response = self._client.post(
            "/v1/messages",
            headers={"x-api-key": self._grant},
            json=payload,
        )
        response.raise_for_status()
        return _Message(response.json())


class _Message:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload
        self.stop_reason = payload.get("stop_reason")
        self.stop_details = payload.get("stop_details")
        self.content = payload.get("content", [])
        self.usage = _Usage(payload.get("usage", {}))
        self.model = payload.get("model", DEFAULT_MODEL)


class _Usage:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.input_tokens = payload.get("input_tokens", 0)
        self.output_tokens = payload.get("output_tokens", 0)
        self.cache_read_input_tokens = payload.get("cache_read_input_tokens", 0)
        self.cache_creation_input_tokens = payload.get(
            "cache_creation_input_tokens", 0
        )


def final_answer(catalog_paths: list[str]) -> dict[str, Any]:
    controller = next(path for path in catalog_paths if path.endswith("Controller.java"))
    repository = next(path for path in catalog_paths if path.endswith("Repository.java"))
    payload = {
        "findings": [
            {
                "rule_id": "semantic/sql-injection",
                "cwe_ids": ["CWE-89"],
                "category": "sql-injection",
                "severity": "high",
                "confidence": "medium",
                "message": "The owner parameter is concatenated into SQL.",
                "locations": [
                    {
                        "path": repository,
                        "start_line": 15,
                        "end_line": 15,
                        "symbol": "OrderRepository.findByOwner",
                        "role": "sink",
                    }
                ],
                "sink": "java.sql.Statement.execute",
                "call_chain": [
                    {
                        "path": controller,
                        "start_line": 24,
                        "end_line": 24,
                        "symbol": "OrderController.search",
                        "role": "entrypoint",
                        "note": None,
                    },
                    {
                        "path": repository,
                        "start_line": 15,
                        "end_line": 15,
                        "symbol": "OrderRepository.findByOwner",
                        "role": "sink",
                        "note": None,
                    },
                ],
                "controllability": "owner is an unvalidated @RequestParam.",
                "existing_defenses": [],
                "attack_preconditions": "Unauthenticated reachability.",
                "impact": "Arbitrary read of the orders table.",
                "recommended_verification": "Replay with a single quote.",
            }
        ]
    }
    return {
        "id": "msg_final",
        "type": "message",
        "role": "assistant",
        "model": DEFAULT_MODEL,
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 900, "output_tokens": 220},
    }


@pytest.fixture
def gateway(tmp_path: Path) -> tuple[TestClient, StubUpstreamSession, GatewaySettings]:
    api_key_file = tmp_path / "api.key"
    api_key_file.write_text(REAL_API_KEY)
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    settings = GatewaySettings(
        api_key_file=api_key_file,
        grant_key_file=grant_key_file,
        upstream_base_url="https://api.anthropic.invalid",
    )
    catalog_paths = sorted(
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    )
    session = StubUpstreamSession([final_answer(catalog_paths)])
    upstream = UpstreamClient(settings, session=session)
    with TestClient(create_gateway_app(settings, upstream=upstream)) as client:
        yield client, session, settings


def orchestrator_grant() -> str:
    """Minted exactly as `DeterministicOrchestrator._mint_grant` does."""

    return mint_grant(
        ModelGrant(
            audit_run_id="run-integration",
            task_id="task-integration",
            worker="deterministic-orchestrator",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) + timedelta(seconds=1800 + 120),
            max_requests=10,
            max_output_tokens=160_000,
        ),
        GRANT_KEY,
    )


def test_a_review_reaches_the_model_through_the_gateway_and_returns_candidates(
    gateway: tuple[TestClient, StubUpstreamSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    grant = orchestrator_grant()
    broker = ToolBroker(FIXTURE_ROOT)
    scope = ReviewScope(
        module=".",
        attack_surface="HTTP endpoint",
        category="sql-injection",
    )
    reviewer = SemanticReviewer(
        SemanticModelClient(
            base_url="http://gateway.invalid",
            grant_token=grant,
            transport=GatewayTransport(client, grant),
        ),
        broker,
        scope=scope,
        max_turns=4,
    )

    result = reviewer.run()

    assert result.status is ToolStatus.COMPLETED
    assert len(result.findings) == 1
    # Every Orchestrator-minted request was accepted by the real Gateway, and
    # the Gateway substituted the real key at egress on each one.
    assert session.calls
    assert all(call["headers"]["x-api-key"] == REAL_API_KEY for call in session.calls)
    assert grant not in json.dumps(session.calls)

    candidates = to_candidates(
        list(result.findings),
        catalog=broker.catalog,
        snapshot_sha256=SNAPSHOT_SHA,
    )

    assert len(candidates) == 1
    assert candidates[0]["controllability"]
    assert len(candidates[0]["call_chain"]) == 2


def test_the_gateway_clamps_the_reviewers_output_ceiling_to_the_grant(
    gateway: tuple[TestClient, StubUpstreamSession, GatewaySettings],
) -> None:
    client, session, settings = gateway
    grant = mint_grant(
        ModelGrant(
            audit_run_id="run-integration",
            task_id="task-integration",
            worker="deterministic-orchestrator",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) + timedelta(minutes=20),
            max_requests=10,
            max_output_tokens=2_000,
        ),
        GRANT_KEY,
    )
    reviewer = SemanticReviewer(
        SemanticModelClient(
            base_url="http://gateway.invalid",
            grant_token=grant,
            max_tokens=64_000,
            transport=GatewayTransport(client, grant),
        ),
        ToolBroker(FIXTURE_ROOT),
        scope=ReviewScope(
            module=".",
            attack_surface="HTTP endpoint",
            category="sql-injection",
        ),
        max_turns=4,
    )

    reviewer.run()

    assert session.calls[0]["json"]["max_tokens"] <= 2_000


def test_a_grant_the_gateway_cannot_verify_is_refused_before_egress(
    gateway: tuple[TestClient, StubUpstreamSession, GatewaySettings],
) -> None:
    client, session, _settings = gateway
    foreign = mint_grant(
        ModelGrant(
            audit_run_id="run-integration",
            task_id="task-integration",
            worker="deterministic-orchestrator",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) + timedelta(minutes=20),
            max_requests=10,
            max_output_tokens=2_000,
        ),
        b"a-different-signing-key-entirely!",
    )

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": foreign},
        json={
            "model": DEFAULT_MODEL,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": "review"}],
        },
    )

    assert response.status_code == 401
    assert session.calls == []


def test_the_reviewer_cannot_buy_itself_a_network_through_the_gateway(
    gateway: tuple[TestClient, StubUpstreamSession, GatewaySettings],
) -> None:
    """§13.5 #5 on the real path: the container is on an internal network, and
    server-side tools would have run the outbound request from the model
    provider instead."""

    client, session, _settings = gateway
    grant = orchestrator_grant()

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": grant},
        json={
            "model": DEFAULT_MODEL,
            "max_tokens": 512,
            "messages": [{"role": "user", "content": "review"}],
            "tools": [{"type": "web_fetch_20260209", "name": "web_fetch"}],
        },
    )

    assert response.status_code == 403
    assert response.json()["error_code"] == "LLM_TOOL_NOT_ALLOWED"
    assert session.calls == []
