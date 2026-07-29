"""The whole blind-review chain, with only the model itself replaced.

Everything between the Orchestrator and `api.anthropic.com` runs for real:
the Orchestrator mints a grant, the reviewer constructs its client against a
Gateway origin, the actual `create_gateway_app` verifies the grant and enforces
its policy, and only the upstream HTTP call is a stub. This is the furthest
this suite can go without a live model key.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from cairn.analysis.contracts import ToolStatus
from cairn.gateway.app import create_gateway_app
from cairn.gateway.config import GatewaySettings
from cairn.gateway.tokens import ModelGrant, mint_grant
from cairn.gateway.upstream import UpstreamClient
from cairn.semantic.broker import ToolBroker
from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
from cairn.verify.prompt import VerifyAssignment
from cairn.verify.review import IndependentReviewer

FIXTURE_ROOT = Path(__file__).parents[1] / "semantic" / "fixtures" / "injected-app"
ROOT_CAUSE_KEY = "b" * 64
REAL_API_KEY = "sk-ant-cairn-REAL-UPSTREAM-KEY-0123456789ab"
GRANT_KEY = b"integration-grant-signing-key-abc"


# The SDK stubs are re-declared rather than imported from the semantic suite:
# `cairn/tests` has no `__init__.py`, so each test directory is its own
# top-level package and there is nothing to import across.


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


def verdict_answer(catalog_paths: list[str]) -> dict[str, Any]:
    controller = next(
        path for path in catalog_paths if path.endswith("OrderController.java")
    )
    repository = next(
        path for path in catalog_paths if path.endswith("OrderRepository.java")
    )
    payload = {
        "verdict": "confirmed",
        "reasoning": "I traced `owner` from the controller into the query text.",
        "reachability": "GET /orders?owner= is reachable without authentication.",
        "call_chain": [
            {
                "path": controller,
                "start_line": 1,
                "end_line": 1,
                "symbol": "OrderController.list",
                "role": "entrypoint",
                "note": None,
            },
            {
                "path": repository,
                "start_line": 1,
                "end_line": 1,
                "symbol": "OrderRepository.find",
                "role": "sink",
                "note": None,
            },
        ],
        "defeating_control": None,
    }
    return {
        "id": "msg_verdict",
        "type": "message",
        "role": "assistant",
        "model": DEFAULT_MODEL,
        "content": [{"type": "text", "text": json.dumps(payload)}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 800, "output_tokens": 180},
    }


@pytest.fixture
def gateway(tmp_path: Path) -> tuple[TestClient, StubUpstreamSession]:
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
    session = StubUpstreamSession([verdict_answer(catalog_paths)])
    upstream = UpstreamClient(settings, session=session)
    with TestClient(create_gateway_app(settings, upstream=upstream)) as client:
        yield client, session


def verifier_grant() -> str:
    """Minted exactly as `_execute_independent_review` does."""

    return mint_grant(
        ModelGrant(
            audit_run_id="run-integration",
            task_id="verify-task-integration",
            worker="deterministic-orchestrator",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) + timedelta(seconds=1200 + 120),
            max_requests=18,
            max_output_tokens=288_000,
        ),
        GRANT_KEY,
    )


def assignment(catalog_paths: list[str]) -> VerifyAssignment:
    repository = next(
        path for path in catalog_paths if path.endswith("OrderRepository.java")
    )
    return VerifyAssignment(
        root_cause_key=ROOT_CAUSE_KEY,
        module="core",
        category="sql-injection",
        cwe_ids=("CWE-89",),
        sink="java.sql.Statement.execute",
        locations=(
            {
                "path": repository,
                "start_line": 1,
                "end_line": 1,
                "symbol": "OrderRepository.find",
                "role": "sink",
            },
        ),
    )


def catalog_paths() -> list[str]:
    return sorted(
        path.relative_to(FIXTURE_ROOT).as_posix()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    )


def test_a_blind_review_reaches_the_model_through_the_gateway(
    gateway: tuple[TestClient, StubUpstreamSession],
) -> None:
    client, session = gateway
    grant = verifier_grant()

    reviewer = IndependentReviewer(
        SemanticModelClient(
            base_url="http://gateway.invalid",
            grant_token=grant,
            transport=GatewayTransport(client, grant),
        ),
        ToolBroker(FIXTURE_ROOT),
        assignment=assignment(catalog_paths()),
        max_turns=4,
    )

    result = reviewer.run()

    assert result.status is ToolStatus.COMPLETED
    assert result.verdict is not None
    assert result.verdict.verdict == "confirmed"
    assert result.root_cause_key == ROOT_CAUSE_KEY


def test_the_gateway_substitutes_the_real_key_and_the_grant_never_leaves(
    gateway: tuple[TestClient, StubUpstreamSession],
) -> None:
    client, session = gateway
    grant = verifier_grant()

    IndependentReviewer(
        SemanticModelClient(
            base_url="http://gateway.invalid",
            grant_token=grant,
            transport=GatewayTransport(client, grant),
        ),
        ToolBroker(FIXTURE_ROOT),
        assignment=assignment(catalog_paths()),
        max_turns=4,
    ).run()

    assert session.calls
    assert all(call["headers"]["x-api-key"] == REAL_API_KEY for call in session.calls)
    assert grant not in json.dumps(session.calls)


def test_the_operator_channel_carries_only_assignment_metadata(
    gateway: tuple[TestClient, StubUpstreamSession],
) -> None:
    """What reaches the model is paths, category and CWE — not an analysis.

    The wire contract already makes prose unrepresentable
    (`test_blind_channel.py`); this checks the same holds after the assignment
    has been rendered, sent through the real Gateway and forwarded upstream.
    """

    client, session = gateway
    grant = verifier_grant()

    IndependentReviewer(
        SemanticModelClient(
            base_url="http://gateway.invalid",
            grant_token=grant,
            transport=GatewayTransport(client, grant),
        ),
        ToolBroker(FIXTURE_ROOT),
        assignment=assignment(catalog_paths()),
        max_turns=4,
    ).run()

    operator = [
        message
        for call in session.calls
        for message in call["json"]["messages"]
        if message.get("role") == "system"
    ]
    assert operator
    for message in operator:
        text = str(message["content"])
        assert "sql-injection" in text
        assert "CWE-89" in text
        assert "deliberately withheld" in text
        # Everything the reporting worker would have written about *why*. The
        # labels are the ones `cairn.pipeline.promote._description` renders, so
        # this stays a real guard rather than one that passes because the
        # wording moved.
        for absent in ("可控性：", "影响：", "调用链：", "已有防护", "建议验证方式："):
            assert absent not in text


def test_an_expired_grant_is_refused_by_the_real_gateway(
    gateway: tuple[TestClient, StubUpstreamSession],
) -> None:
    """The seam between minting and verification has to agree."""

    client, session = gateway
    expired = mint_grant(
        ModelGrant(
            audit_run_id="run-integration",
            task_id="verify-task-integration",
            worker="deterministic-orchestrator",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
            max_requests=18,
            max_output_tokens=288_000,
        ),
        GRANT_KEY,
    )

    response = client.post(
        "/v1/messages",
        headers={"x-api-key": expired},
        json={
            "model": DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "hello"}],
            "max_tokens": 100,
        },
    )

    assert response.status_code == 401
    assert session.calls == []
