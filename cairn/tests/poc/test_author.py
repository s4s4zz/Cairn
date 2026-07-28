"""The PoC Author's loop, driven against a stub transport.

The author has no target application — it writes a request for the platform to
run later — so the properties here are about the model channel: a plan the
platform cannot use produces no plan rather than a bad one, and the channel
layout is the §9.6 one.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from cairn.poc.author import PocAuthor
from cairn.poc.contracts import (
    CALLBACK_TOKEN,
    POC_CONTRACT,
    POC_TOOL_NAME,
    REASON_MODEL_REFUSED,
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    REASON_TURN_LIMIT,
)
from cairn.poc.prompt import (
    POC_AUTHOR_SYSTEM_PROMPT,
    PocAssignment,
    assignment_instruction,
)
from cairn.semantic.broker import ToolBroker
from cairn.semantic.client import SemanticModelClient

FIXTURE_ROOT = Path(__file__).parents[1] / "semantic" / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
GRANT_TOKEN = "g" * 48
FINDING_ID = "11111111-1111-1111-1111-111111111111"


class ScriptExhausted(BaseException):
    pass


class StubTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def create(self, **payload: object) -> object:
        self.requests.append(copy.deepcopy(payload))
        if not self.responses:
            raise ScriptExhausted(f"ran out after {len(self.requests)} request(s)")
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def usage() -> dict[str, int]:
    return {
        "input_tokens": 120,
        "output_tokens": 60,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }


def assistant_text(text: str, **kwargs: object) -> dict:
    return {
        "model": kwargs.get("model", "claude-opus-5"),
        "stop_reason": kwargs.get("stop_reason", "end_turn"),
        "content": [{"type": "text", "text": text}],
        "usage": usage(),
    }


def assistant_tool_use(*calls: tuple[str, str, dict[str, object]]) -> dict:
    return {
        "model": "claude-opus-5",
        "stop_reason": "tool_use",
        "content": [
            {"type": "tool_use", "id": call_id, "name": name, "input": arguments}
            for call_id, name, arguments in calls
        ],
        "usage": usage(),
    }


def plan_answer(*, stop_reason: str = "end_turn", **overrides: object) -> dict:
    payload: dict[str, object] = {
        "request": {
            "method": "POST",
            "path": "/orders",
            "headers": {"content-type": "application/json"},
            "body": '{"owner":"x"}',
        },
        "injection": {
            "location": "body_field",
            "name": "owner",
            "benign": "alice",
            "payload": "${7*7}",
        },
        "criterion": {
            "kind": "contains_text",
            "match_text": "49",
            "status_code": None,
            "elapsed_ms": None,
        },
        "rationale": "The owner field is evaluated as an expression.",
    }
    for key, value in overrides.items():
        if key in payload and isinstance(value, dict):
            payload[key] = {**payload[key], **value}  # type: ignore[dict-item]
        else:
            payload[key] = value
    return {
        "model": "claude-opus-5",
        "stop_reason": stop_reason,
        "content": [],
        "parsed": payload,
        "usage": usage(),
    }


def assignment() -> PocAssignment:
    return PocAssignment(
        finding_id=FINDING_ID,
        module="web",
        category="expression-injection",
        cwe_ids=("CWE-917",),
        sink="SpelExpressionParser.parseExpression",
        http_method="POST",
        route="/orders",
        route_prefixes=(),
        locations=(
            {
                "path": CONTROLLER,
                "start_line": 1,
                "end_line": 2,
                "symbol": "OrderController.create",
                "role": "sink",
            },
        ),
    )


def author(responses: list[object], **kwargs: object) -> tuple[PocAuthor, StubTransport]:
    transport = StubTransport(responses)
    client = SemanticModelClient(
        base_url="http://cairn-llm-gateway:8002",
        grant_token=GRANT_TOKEN,
        transport=transport,
    )
    return (
        PocAuthor(client, ToolBroker(FIXTURE_ROOT), assignment=assignment(), **kwargs),
        transport,
    )


# --- a plan is authored -------------------------------------------------------


def test_a_well_formed_answer_becomes_a_plan() -> None:
    agent, _ = author([assistant_text("read it"), plan_answer()])

    result = agent.run()

    assert result.status == "completed"
    assert result.contract == POC_CONTRACT
    assert result.tool_name == POC_TOOL_NAME
    assert result.plan is not None
    assert result.plan.finding_id == FINDING_ID
    # The platform fills identity, not the model.
    assert result.plan.category == "expression-injection"


def test_an_out_of_band_plan_is_authored() -> None:
    agent, _ = author(
        [
            assistant_text("read it"),
            plan_answer(
                injection={"payload": f"http://x/{CALLBACK_TOKEN}"},
                criterion={"kind": "echo_nonce_observed", "match_text": None},
            ),
        ]
    )

    result = agent.run()

    assert result.status == "completed"
    assert result.plan.criterion.kind == "echo_nonce_observed"


# --- a plan the platform cannot use is discarded ------------------------------


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param(
            plan_answer(request={"path": "http://evil/x"}), id="absolute-path"
        ),
        pytest.param(
            plan_answer(request={"headers": {"host": "evil"}}), id="host-header"
        ),
        pytest.param(
            plan_answer(injection={"benign": "same", "payload": "same"}),
            id="non-discriminating-values",
        ),
    ],
)
def test_a_plan_that_violates_the_contract_yields_no_plan(answer: dict) -> None:
    agent, _ = author([assistant_text("read it"), answer])

    result = agent.run()

    assert result.status == "failed"
    assert result.reason_code == REASON_OUTPUT_INVALID
    assert result.plan is None


# --- nothing that went wrong yields a plan ------------------------------------


def test_a_refusal_yields_no_plan() -> None:
    agent, _ = author(
        [
            {
                "model": "claude-opus-5",
                "stop_reason": "refusal",
                "stop_details": {"type": "refusal", "category": "cyber"},
                "content": [],
                "usage": usage(),
            }
        ]
    )

    result = agent.run()

    assert result.status == "unavailable"
    assert result.reason_code == REASON_MODEL_REFUSED
    assert result.plan is None


def test_a_transport_failure_yields_no_plan() -> None:
    agent, _ = author([RuntimeError("gateway down")])

    result = agent.run()

    assert result.status == "unavailable"
    assert result.plan is None


def test_an_exhausted_turn_budget_yields_no_plan() -> None:
    agent, _ = author(
        [
            assistant_tool_use(("t1", "read_inventory", {})),
            assistant_tool_use(("t2", "read_inventory", {})),
            plan_answer(),
        ],
        max_turns=2,
    )

    result = agent.run()

    assert result.status == "failed"
    assert result.reason_code == REASON_TURN_LIMIT
    assert result.plan is None


def test_a_truncated_answer_yields_no_plan() -> None:
    agent, _ = author(
        [assistant_text("read it"), plan_answer(stop_reason="max_tokens")]
    )

    result = agent.run()

    assert result.status == "failed"
    assert result.reason_code == REASON_OUTPUT_INCOMPLETE
    assert result.plan is None


def test_an_unparseable_answer_yields_no_plan() -> None:
    agent, _ = author([assistant_text("read it"), assistant_text("I think it is /x")])

    result = agent.run()

    assert result.status == "failed"
    assert result.reason_code == REASON_OUTPUT_INVALID
    assert result.plan is None


# --- channel separation -------------------------------------------------------


def test_the_assignment_travels_on_the_operator_channel() -> None:
    agent, transport = author([assistant_text("read it"), plan_answer()])

    agent.run()

    messages = transport.requests[0]["messages"]
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "system"
    assert messages[1]["content"] == assignment_instruction(assignment())
    assert transport.requests[0]["system"] == POC_AUTHOR_SYSTEM_PROMPT


def test_the_system_prompt_is_a_constant_with_no_code_filled_fields() -> None:
    """The `{name}` and `{{CAIRN_CALLBACK}}` in the text are documentation the
    model reads, not format fields the code substitutes — so the constant is
    used verbatim and repository bytes cannot reach it through interpolation."""

    import cairn.poc.prompt as prompt_module

    source = Path(prompt_module.__file__).read_text(encoding="utf-8")
    assert ".format(" not in source
    assert "POC_AUTHOR_SYSTEM_PROMPT %" not in source
    assert FINDING_ID not in POC_AUTHOR_SYSTEM_PROMPT
