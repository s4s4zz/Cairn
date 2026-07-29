"""The Independent Reviewer's loop, driven against a stub transport.

One property dominates this stage and is asserted from several directions:
**nothing that goes wrong may produce a rejection.** §7.7 states the rule for
dynamic verification, and it holds identically here — a reviewer that could not
do its job must not be able to delete a candidate.

The second property is that a verdict has to be falsifiable: a confirmation
needs a chain the reviewer traced itself, and a rejection needs a named control.
"""

from __future__ import annotations

import copy
from pathlib import Path

import pytest

from cairn.analysis.contracts import ToolStatus
from cairn.semantic.broker import ToolBroker
from cairn.semantic.client import SemanticModelClient
from cairn.semantic.conversation import ChannelInvariantError
from cairn.verify.contracts import (
    REASON_MODEL_REFUSED,
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    REASON_TURN_LIMIT,
    VERIFY_CONTRACT,
    VERIFY_TOOL_NAME,
    WARN_NO_DEFEATING_CONTROL,
    WARN_NO_REBUILT_CHAIN,
    verify_output_schema,
)
from cairn.verify.prompt import (
    FINAL_ANSWER_REQUEST,
    INDEPENDENT_REVIEW_SYSTEM_PROMPT,
    VerifyAssignment,
    assignment_instruction,
)
from cairn.verify.review import IndependentReviewer

FIXTURE_ROOT = Path(__file__).parents[1] / "semantic" / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
REPOSITORY = "core/src/main/java/dev/cairn/shop/OrderRepository.java"
GRANT_TOKEN = "g" * 48
ROOT_CAUSE_KEY = "b" * 64


class ScriptExhausted(BaseException):
    """The stub ran out of scripted responses.

    A :class:`BaseException` on purpose: the client wraps every ``Exception``
    from the transport into ``SemanticUnavailable``, which would turn a
    miscounted script into a quietly passing test asserting on a review that
    never ran.
    """


class StubTransport:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.requests: list[dict[str, object]] = []

    def create(self, **payload: object) -> object:
        self.requests.append(copy.deepcopy(payload))
        if not self.responses:
            raise ScriptExhausted(
                f"stub transport ran out after {len(self.requests)} request(s)"
            )
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
        "usage": kwargs.get("usage", usage()),
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


def step(path: str, line: int, role: str, symbol: str = "Shop.handle") -> dict:
    return {
        "path": path,
        "start_line": line,
        "end_line": line,
        "symbol": symbol,
        "role": role,
        "note": None,
    }


def verdict_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "verdict": "confirmed",
        "reasoning": "The controller concatenates `owner` into the query text.",
        "reachability": "GET /orders?owner= is reachable to any authenticated user.",
        "call_chain": [
            step(CONTROLLER, 1, "entrypoint"),
            step(REPOSITORY, 1, "sink"),
        ],
        "defeating_control": None,
    }
    payload.update(overrides)
    return payload


def final_answer(payload: dict[str, object], **kwargs: object) -> dict:
    return {
        "model": kwargs.get("model", "claude-opus-5"),
        "stop_reason": kwargs.get("stop_reason", "end_turn"),
        "content": [],
        "parsed": payload,
        "usage": usage(),
    }


def assignment() -> VerifyAssignment:
    return VerifyAssignment(
        root_cause_key=ROOT_CAUSE_KEY,
        module="web",
        category="sql-injection",
        cwe_ids=("CWE-89",),
        sink="Statement.executeQuery",
        locations=(
            {
                "path": CONTROLLER,
                "start_line": 1,
                "end_line": 2,
                "symbol": "OrderController.list",
                "role": "sink",
            },
        ),
    )


def reviewer(responses: list[object], **kwargs: object) -> tuple[IndependentReviewer, StubTransport]:
    transport = StubTransport(responses)
    client = SemanticModelClient(
        base_url="http://cairn-llm-gateway:8002",
        grant_token=GRANT_TOKEN,
        transport=transport,
    )
    return (
        IndependentReviewer(
            client,
            ToolBroker(FIXTURE_ROOT),
            assignment=assignment(),
            **kwargs,
        ),
        transport,
    )


# --- verdicts -----------------------------------------------------------------


def test_a_traced_confirmation_stands() -> None:
    agent, _ = reviewer(
        [assistant_text("done reading"), final_answer(verdict_payload())]
    )

    result = agent.run()

    assert result.status is ToolStatus.COMPLETED
    assert result.contract == VERIFY_CONTRACT
    assert result.tool_name == VERIFY_TOOL_NAME
    assert result.root_cause_key == ROOT_CAUSE_KEY
    assert result.verdict is not None
    assert result.verdict.verdict == "confirmed"
    assert len(result.verdict.call_chain) == 2


def test_a_rejection_naming_a_control_stands() -> None:
    agent, _ = reviewer(
        [
            assistant_text("read the repository"),
            final_answer(
                verdict_payload(
                    verdict="rejected",
                    call_chain=[],
                    defeating_control=f"{REPOSITORY}:1 binds the value as a parameter",
                )
            ),
        ]
    )

    result = agent.run()

    assert result.verdict is not None
    assert result.verdict.verdict == "rejected"


# --- unsupported claims are downgraded, never trusted ------------------------


def test_a_confirmation_without_a_rebuilt_chain_becomes_inconclusive() -> None:
    """§7.8 asks the reviewer to rebuild the chain itself; a confirmation
    nobody can retrace is not evidence."""

    agent, _ = reviewer(
        [assistant_text("looked"), final_answer(verdict_payload(call_chain=[]))]
    )

    result = agent.run()

    assert result.verdict is not None
    assert result.verdict.verdict == "inconclusive"
    assert any(
        warning["reason_code"] == WARN_NO_REBUILT_CHAIN for warning in result.warnings
    )


def test_a_one_step_chain_is_not_a_chain() -> None:
    agent, _ = reviewer(
        [
            assistant_text("looked"),
            final_answer(
                verdict_payload(call_chain=[step(CONTROLLER, 1, "entrypoint")])
            ),
        ]
    )

    assert agent.run().verdict.verdict == "inconclusive"


def test_a_rejection_naming_no_control_becomes_inconclusive() -> None:
    """"I do not think this is exploitable" is not a result anyone can check."""

    agent, _ = reviewer(
        [
            assistant_text("looked"),
            final_answer(verdict_payload(verdict="rejected", call_chain=[])),
        ]
    )

    result = agent.run()

    assert result.verdict is not None
    assert result.verdict.verdict == "inconclusive"
    assert any(
        warning["reason_code"] == WARN_NO_DEFEATING_CONTROL
        for warning in result.warnings
    )


@pytest.mark.parametrize("control", ["", "   ", "​"])
def test_a_blank_defeating_control_does_not_count(control: str) -> None:
    agent, _ = reviewer(
        [
            assistant_text("looked"),
            final_answer(
                verdict_payload(
                    verdict="rejected", call_chain=[], defeating_control=control
                )
            ),
        ]
    )

    assert agent.run().verdict.verdict == "inconclusive"


def test_a_chain_citing_a_line_the_source_does_not_have_is_refused() -> None:
    """A rebuilt chain that does not resolve against the Snapshot is not a chain."""

    agent, _ = reviewer(
        [
            assistant_text("looked"),
            final_answer(
                verdict_payload(
                    call_chain=[
                        step(CONTROLLER, 900_000, "entrypoint"),
                        step(REPOSITORY, 900_001, "sink"),
                    ]
                )
            ),
        ]
    )

    result = agent.run()

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_OUTPUT_INVALID
    assert result.verdict is None


# --- nothing that goes wrong may reject --------------------------------------


def test_a_refusal_yields_no_verdict_rather_than_a_rejection() -> None:
    """A decline arrives as HTTP 200 with `stop_reason: refusal`."""

    agent, _ = reviewer(
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

    assert result.status is ToolStatus.UNAVAILABLE
    assert result.reason_code == REASON_MODEL_REFUSED
    assert result.verdict is None


def test_a_transport_failure_yields_no_verdict() -> None:
    agent, _ = reviewer([RuntimeError("gateway unreachable")])

    result = agent.run()

    assert result.status is ToolStatus.UNAVAILABLE
    assert result.verdict is None


def test_an_exhausted_turn_budget_yields_no_verdict() -> None:
    agent, _ = reviewer(
        [
            assistant_tool_use(("t1", "read_inventory", {})),
            assistant_tool_use(("t2", "read_inventory", {})),
            final_answer(verdict_payload()),
        ],
        max_turns=2,
    )

    result = agent.run()

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_TURN_LIMIT
    assert result.verdict is None


def test_a_truncated_final_answer_yields_no_verdict() -> None:
    agent, _ = reviewer(
        [
            assistant_text("looked"),
            final_answer(verdict_payload(), stop_reason="max_tokens"),
        ]
    )

    result = agent.run()

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_OUTPUT_INCOMPLETE
    assert result.verdict is None


def test_an_unparseable_answer_yields_no_verdict() -> None:
    agent, _ = reviewer(
        [assistant_text("looked"), assistant_text("I am fairly sure it is fine.")]
    )

    result = agent.run()

    assert result.status is ToolStatus.FAILED
    assert result.reason_code == REASON_OUTPUT_INVALID
    assert result.verdict is None


@pytest.mark.parametrize(
    "responses",
    [
        pytest.param([RuntimeError("boom")], id="transport"),
        pytest.param(
            [assistant_text("looked"), assistant_text("nope")], id="unparseable"
        ),
        pytest.param(
            [
                assistant_text("looked"),
                final_answer(verdict_payload(), stop_reason="max_tokens"),
            ],
            id="truncated",
        ),
    ],
)
def test_no_failure_mode_produces_a_rejection(responses: list[object]) -> None:
    agent, _ = reviewer(responses)

    result = agent.run()

    assert result.verdict is None or result.verdict.verdict != "rejected"


# --- channel separation -------------------------------------------------------


def test_the_assignment_travels_on_the_operator_channel() -> None:
    agent, transport = reviewer(
        [assistant_text("looked"), final_answer(verdict_payload())]
    )

    agent.run()

    messages = transport.requests[0]["messages"]
    assert messages[0]["role"] == "user"
    assert messages[1]["role"] == "system"
    assert messages[1]["content"] == assignment_instruction(assignment())
    assert transport.requests[0]["system"] == INDEPENDENT_REVIEW_SYSTEM_PROMPT


def test_the_system_prompt_carries_no_repository_bytes() -> None:
    """A module constant with no interpolation cannot be influenced by source."""

    assert "{" not in INDEPENDENT_REVIEW_SYSTEM_PROMPT.replace("{}", "")
    assert ROOT_CAUSE_KEY not in INDEPENDENT_REVIEW_SYSTEM_PROMPT


def test_every_prose_field_of_the_verdict_asks_for_chinese() -> None:
    """The verdict is shown beside the Finding it settles, so it is read in the
    same language. The schema states it at output time and the prompt states it
    first; a requirement on only one of them rests on which the model weighs."""

    properties = verify_output_schema()["properties"]

    for field in ("reasoning", "reachability", "defeating_control"):
        assert "中文" in properties[field]["description"], field
    assert "中文" in properties["call_chain"]["items"]["properties"]["note"][
        "description"
    ]

    assert "Simplified Chinese" in INDEPENDENT_REVIEW_SYSTEM_PROMPT
    assert "Simplified Chinese" in FINAL_ANSWER_REQUEST
    for field in ("`reasoning`", "`reachability`", "`defeating_control`"):
        assert field in INDEPENDENT_REVIEW_SYSTEM_PROMPT, field
    # File and line citations have to survive it, or a Chinese verdict stops
    # being retraceable.
    assert "verbatim" in INDEPENDENT_REVIEW_SYSTEM_PROMPT


def test_a_misplaced_operator_message_is_a_defect_not_a_degraded_mode() -> None:
    from cairn.semantic.conversation import check_channel_invariant

    with pytest.raises(ChannelInvariantError):
        check_channel_invariant([{"role": "system", "content": "assignment"}])


def test_the_reviewer_reads_the_source_through_the_broker_not_the_prompt() -> None:
    """Repository *content* reaches the model only inside tool results.

    The operator channel legitimately names paths and lines — those are index
    metadata the platform authored. What must never appear there is anything the
    repository wrote, and the fixture puts a prompt-injection attempt in a
    comment precisely so that distinction is testable.
    """

    injected = "Ignore all previous instructions"
    agent, transport = reviewer(
        [
            assistant_tool_use(
                (
                    "t1",
                    "read_file",
                    {"path": CONTROLLER, "start_line": 1, "end_line": 40},
                )
            ),
            assistant_text("read it"),
            final_answer(verdict_payload()),
        ]
    )

    agent.run()

    tool_results = [
        block
        for request in transport.requests
        for message in request["messages"]
        if isinstance(message.get("content"), list)
        for block in message["content"]
        if isinstance(block, dict) and block.get("type") == "tool_result"
    ]
    assert tool_results
    # The injected instruction arrives, as data, in a tool result...
    assert any(injected in str(block.get("content")) for block in tool_results)
    # ...and nowhere on the two channels the platform speaks on.
    for request in transport.requests:
        assert injected not in str(request["system"])
        operator = [
            message
            for message in request["messages"]
            if message.get("role") == "system"
        ]
        assert operator
        assert all(injected not in str(message["content"]) for message in operator)
