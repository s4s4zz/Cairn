"""The tool-use conversation driver shared by Cairn's reviewing agents.

Extracted from :mod:`cairn.semantic.review` when the Independent Reviewer
(§7.8) arrived and needed the same loop. The mechanics here are worth sharing
precisely because none of them are obvious and all of them were paid for once:

* a ``pause_turn`` must be appended verbatim and re-sent — the Python SDK does
  not auto-resume;
* a turn truncated at ``max_tokens`` may still carry complete ``tool_use``
  blocks, each of which the API requires a matching ``tool_result`` for, and
  the request that follows must not end on an assistant turn;
* every refused tool call still returns an ``is_error`` result, so the model
  can correct itself and no ``tool_use`` is left unanswered;
* the §9.6 channel layout is asserted before every request, because a
  misplaced operator-channel message does not fail loudly — it silently
  relocates platform directives next to a channel repository content can
  imitate.

What stays with each agent is its remit: the system prompt, the opening
messages, the output schema, and what to do with the answer. This class knows
nothing about findings or verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import logging

from cairn.semantic.broker import BrokerError, ToolBroker
from cairn.semantic.client import (
    STOP_MAX_TOKENS,
    STOP_PAUSE_TURN,
    STOP_TOOL_USE,
    SemanticModelClient,
    content_blocks,
    response_field,
    stop_reason_of,
)

LOG = logging.getLogger(__name__)

MAX_WARNINGS = 64
_TOOL_RESULT_MAX_BYTES = 96 * 1024

# Refused tool calls that originate in this module rather than in the broker.
TOOL_USE_INVALID = "TOOL_USE_INVALID"
TOOL_BUDGET_EXHAUSTED = "TOOL_BUDGET_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class ConversationCodes:
    """Reason codes an agent wants recorded for the shared limit conditions.

    Parameterised rather than shared constants so a verify result never reports
    a ``SEMANTIC_*`` code and vice versa: the code is what an operator greps
    for, so it has to name the stage that actually hit the limit.
    """

    turn_limit: str
    tool_budget: str
    output_incomplete: str


class ChannelInvariantError(RuntimeError):
    """The message list violates the §9.6 channel layout.

    Raised instead of sending the request. A misplaced operator-channel message
    is a security defect, not a degraded mode, so it must never reach the API.
    """


def check_channel_invariant(messages: list[dict]) -> None:
    """Enforce the §9.6 channel layout on an outgoing message list.

    Two rules, both of which the Messages API would otherwise accept or reject
    for its own reasons rather than ours:

    * ``messages[0]`` must be the platform's user kickoff. A ``system`` message
      at index 0 is rejected by the API, but a *missing* one is not — and a
      conversation whose first turn is not ours is a conversation whose framing
      we do not control.
    * every ``{"role": "system"}`` message must sit immediately after a user
      message. The operator channel is only meaningful where the API defines
      it; anywhere else it is an ordinary text turn wearing a trusted label.
    """

    if not messages:
        raise ChannelInvariantError("message list must not be empty")
    if messages[0].get("role") != "user":
        raise ChannelInvariantError("messages[0] must be the platform user kickoff")
    for index, message in enumerate(messages):
        if message.get("role") != "system":
            continue
        if index == 0:
            raise ChannelInvariantError(
                "an operator-channel message cannot be messages[0]"
            )
        if messages[index - 1].get("role") != "user":
            raise ChannelInvariantError(
                "an operator-channel message must follow a user message"
            )
        # The API's placement rule has a second half: a mid-conversation system
        # message must be last or be followed by an assistant turn. A misplaced
        # one does not fail loudly — it silently relocates platform directives
        # next to a channel repository content can imitate.
        if index + 1 < len(messages) and messages[index + 1].get("role") != "assistant":
            raise ChannelInvariantError(
                "an operator-channel message must be last or precede an"
                " assistant message"
            )


def is_unanswerable_tool_use(block: object) -> bool:
    """A ``tool_use`` block with no usable id, which nothing can reply to."""

    if response_field(block, "type") != "tool_use":
        return False
    tool_use_id = response_field(block, "id")
    return not isinstance(tool_use_id, str) or not tool_use_id


def tool_use_calls(response: object) -> list[object]:
    """Every ``tool_use`` block in the response, in order."""

    return [
        block
        for block in content_blocks(response)
        if response_field(block, "type") == "tool_use"
    ]


def tool_result(tool_use_id: str, content: str) -> dict[str, object]:
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": content,
    }


def tool_error(tool_use_id: str, code: str, message: str) -> dict[str, object]:
    """A refused tool call, returned to the model so it can correct itself.

    ``is_error`` is what makes the refusal legible: the model sees that the call
    failed and why. Dropping the block instead would leave a ``tool_use`` with
    no matching result, which the API rejects, and would hide the refusal from
    both the model and the audit log.
    """

    block = tool_result(tool_use_id, f"{code}: {message}")
    block["is_error"] = True
    return block


def encode_payload(payload: object) -> str:
    """Serialize a broker result for the model.

    ``default=str`` keeps an unexpected value type from raising mid-loop; the
    byte cap is a second bound behind the broker's own limits, so a large index
    cannot blow up the context on its own.
    """

    try:
        text = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError):  # pragma: no cover - defensive
        text = str(payload)
    if len(text.encode("utf-8")) <= _TOOL_RESULT_MAX_BYTES:
        return text
    clipped = text.encode("utf-8")[:_TOOL_RESULT_MAX_BYTES].decode("utf-8", "ignore")
    return f"{clipped}\n[truncated: tool result exceeded the transfer limit]"


class ToolConversation:
    """One agent's read-only tool-use conversation, from kickoff to final answer."""

    def __init__(
        self,
        client: SemanticModelClient,
        broker: ToolBroker,
        *,
        system: str,
        initial_messages: list[dict],
        output_schema: dict,
        final_answer_request: str,
        codes: ConversationCodes,
        warning_context: dict[str, object],
        max_turns: int = 24,
        max_tool_calls: int = 200,
    ) -> None:
        if max_turns < 2:
            # One request cannot both explore and deliver the final answer.
            raise ValueError("max_turns must allow at least two requests")
        if max_tool_calls < 0:
            raise ValueError("max_tool_calls must not be negative")
        check_channel_invariant(initial_messages)
        self._client = client
        self._broker = broker
        self._system = system
        self._output_schema = output_schema
        self._final_answer_request = final_answer_request
        self._codes = codes
        self._warning_context = dict(warning_context)
        self._max_turns = max_turns
        self._max_tool_calls = max_tool_calls

        self.messages: list[dict] = list(initial_messages)
        self.warnings: list[dict[str, object]] = []
        self.served_model: str | None = None
        self.usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "requests": 0,
        }
        self._turns = 0
        self._tool_calls = 0

    # -- conversation ------------------------------------------------------

    def explore(self) -> str | None:
        """Run the tool-use loop. Returns a limit reason code, or ``None``.

        One request per iteration. Every requested tool is executed and every
        result — success or refusal — returns in a single user message, which is
        what the API requires for parallel tool use and what keeps a refused
        call from vanishing.
        """

        tools = self._broker.tool_definitions()
        limit_reason: str | None = None
        # One request is always held back for the final structured answer.
        while self._turns < self._max_turns - 1:
            response = self._create(tools=tools)
            stop_reason = stop_reason_of(response)

            if stop_reason == STOP_PAUSE_TURN:
                # The Python SDK does not auto-resume. The documented pattern
                # is to append the paused turn verbatim and send again.
                self.messages.append(self.assistant_turn(response))
                continue
            if stop_reason == STOP_MAX_TOKENS:
                # A truncated exploration turn is recoverable, but only if the
                # history stays well formed: any tool_use block it managed to
                # emit still needs a matching tool_result, and the request that
                # follows must not end on an assistant turn (a trailing
                # assistant message is a prefill, which this model rejects).
                self.warn(
                    self._codes.output_incomplete,
                    detail="an exploration turn hit the output token ceiling",
                )
                self.messages.append(self.assistant_turn(response))
                self._answer_truncated_calls(response)
                continue
            if stop_reason != STOP_TOOL_USE:
                self.messages.append(self.assistant_turn(response))
                return limit_reason

            calls = tool_use_calls(response)
            self.messages.append(self.assistant_turn(response))
            results: list[dict[str, object]] = []
            for call in calls:
                block, exhausted = self._execute(call)
                results.append(block)
                if exhausted:
                    limit_reason = self._codes.tool_budget
            # All results in one user message, tool_result blocks first.
            self.messages.append({"role": "user", "content": results})
            if limit_reason is not None:
                self.warn(
                    self._codes.tool_budget,
                    detail=f"tool call budget of {self._max_tool_calls} was reached",
                )
                return limit_reason

        self.warn(
            self._codes.turn_limit,
            detail=f"turn budget of {self._max_turns} was reached",
        )
        return self._codes.turn_limit

    def request_final_answer(self) -> object:
        """Ask for the structured result with tools disabled.

        ``tool_choice`` is ``none`` so the model cannot answer with another tool
        call, and ``tools`` stays present so the definitions still match the
        ``tool_use`` blocks already in the history.
        """

        self.append_user_text(self._final_answer_request)
        tools = self._broker.tool_definitions()
        while True:
            response = self._create(
                tools=tools,
                output_schema=self._output_schema,
                tool_choice={"type": "none"},
            )
            if (
                stop_reason_of(response) == STOP_PAUSE_TURN
                and self._turns < self._max_turns
            ):
                self.messages.append(self.assistant_turn(response))
                continue
            return response

    def _answer_truncated_calls(self, response: object) -> None:
        """Close out a truncated assistant turn so the history stays valid.

        A turn cut off at ``max_tokens`` may still contain complete ``tool_use``
        blocks, each of which the API requires a matching ``tool_result`` for.
        Those calls are answered as errors rather than executed: the turn that
        requested them was incomplete, so the arguments cannot be trusted to be
        what the model meant. Either way the next message is a user turn, which
        is what the request after this one needs.
        """

        results: list[dict[str, object]] = []
        for call in tool_use_calls(response):
            tool_use_id = response_field(call, "id")
            if isinstance(tool_use_id, str) and tool_use_id:
                results.append(
                    tool_error(
                        tool_use_id,
                        TOOL_USE_INVALID,
                        "the turn that requested this call was truncated; issue"
                        " the call again if you still need it",
                    )
                )
        results.append(
            {
                "type": "text",
                "text": "Your previous turn was cut off at the output limit."
                " Continue with shorter turns.",
            }
        )
        self.messages.append({"role": "user", "content": results})

    def _execute(self, call: object) -> tuple[dict[str, object], bool]:
        """Run one requested tool call. Returns its block and a budget flag.

        A malformed request, an exhausted budget and a broker refusal all
        produce an ``is_error`` result rather than an exception: the loop
        continues, the model can correct itself, and every ``tool_use`` keeps a
        matching ``tool_result``.
        """

        tool_use_id = response_field(call, "id")
        name = response_field(call, "name")
        arguments = response_field(call, "input")
        if not isinstance(tool_use_id, str) or not tool_use_id:
            # Without an id there is nothing to answer; recorded and skipped.
            self.warn(TOOL_USE_INVALID, detail="tool_use block carried no id")
            return ({"type": "text", "text": "[malformed tool_use block ignored]"}, False)
        if not isinstance(name, str) or not name:
            return (
                tool_error(tool_use_id, TOOL_USE_INVALID, "tool_use block named no tool"),
                False,
            )
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            return (
                tool_error(
                    tool_use_id,
                    TOOL_USE_INVALID,
                    "tool arguments must be an object",
                ),
                False,
            )
        if self._tool_calls >= self._max_tool_calls:
            return (
                tool_error(
                    tool_use_id,
                    TOOL_BUDGET_EXHAUSTED,
                    "the tool call budget for this scope is exhausted; report"
                    " what you have established so far",
                ),
                True,
            )

        self._tool_calls += 1
        try:
            payload = self._broker.invoke(name, arguments)
        except BrokerError as refused:
            # Codes only: the message is written for the model and the code is
            # what the audit log keys on. No repository bytes are logged.
            LOG.debug(
                "agent tool call refused",
                extra={"tool": name, "broker_code": refused.code},
            )
            return (tool_error(tool_use_id, refused.code, refused.message), False)
        return (tool_result(tool_use_id, encode_payload(payload)), False)

    def append_user_text(self, text: str) -> None:
        """Add platform text to the user channel without stacking two turns.

        When the previous message is the user turn carrying tool results, the
        text is appended after those blocks — ``tool_result`` blocks must come
        first in their message, and two consecutive user turns are avoidable
        noise in the cached prefix.
        """

        block = {"type": "text", "text": text}
        if self.messages and self.messages[-1].get("role") == "user":
            content = self.messages[-1].get("content")
            if isinstance(content, list):
                content.append(block)
                return
            if isinstance(content, str):
                self.messages[-1]["content"] = [
                    {"type": "text", "text": content},
                    block,
                ]
                return
        self.messages.append({"role": "user", "content": [block]})

    def assistant_turn(self, response: object) -> dict[str, object]:
        """Echo the assistant turn back, minus blocks that cannot be answered.

        Every block is preserved, thinking blocks included: dropping them
        breaks tool-use continuation on a thinking model. The one exception is
        a ``tool_use`` block with no usable id — it cannot be given a matching
        ``tool_result``, and the API rejects a history containing an unanswered
        ``tool_use``, which would cost the whole scope on the next turn.
        """

        blocks = [
            block
            for block in content_blocks(response)
            if not is_unanswerable_tool_use(block)
        ]
        return {"role": "assistant", "content": blocks}

    def _create(
        self,
        *,
        tools: list[dict] | None,
        output_schema: dict | None = None,
        tool_choice: dict | None = None,
    ) -> object:
        """Send one request, accounting for it before it leaves.

        The request is counted before dispatch so a failure still shows up in
        the usage record; token counts are added only for a request that
        returned one.
        """

        check_channel_invariant(self.messages)
        self._turns += 1
        self.usage["requests"] += 1
        response = self._client.create(
            system=self._system,
            messages=self.messages,
            tools=tools,
            output_schema=output_schema,
            tool_choice=tool_choice,
        )
        self._record_usage(response)
        return response

    # -- accounting --------------------------------------------------------

    def _record_usage(self, response: object) -> None:
        served = response_field(response, "model")
        if isinstance(served, str) and 0 < len(served) <= 255:
            # The Gateway's refusal fallback can serve a different model than
            # was requested, so the manifest reports what actually answered.
            self.served_model = served
        usage = response_field(response, "usage")
        if usage is None:
            return
        for field in (
            "input_tokens",
            "output_tokens",
            "cache_read_input_tokens",
            "cache_creation_input_tokens",
        ):
            value = response_field(usage, field)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                continue
            self.usage[field] += value

    def warn(
        self,
        reason_code: str,
        *,
        detail: str = "",
        category: str | None = None,
    ) -> None:
        """Record a coverage warning, deduplicated and bounded.

        Mirrors the orchestrator's warning shape so an agent warning merges into
        the run's coverage report without special handling.
        """

        if len(self.warnings) >= MAX_WARNINGS:
            return
        warning: dict[str, object] = {
            "reason_code": reason_code,
            **self._warning_context,
        }
        if detail:
            warning["detail"] = detail[:512]
        if category:
            warning["category"] = category[:128]
        key = (reason_code, warning.get("detail"))
        if any(
            (existing.get("reason_code"), existing.get("detail")) == key
            for existing in self.warnings
        ):
            return
        self.warnings.append(warning)

    def structured_payload(self, response: object) -> object:
        """Extract the model's final answer as data.

        Returned as-is when it does not decode: a malformed answer belongs with
        the caller's parser, which records it as a rejection. Repairing it here
        would invent evidence.
        """

        parsed = response_field(response, "parsed")
        if isinstance(parsed, (dict, list)):
            return parsed
        chunks: list[str] = []
        for block in content_blocks(response):
            if response_field(block, "type") != "text":
                continue
            text = response_field(block, "text")
            if isinstance(text, str):
                chunks.append(text)
        joined = "".join(chunks)
        if not joined.strip():
            return {}
        try:
            return json.loads(joined)
        except (TypeError, ValueError):
            return joined
