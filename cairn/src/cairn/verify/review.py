"""The Independent Reviewer's conversation driver (§7.8, §9.6, §9.7, §13.6).

One :class:`IndependentReviewer` reviews one candidate and returns one
:class:`~cairn.verify.contracts.VerifyResult`. The loop itself is
:class:`~cairn.semantic.conversation.ToolConversation`, shared with the
Semantic Reviewer; what lives here is the rule that makes this stage a
verification rather than a second opinion:

**Nothing that goes wrong produces a rejection.** A refusal, a transport
failure, an exhausted turn budget, an unparseable answer, a confirmation with
no rebuilt chain, a rejection with no named control — every one of them becomes
``inconclusive``. §7.7 states the rule for dynamic verification ("environment
missing, build failure and timeout produce inconclusive, never rejected") and
it holds just as firmly here: a reviewer that could not do its job must not be
able to delete a candidate.
"""

from __future__ import annotations

import logging

from pydantic import ValidationError

from cairn.analysis.contracts import ToolStatus
from cairn.semantic.broker import ToolBroker
from cairn.semantic.client import (
    DEFAULT_MODEL,
    STOP_MAX_TOKENS,
    STOP_PAUSE_TURN,
    SemanticModelClient,
    SemanticRefusal,
    SemanticUnavailable,
    stop_reason_of,
)
from cairn.semantic.conversation import ConversationCodes, ToolConversation
from cairn.verify.contracts import (
    REASON_MODEL_REFUSED,
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    REASON_TOOL_BUDGET,
    REASON_TURN_LIMIT,
    VERIFY_CONTRACT,
    VERIFY_TOOL_NAME,
    IndependentVerdict,
    VerifyResult,
    VerifyUsage,
    parse_verdict,
    verify_output_schema,
)
from cairn.verify.prompt import (
    FINAL_ANSWER_REQUEST,
    INDEPENDENT_REVIEW_SYSTEM_PROMPT,
    VerifyAssignment,
    assignment_instruction,
    initial_user_message,
)

LOG = logging.getLogger(__name__)

VERIFY_CODES = ConversationCodes(
    turn_limit=REASON_TURN_LIMIT,
    tool_budget=REASON_TOOL_BUDGET,
    output_incomplete=REASON_OUTPUT_INCOMPLETE,
)

# What an unusable answer becomes. Named so the intent is greppable: this is
# the only verdict a failure may produce.
INCONCLUSIVE = "inconclusive"


class IndependentReviewer:
    """Drives one candidate's blind review to a validated verdict."""

    def __init__(
        self,
        client: SemanticModelClient,
        broker: ToolBroker,
        *,
        assignment: VerifyAssignment,
        model: str = DEFAULT_MODEL,
        max_turns: int = 16,
        max_tool_calls: int = 120,
    ) -> None:
        self._broker = broker
        self._assignment = assignment
        self._model = model
        self._conversation = ToolConversation(
            client,
            broker,
            system=INDEPENDENT_REVIEW_SYSTEM_PROMPT,
            initial_messages=[
                {"role": "user", "content": initial_user_message()},
                {"role": "system", "content": assignment_instruction(assignment)},
            ],
            output_schema=verify_output_schema(),
            final_answer_request=FINAL_ANSWER_REQUEST,
            codes=VERIFY_CODES,
            warning_context={
                "tool": VERIFY_TOOL_NAME,
                "root_cause_key": assignment.root_cause_key,
            },
            max_turns=max_turns,
            max_tool_calls=max_tool_calls,
        )

    def run(self) -> VerifyResult:
        """Review the candidate and return the manifest.

        Never raises for a model-side outcome. A platform defect — a broker
        crash that is not a ``BrokerError``, a channel invariant violation —
        does propagate, because degrading it silently would hide the defect
        behind a plausible inconclusive.
        """

        try:
            limit_reason = self._conversation.explore()
            response = self._conversation.request_final_answer()
        except SemanticRefusal as refusal:
            self._conversation.warn(
                REASON_MODEL_REFUSED,
                detail=(
                    "model declined the candidate "
                    f"(category={refusal.category or 'unknown'})"
                ),
                category=refusal.category,
            )
            return self._failed(REASON_MODEL_REFUSED, ToolStatus.UNAVAILABLE)
        except SemanticUnavailable as unavailable:
            self._conversation.warn(
                unavailable.reason_code,
                detail=unavailable.detail,
            )
            return self._failed(unavailable.reason_code, ToolStatus.UNAVAILABLE)

        final_stop = stop_reason_of(response)
        if final_stop in {STOP_MAX_TOKENS, STOP_PAUSE_TURN}:
            self._conversation.warn(
                REASON_OUTPUT_INCOMPLETE,
                detail=f"final answer did not finish (stop_reason={final_stop})",
            )
            return self._failed(REASON_OUTPUT_INCOMPLETE, ToolStatus.FAILED)
        if limit_reason is not None:
            # The reviewer ran out of budget before it finished reading. Its
            # answer describes an incomplete investigation.
            return self._failed(limit_reason, ToolStatus.FAILED)

        try:
            verdict, downgrades = parse_verdict(
                self._conversation.structured_payload(response),
                catalog=self._broker.catalog,
            )
        except (ValidationError, ValueError) as exc:
            self._conversation.warn(REASON_OUTPUT_INVALID, detail=_detail(exc))
            return self._failed(REASON_OUTPUT_INVALID, ToolStatus.FAILED)

        for reason_code, detail in downgrades:
            self._conversation.warn(reason_code, detail=detail)
        return VerifyResult(
            contract=VERIFY_CONTRACT,
            status=ToolStatus.COMPLETED,
            tool_name=VERIFY_TOOL_NAME,
            model=self._conversation.served_model or self._model,
            root_cause_key=self._assignment.root_cause_key,
            reason_code=None,
            verdict=verdict,
            warnings=list(self._conversation.warnings),
            usage=VerifyUsage(**self._conversation.usage),
        )

    def _failed(self, reason_code: str, status: ToolStatus) -> VerifyResult:
        """A review that did not conclude.

        The manifest carries no verdict at all rather than an ``inconclusive``
        one: the orchestrator maps a missing verdict to ``inconclusive`` when it
        records the ``Verification``, and keeping the two representations
        distinct means "the reviewer decided it could not tell" and "the review
        never happened" stay legible in the stored result.
        """

        return VerifyResult(
            contract=VERIFY_CONTRACT,
            status=status,
            tool_name=VERIFY_TOOL_NAME,
            model=self._conversation.served_model or self._model,
            root_cause_key=self._assignment.root_cause_key,
            reason_code=reason_code,
            verdict=None,
            warnings=list(self._conversation.warnings),
            usage=VerifyUsage(**self._conversation.usage),
        )


def _detail(error: Exception) -> str:
    if isinstance(error, ValidationError):
        first = error.errors()[0]
        location = ".".join(str(part) for part in first.get("loc", ()))
        message = str(first.get("msg", "invalid"))
        return (f"{location}: {message}" if location else message)[:512]
    return str(error)[:512]


__all__ = ["INCONCLUSIVE", "IndependentReviewer", "IndependentVerdict"]
