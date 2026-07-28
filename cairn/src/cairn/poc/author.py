"""The PoC Author's conversation driver (§7.7, §9.6, §13.5).

One :class:`PocAuthor` writes one :class:`~cairn.poc.contracts.PocPlan` for one
Finding. The loop is
:class:`~cairn.semantic.conversation.ToolConversation`, shared with the two
reviewers; what lives here is the author's remit and the rule that a plan the
platform cannot use produces *no plan* rather than a broken one.

The author has the model channel and the read-only source, and no access to the
target application — it does not exist yet. That separation is the point: the
container that talks to the model cannot reach the application, and the container
that runs the PoC (the validation sandbox) cannot talk to the model. No single
context both writes a PoC and judges whether it worked.
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
from cairn.poc.contracts import (
    POC_CONTRACT,
    POC_TOOL_NAME,
    REASON_MODEL_REFUSED,
    REASON_OUTPUT_INCOMPLETE,
    REASON_OUTPUT_INVALID,
    REASON_TOOL_BUDGET,
    REASON_TURN_LIMIT,
    PocPlan,
    PocResult,
    poc_output_schema,
)
from cairn.poc.prompt import (
    FINAL_ANSWER_REQUEST,
    POC_AUTHOR_SYSTEM_PROMPT,
    PocAssignment,
    assignment_instruction,
    initial_user_message,
)

LOG = logging.getLogger(__name__)

POC_CODES = ConversationCodes(
    turn_limit=REASON_TURN_LIMIT,
    tool_budget=REASON_TOOL_BUDGET,
    output_incomplete=REASON_OUTPUT_INCOMPLETE,
)


class PocAuthor:
    """Drives one Finding's PoC authoring to a validated plan."""

    def __init__(
        self,
        client: SemanticModelClient,
        broker: ToolBroker,
        *,
        assignment: PocAssignment,
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
            system=POC_AUTHOR_SYSTEM_PROMPT,
            initial_messages=[
                {"role": "user", "content": initial_user_message()},
                {"role": "system", "content": assignment_instruction(assignment)},
            ],
            output_schema=poc_output_schema(),
            final_answer_request=FINAL_ANSWER_REQUEST,
            codes=POC_CODES,
            warning_context={
                "tool": POC_TOOL_NAME,
                "finding_id": assignment.finding_id,
            },
            max_turns=max_turns,
            max_tool_calls=max_tool_calls,
        )

    def run(self) -> PocResult:
        """Author the PoC and return the manifest.

        Never raises for a model-side outcome. A refusal, a transport failure,
        an exhausted budget and an unparseable or non-conforming answer all
        produce a manifest with no plan: the platform would rather have no PoC
        for a finding than run one it could not validate.
        """

        try:
            limit_reason = self._conversation.explore()
            response = self._conversation.request_final_answer()
        except SemanticRefusal as refusal:
            self._conversation.warn(
                REASON_MODEL_REFUSED,
                detail=(
                    "model declined to author a PoC "
                    f"(category={refusal.category or 'unknown'})"
                ),
                category=refusal.category,
            )
            return self._failed(REASON_MODEL_REFUSED, "unavailable")
        except SemanticUnavailable as unavailable:
            self._conversation.warn(
                unavailable.reason_code,
                detail=unavailable.detail,
            )
            return self._failed(unavailable.reason_code, "unavailable")

        final_stop = stop_reason_of(response)
        if final_stop in {STOP_MAX_TOKENS, STOP_PAUSE_TURN}:
            self._conversation.warn(
                REASON_OUTPUT_INCOMPLETE,
                detail=f"final answer did not finish (stop_reason={final_stop})",
            )
            return self._failed(REASON_OUTPUT_INCOMPLETE, "failed")
        if limit_reason is not None:
            return self._failed(limit_reason, "failed")

        payload = self._conversation.structured_payload(response)
        if not isinstance(payload, dict):
            self._conversation.warn(
                REASON_OUTPUT_INVALID,
                detail="the model answer was not a structured object",
            )
            return self._failed(REASON_OUTPUT_INVALID, "failed")
        try:
            plan = PocPlan.model_validate(
                {
                    **payload,
                    "finding_id": self._assignment.finding_id,
                    "category": self._assignment.category,
                }
            )
        except ValidationError as exc:
            # A plan the platform cannot use — a disallowed header, an absolute
            # path, a criterion that could not discriminate — is discarded here.
            self._conversation.warn(REASON_OUTPUT_INVALID, detail=_detail(exc))
            return self._failed(REASON_OUTPUT_INVALID, "failed")

        return PocResult(
            contract=POC_CONTRACT,
            status="completed",
            tool_name=POC_TOOL_NAME,
            model=self._conversation.served_model or self._model,
            finding_id=self._assignment.finding_id,
            reason_code=None,
            plan=plan,
            warnings=list(self._conversation.warnings),
        )

    def _failed(self, reason_code: str, status: str) -> PocResult:
        return PocResult(
            contract=POC_CONTRACT,
            status=status,
            tool_name=POC_TOOL_NAME,
            model=self._conversation.served_model or self._model,
            finding_id=self._assignment.finding_id,
            reason_code=reason_code,
            plan=None,
            warnings=list(self._conversation.warnings),
        )


def _detail(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = str(first.get("msg", "invalid"))
    return (f"{location}: {message}" if location else message)[:512]


__all__ = ["PocAuthor"]
