"""The Semantic Reviewer's conversation driver (§7.5, §9.6, §9.7, §13.5).

One :class:`SemanticReviewer` reviews one scope and returns one
:class:`~cairn.semantic.contracts.SemanticReviewResult`. The tool-use loop,
channel-invariant checks and usage accounting live in
:mod:`cairn.semantic.conversation`, shared with the Independent Reviewer
(§7.8); what stays here is this agent's remit.

Three properties are load-bearing and each is enforced rather than assumed:

**Channel separation (§9.6).** Instructions and repository bytes travel on
different channels and are never concatenated. ``system`` is the byte-stable
module constant :data:`~cairn.semantic.prompt.JAVA_AUDIT_SYSTEM_PROMPT`;
``messages[0]`` is the platform's user kickoff; ``messages[1]`` is the
mid-conversation operator channel carrying the scope assignment. Repository
content — source, README, ``AGENTS.md``, ``CLAUDE.md``, comments, fixtures,
build logs — reaches the model only inside ``tool_result`` blocks.

**No candidate is confirmed.** The model's answer is parsed by
:func:`~cairn.semantic.findings.parse_findings`, which enforces the §7.5
evidence rules against untrusted output. Output missing a code location, a call
chain or a controllability statement becomes a recorded rejection, never a
candidate. There is no path in this module that promotes model output past that
gate.

**A refusal is a visible outcome, not a silent empty result.** A decline
produces ``ToolStatus.UNAVAILABLE`` with ``SEMANTIC_MODEL_REFUSED`` and a
warning carrying the refusal category, so the run's coverage report shows the
scope was not reviewed. A zero-finding *completed* review means the model
looked and found nothing defensible; the two must never be confusable.
"""

from __future__ import annotations

import logging

from cairn.semantic.client import (
    DEFAULT_MODEL,
    STOP_MAX_TOKENS,
    STOP_PAUSE_TURN,
    SemanticModelClient,
    SemanticRefusal,
    SemanticUnavailable,
    stop_reason_of,
)
from cairn.semantic.broker import ToolBroker
from cairn.semantic.conversation import (
    MAX_WARNINGS,
    TOOL_BUDGET_EXHAUSTED,
    TOOL_USE_INVALID,
    ChannelInvariantError,
    ConversationCodes,
    ToolConversation,
    check_channel_invariant,
)
from cairn.semantic.contracts import (
    REASON_OUTPUT_INCOMPLETE,
    REASON_MODEL_REFUSED,
    REASON_TURN_LIMIT,
    SEMANTIC_CONTRACT,
    SEMANTIC_TOOL_NAME,
    SemanticFinding,
    SemanticRejection,
    SemanticReviewResult,
    SemanticUsage,
    semantic_output_schema,
)
from cairn.semantic.findings import ReviewScope, parse_findings
from cairn.semantic.prompt import (
    JAVA_AUDIT_SYSTEM_PROMPT,
    initial_user_message,
    scope_instruction,
)
from cairn.analysis.contracts import ToolStatus

LOG = logging.getLogger(__name__)

REASON_TOOL_BUDGET = "SEMANTIC_TOOL_BUDGET_REACHED"

SEMANTIC_CODES = ConversationCodes(
    turn_limit=REASON_TURN_LIMIT,
    tool_budget=REASON_TOOL_BUDGET,
    output_incomplete=REASON_OUTPUT_INCOMPLETE,
)

FINAL_ANSWER_REQUEST = (
    "Stop reading and report now. Return the structured result for the assigned"
    " scope in the required schema, with an empty findings array if the scope"
    " holds no candidate you can support with a location, a call chain and a"
    " controllability statement."
)

# Retained for callers that imported them from this module before the
# conversation driver was extracted.
_check_channel_invariant = check_channel_invariant

__all__ = [
    "FINAL_ANSWER_REQUEST",
    "MAX_WARNINGS",
    "REASON_TOOL_BUDGET",
    "SEMANTIC_CODES",
    "TOOL_BUDGET_EXHAUSTED",
    "TOOL_USE_INVALID",
    "ChannelInvariantError",
    "SemanticReviewer",
]


class SemanticReviewer:
    """Drives one scope's review conversation to a validated result."""

    def __init__(
        self,
        client: SemanticModelClient,
        broker: ToolBroker,
        *,
        scope: ReviewScope,
        model: str = DEFAULT_MODEL,
        max_turns: int = 24,
        max_tool_calls: int = 200,
    ) -> None:
        self._broker = broker
        self._scope = scope
        self._model = model
        self._conversation = ToolConversation(
            client,
            broker,
            system=JAVA_AUDIT_SYSTEM_PROMPT,
            # ``messages[1]`` is the operator channel. It cannot be
            # ``messages[0]``, which is exactly why the kickoff comes first: the
            # scope assignment is a platform directive and belongs on a channel
            # repository bytes never touch.
            initial_messages=[
                {"role": "user", "content": initial_user_message(scope)},
                {"role": "system", "content": scope_instruction(scope)},
            ],
            output_schema=semantic_output_schema(),
            final_answer_request=FINAL_ANSWER_REQUEST,
            codes=SEMANTIC_CODES,
            warning_context={
                "tool": SEMANTIC_TOOL_NAME,
                "scope_key": scope.scope_key,
            },
            max_turns=max_turns,
            max_tool_calls=max_tool_calls,
        )

    def run(self) -> SemanticReviewResult:
        """Review the scope and return the per-scope manifest.

        Never raises for a model-side outcome: a decline, a transport failure, a
        budget rejection and an exhausted turn allowance all become a
        non-completed result carrying a reason code. A defect in the platform
        itself — a broker crash that is not a :class:`BrokerError`, a channel
        invariant violation — does propagate, because silently degrading it
        would hide the defect behind a plausible empty review.
        """

        try:
            limit_reason = self._conversation.explore()
            response = self._conversation.request_final_answer()
        except SemanticRefusal as refusal:
            # §13.5: a decline is reported, not swallowed and not raised.
            self._conversation.warn(
                REASON_MODEL_REFUSED,
                detail=(
                    "model declined the scope "
                    f"(category={refusal.category or 'unknown'})"
                ),
                category=refusal.category,
            )
            return self._result(
                status=ToolStatus.UNAVAILABLE,
                reason_code=REASON_MODEL_REFUSED,
            )
        except SemanticUnavailable as unavailable:
            self._conversation.warn(
                unavailable.reason_code,
                detail=unavailable.detail,
            )
            return self._result(
                status=ToolStatus.UNAVAILABLE,
                reason_code=unavailable.reason_code,
            )

        final_stop = stop_reason_of(response)
        # Truncated at the ceiling, or still paused with no turns left to resume
        # it — either way the structured answer is not known to be complete.
        incomplete = final_stop in {STOP_MAX_TOKENS, STOP_PAUSE_TURN}
        if incomplete:
            self._conversation.warn(
                REASON_OUTPUT_INCOMPLETE,
                detail=f"final answer did not finish (stop_reason={final_stop})",
            )
        findings, rejections = parse_findings(
            self._conversation.structured_payload(response),
            catalog=self._broker.catalog,
        )
        if not findings:
            # A non-completed result may carry neither findings nor a missing
            # reason code, so the choice between salvaging what the model did
            # produce and failing the scope is made once, here. With findings in
            # hand the scope is COMPLETED and the limit survives as a warning;
            # with nothing to show, reporting "completed, zero findings" would
            # claim a review that never happened.
            if limit_reason is not None:
                return self._result(
                    status=ToolStatus.FAILED,
                    reason_code=REASON_TURN_LIMIT,
                    rejections=rejections,
                )
            if incomplete:
                return self._result(
                    status=ToolStatus.FAILED,
                    reason_code=REASON_OUTPUT_INCOMPLETE,
                    rejections=rejections,
                )
        return self._result(
            status=ToolStatus.COMPLETED,
            reason_code=None,
            findings=findings,
            rejections=rejections,
        )

    def _result(
        self,
        *,
        status: ToolStatus,
        reason_code: str | None,
        findings: list[SemanticFinding] | None = None,
        rejections: list[SemanticRejection] | None = None,
    ) -> SemanticReviewResult:
        return SemanticReviewResult(
            contract=SEMANTIC_CONTRACT,
            status=status,
            tool_name=SEMANTIC_TOOL_NAME,
            model=self._conversation.served_model or self._model,
            scope_key=self._scope.scope_key,
            reason_code=reason_code,
            findings=list(findings or []),
            rejections=list(rejections or []),
            warnings=list(self._conversation.warnings),
            usage=SemanticUsage(**self._conversation.usage),
        )
