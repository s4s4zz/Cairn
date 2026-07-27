"""Messages API client for the Semantic Reviewer (§5.1, §9.5, §9.7).

Every request leaves through the LLM Gateway. The worker holds only a
short-lived grant bound to one AuditRun, one Worker and an expiry; the long-term
model API key exists solely inside the Gateway, so ``base_url`` points at the
Gateway origin and ``grant_token`` is what travels as ``x-api-key``. Nothing in
this module logs a prompt body, a response body, or the grant.

Two design choices are load-bearing:

* ``anthropic`` is imported lazily — inside :meth:`SemanticModelClient._build_transport`
  and inside :func:`_anthropic_error_labels` — never at module import time. The
  platform, and its test suite, must import and run without the SDK present; a
  caller supplying ``transport=`` never touches it at all.
* ``stop_reason`` is read before anything looks at ``content``. A safety decline
  arrives as HTTP 200 with ``stop_reason: "refusal"``, and ``stop_details`` is
  populated *only* then — ``null`` for every other stop reason. Branching on
  ``stop_details`` instead of ``stop_reason``, or indexing ``content`` first,
  turns a decline into an IndexError somewhere far away from its cause. This
  client therefore never reads ``content``: it hands the response back and
  exposes accessors so the caller can make the same ordering explicit.
"""

from __future__ import annotations

from collections.abc import Mapping
import logging
from typing import Protocol

from cairn.semantic.contracts import (
    REASON_BUDGET_EXHAUSTED,
    REASON_MODEL_UNAVAILABLE,
)

LOG = logging.getLogger(__name__)

DEFAULT_MODEL = "claude-opus-5"
# Effort is nested inside ``output_config``; a top-level ``effort`` is a 400.
EFFORT_LEVELS = ("low", "medium", "high", "xhigh", "max")
# The Python SDK refuses a non-streaming request it estimates will exceed ten
# minutes, so a large ``max_tokens`` must stream. The switch lives in exactly
# one place (:meth:`SemanticModelClient._dispatch`).
STREAMING_MAX_TOKENS = 16_000

STOP_END_TURN = "end_turn"
STOP_MAX_TOKENS = "max_tokens"
STOP_PAUSE_TURN = "pause_turn"
STOP_REFUSAL = "refusal"
STOP_STOP_SEQUENCE = "stop_sequence"
STOP_TOOL_USE = "tool_use"

# Gateway policy codes (``cairn.gateway.errors``) that mean something more
# specific than "the model is unavailable". Everything else collapses to
# REASON_MODEL_UNAVAILABLE, because the reviewer's only choice is whether the
# scope can be retried at all.
_GATEWAY_REASON_CODES = {"LLM_BUDGET_EXHAUSTED": REASON_BUDGET_EXHAUSTED}

_DETAIL_MAX_LENGTH = 200
_REDACTED = "[redacted]"
# Shorter than any minted grant (the MAC half alone is 43 base64url chars), and
# long enough that the value cannot be an ordinary substring of English or of a
# JSON field path. See :func:`_redact`.
_MIN_REDACTABLE_SECRET = 16


class SemanticRefusal(Exception):
    """The model declined the request (HTTP 200, ``stop_reason: "refusal"``).

    A decline is a normal outcome for a security audit, not a crash and not an
    empty result: the reviewer reports it as an unavailable scope so coverage
    stays honest.
    """

    def __init__(self, category: str | None) -> None:
        super().__init__(f"model declined the request (category={category or 'unknown'})")
        self.category = category


class SemanticUnavailable(Exception):
    """The exchange failed. ``reason_code`` is a §13.5 semantic reason code."""

    def __init__(self, reason_code: str, detail: str = "") -> None:
        super().__init__(detail or reason_code)
        self.reason_code = reason_code
        self.detail = detail


class MessageTransport(Protocol):
    """The slice of ``client.messages`` this module uses.

    Only ``create`` is required. A transport may also expose ``stream``; the
    real SDK does, and :meth:`SemanticModelClient._dispatch` uses it above
    :data:`STREAMING_MAX_TOKENS`. A test double with ``create`` alone stays
    valid — it simply never streams.
    """

    def create(self, **payload: object) -> object: ...


def response_field(source: object, name: str, default: object = None) -> object:
    """Read one field from a mapping or an object, whichever arrived.

    The SDK returns pydantic models; the Gateway speaks plain JSON and test
    doubles use dicts. Both shapes are read the same way so response handling
    has one code path rather than two divergent ones.
    """

    if isinstance(source, Mapping):
        return source.get(name, default)
    return getattr(source, name, default)


def stop_reason_of(response: object) -> str | None:
    """Return the response's ``stop_reason``, or ``None`` when absent."""

    value = response_field(response, "stop_reason")
    return value if isinstance(value, str) else None


def content_blocks(response: object) -> list[object]:
    """Return the response content blocks; empty when there are none.

    Callers must read :func:`stop_reason_of` first. This helper never raises on
    a missing or malformed ``content``, so a decline or a truncated turn cannot
    become an IndexError.
    """

    content = response_field(response, "content")
    return list(content) if isinstance(content, list) else []


def refusal_category(response: object) -> str | None:
    """Extract ``stop_details.category`` from a refusal response.

    ``stop_details`` may be absent, ``None``, a dict (raw JSON) or an object
    (SDK model), and it is populated only on a refusal. All four cases yield
    ``None`` rather than an error.
    """

    details = response_field(response, "stop_details")
    if details is None:
        return None
    category = response_field(details, "category")
    return category if isinstance(category, str) and category else None


def _anthropic_error_labels() -> tuple[tuple[type[BaseException], str], ...]:
    """Anthropic error classes, ordered most specific first.

    Imported here rather than at module scope so this module stays importable
    without the SDK. In the Python SDK ``APIConnectionError`` is a *sibling* of
    ``APIStatusError``, not a subclass, so it sits after it without being
    shadowed. Returns an empty tuple when the SDK is absent.
    """

    try:
        import anthropic
    except ImportError:
        return ()
    return (
        (anthropic.BadRequestError, "bad_request"),
        (anthropic.AuthenticationError, "authentication"),
        (anthropic.PermissionDeniedError, "permission_denied"),
        (anthropic.NotFoundError, "not_found"),
        (anthropic.RateLimitError, "rate_limit"),
        (anthropic.APIStatusError, "api_status"),
        (anthropic.APIConnectionError, "api_connection"),
        # The SDK raises ValueError for a non-streaming request it estimates
        # will exceed its timeout ceiling: a request-shape failure, not a bug.
        (ValueError, "request_too_long"),
    )


def _error_classes() -> tuple[type[BaseException], ...]:
    """The class tuple for the transport ``except`` clause.

    Without the SDK there is no class hierarchy to name, so any transport
    failure — including one raised by an injected double — is wrapped. That
    keeps a Gateway or network failure from escaping as an unclassified
    exception in an environment where ``anthropic`` is not installed.
    """

    classes = tuple(cls for cls, _ in _anthropic_error_labels())
    return classes or (Exception,)


def _error_label(exc: BaseException) -> str:
    for cls, label in _anthropic_error_labels():
        if isinstance(exc, cls):
            return label
    return type(exc).__name__


def _gateway_error_code(exc: BaseException) -> str | None:
    """Recover the Gateway's ``error_code`` from a rejected request.

    The Gateway answers with ``{"error_code": ..., "message": ..., ...}``, which
    the SDK exposes as ``.body``. Only codes this module actually maps are
    matched in the message text, so an upstream Anthropic error type is never
    mistaken for a Gateway policy code.
    """

    body = response_field(exc, "body")
    for candidate in (body, response_field(body, "error")):
        code = response_field(candidate, "error_code")
        if isinstance(code, str) and code:
            return code
    text = _message_of(exc)
    for code in _GATEWAY_REASON_CODES:
        if code in text:
            return code
    return None


def _message_of(exc: BaseException) -> str:
    message = getattr(exc, "message", None)
    if isinstance(message, str) and message:
        return message
    return str(exc)


def _classify(exc: BaseException) -> tuple[str, str | None]:
    gateway_code = _gateway_error_code(exc)
    reason_code = _GATEWAY_REASON_CODES.get(gateway_code or "", REASON_MODEL_UNAVAILABLE)
    return reason_code, gateway_code


def _redact(message: str, secret: str) -> str:
    """Remove the grant from an error message without mangling it.

    Substring replacement is only meaningful for a value long enough to be a
    credential. A minted grant is ``base64url(payload).base64url(mac)`` — the
    MAC alone is 43 characters — so a real token is always well past the
    threshold. A short value, by contrast, occurs inside ordinary words: blindly
    replacing it rewrites the message into nonsense ("thinking.budget_tokens"
    became "thinkin[redacted].bud[redacted]et_tokens" for a one-character
    token), destroying the diagnostic without protecting anything that was a
    secret in the first place. Below the threshold the primary defence — never
    formatting the request payload or headers into this string — is what holds.
    """

    if len(secret) < _MIN_REDACTABLE_SECRET:
        return message
    return message.replace(secret, _REDACTED)


def _detail(exc: BaseException, *, gateway_code: str | None, secret: str) -> str:
    """Build a bounded failure detail that cannot carry the grant.

    The request payload and the request headers are never formatted into this
    string — that is the primary defence. Redacting ``secret`` is the second,
    for the case where an SDK error text quotes something it should not.
    """

    parts = [_error_label(exc)]
    status = response_field(exc, "status_code")
    if isinstance(status, int) and not isinstance(status, bool):
        parts.append(f"status={status}")
    if gateway_code:
        parts.append(f"code={gateway_code}")
    message = _redact(_message_of(exc), secret)
    if message:
        parts.append(message)
    detail = " ".join(part for part in parts if part)
    return detail[:_DETAIL_MAX_LENGTH]


class SemanticModelClient:
    """One Messages API conversation surface for the Semantic Reviewer.

    Holds the request shape in one place so a wrong form cannot be reinvented
    per call site: adaptive thinking (``budget_tokens`` is a 400 on this model
    family), effort nested inside ``output_config``, and the streaming switch
    keyed off ``max_tokens``.
    """

    def __init__(
        self,
        *,
        base_url: str,
        grant_token: str,
        model: str = DEFAULT_MODEL,
        effort: str = "high",
        max_tokens: int = 16000,
        timeout_seconds: float = 600.0,
        transport: MessageTransport | None = None,
    ) -> None:
        normalized_base_url = base_url.strip().rstrip("/")
        if not normalized_base_url:
            raise ValueError("base_url must name the LLM Gateway origin")
        if not grant_token.strip():
            # The value itself never appears in an error message.
            raise ValueError("grant_token must not be empty")
        if not model or len(model) > 255:
            raise ValueError("model must be a non-empty name of at most 255 characters")
        if effort not in EFFORT_LEVELS:
            raise ValueError(f"effort must be one of {', '.join(EFFORT_LEVELS)}")
        if max_tokens < 1:
            raise ValueError("max_tokens must be positive")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self.base_url = normalized_base_url
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.timeout_seconds = timeout_seconds
        self._grant_token = grant_token.strip()
        # Built only when the caller supplies no transport, so importing or
        # exercising this class never requires the SDK.
        self._transport = transport if transport is not None else self._build_transport()

    def __repr__(self) -> str:
        # Explicit, so no accidental repr of this object can print the grant.
        return f"SemanticModelClient(model={self.model!r}, effort={self.effort!r})"

    def create(
        self,
        *,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        output_schema: dict | None = None,
        tool_choice: dict | None = None,
    ) -> object:
        """Send one request and return the response, or raise.

        Raises :class:`SemanticRefusal` when the model declined and
        :class:`SemanticUnavailable` for every transport or policy failure.
        ``pause_turn`` and ``max_tokens`` are *returned*, not raised: the first
        needs the turn restarted (the Python SDK does not auto-resume), the
        second is a truncated answer rather than a decline, and both decisions
        belong to the review driver.

        When ``output_schema`` is given and ``tool_choice`` is not, tools are
        disabled for that request: a structured answer is the end of the turn,
        so leaving tool use available invites another tool call instead of the
        final object.
        """

        payload = self._payload(
            system=system,
            messages=messages,
            tools=tools,
            output_schema=output_schema,
            tool_choice=tool_choice,
        )
        try:
            response = self._dispatch(payload)
        except _error_classes() as exc:
            # ``from None``: the SDK exception, its traceback and its attached
            # request object are dropped rather than re-raised, so nothing
            # carrying the grant can reach a log or a crash report.
            raise self._unavailable(exc) from None
        # stop_reason first, before any caller can index content.
        if stop_reason_of(response) == STOP_REFUSAL:
            raise SemanticRefusal(refusal_category(response))
        return response

    def _payload(
        self,
        *,
        system: str,
        messages: list[dict],
        tools: list[dict] | None,
        output_schema: dict | None,
        tool_choice: dict | None,
    ) -> dict[str, object]:
        output_config: dict[str, object] = {"effort": self.effort}
        if output_schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": output_schema}
            if tool_choice is None:
                tool_choice = {"type": "none"}
        payload: dict[str, object] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": system,
            "messages": messages,
            # Adaptive only: ``budget_tokens`` is rejected on this model family.
            "thinking": {"type": "adaptive"},
            "output_config": output_config,
        }
        if tools is not None:
            # Tool definitions arrive from the broker already carrying
            # ``strict: True`` as a top-level field on each definition.
            payload["tools"] = tools
        if tool_choice is not None:
            payload["tool_choice"] = tool_choice
        return payload

    def _dispatch(self, payload: dict[str, object]) -> object:
        """Send the payload, streaming when the output budget is large."""

        if self.max_tokens < STREAMING_MAX_TOKENS:
            return self._transport.create(**payload)
        stream = getattr(self._transport, "stream", None)
        if stream is None:
            return self._transport.create(**payload)
        with stream(**payload) as active:
            return active.get_final_message()

    def _unavailable(self, exc: BaseException) -> SemanticUnavailable:
        reason_code, gateway_code = _classify(exc)
        LOG.warning(
            "semantic model request failed",
            extra={
                "reason_code": reason_code,
                "gateway_error_code": gateway_code,
                "error_class": type(exc).__name__,
                "model": self.model,
            },
        )
        return SemanticUnavailable(
            reason_code,
            _detail(exc, gateway_code=gateway_code, secret=self._grant_token),
        )

    def _build_transport(self) -> MessageTransport:
        """Construct the real SDK transport pointed at the LLM Gateway.

        ``api_key`` is the short-lived grant, never the model API key: the
        Gateway substitutes the real credential on the egress leg. ``timeout``
        is in seconds.
        """

        import anthropic

        client = anthropic.Anthropic(
            base_url=self.base_url,
            api_key=self._grant_token,
            timeout=self.timeout_seconds,
        )
        return client.messages
