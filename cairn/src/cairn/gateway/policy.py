from __future__ import annotations

from dataclasses import dataclass, field
import threading
import time

from cairn.gateway.config import GatewaySettings
from cairn.gateway.errors import (
    budget_exhausted,
    circuit_open,
    model_not_allowed,
    request_invalid,
    request_too_large,
    tool_not_allowed,
)
from cairn.gateway.tokens import ModelGrant, grant_counter_key, verify_grant


@dataclass
class _GrantUsage:
    requests: int = 0
    output_tokens: int = 0
    in_flight: int = 0


@dataclass
class _CircuitBreaker:
    """Consecutive-failure breaker guarding the upstream model API."""

    failure_threshold: int
    reset_seconds: float
    failures: int = 0
    opened_at: float | None = field(default=None)

    def check(self) -> None:
        if self.opened_at is None:
            return
        if time.monotonic() - self.opened_at >= self.reset_seconds:
            self.opened_at = None
            self.failures = 0
            return
        raise circuit_open()

    def record_success(self) -> None:
        self.failures = 0
        self.opened_at = None

    def record_failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()


class GatewayPolicy:
    """Grant verification, model allowlisting, budget accounting and breaker.

    Counters live in process and reset on restart. That is acceptable because
    the signed grant already bounds the worst case per grant; durable
    accounting belongs to the control plane.
    """

    def __init__(self, settings: GatewaySettings, grant_key: bytes) -> None:
        self.settings = settings
        self._grant_key = grant_key
        self._lock = threading.Lock()
        self._usage: dict[str, _GrantUsage] = {}
        self._breaker = _CircuitBreaker(
            failure_threshold=settings.circuit_failure_threshold,
            reset_seconds=settings.circuit_reset_seconds,
        )

    def check_circuit(self) -> None:
        with self._lock:
            self._breaker.check()

    def authorize(
        self,
        token: str,
        body: dict[str, object],
        body_bytes: int,
    ) -> ModelGrant:
        """Enforce every request-time policy, in the order that matters.

        Cheap and non-credential checks run first so a hostile caller cannot
        use expensive work as an oracle: breaker, then size, then grant
        signature, then model, then budget. ``body`` is mutated in place only to
        clamp ``max_tokens`` down to the effective ceiling.
        """
        self.check_circuit()
        if body_bytes > self.settings.max_request_bytes:
            raise request_too_large()
        if not isinstance(body, dict):
            raise request_invalid()
        grant = verify_grant(
            token,
            self._grant_key,
            max_lifetime_seconds=self.settings.max_grant_lifetime_seconds,
        )
        requested_model = body.get("model")
        if not isinstance(requested_model, str) or not requested_model:
            raise request_invalid("Request body must name a model")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            raise request_invalid("Request body must carry a non-empty messages list")
        if (
            requested_model not in self.settings.model_allowlist
            or requested_model != grant.model
        ):
            raise model_not_allowed()
        _reject_egress_capabilities(body)

        requested_max_tokens = body.get("max_tokens")
        if requested_max_tokens is not None and (
            isinstance(requested_max_tokens, bool)
            or not isinstance(requested_max_tokens, int)
        ):
            raise request_invalid("max_tokens must be an integer")
        if isinstance(requested_max_tokens, int) and requested_max_tokens < 1:
            raise request_invalid("max_tokens must be positive")

        ceiling = min(grant.max_output_tokens, self.settings.max_output_tokens)
        counter_key = grant_counter_key(token)
        with self._lock:
            usage = self._usage.setdefault(counter_key, _GrantUsage())
            if usage.requests >= grant.max_requests:
                raise budget_exhausted()
            if usage.output_tokens >= grant.max_output_tokens:
                raise budget_exhausted()
            # Reserve against spent *and* in-flight tokens before releasing the
            # lock. Measuring only what `record_success` has credited would let
            # concurrent requests each see the same stale remainder and each
            # take the full grant ceiling.
            remaining = grant.max_output_tokens - usage.output_tokens - usage.in_flight
            if remaining <= 0:
                raise budget_exhausted()
            effective_ceiling = min(ceiling, remaining)
            if requested_max_tokens is not None:
                effective_ceiling = min(effective_ceiling, requested_max_tokens)
            usage.requests += 1
            usage.in_flight += effective_ceiling

        if requested_max_tokens is None or requested_max_tokens > effective_ceiling:
            body["max_tokens"] = effective_ceiling
        return grant

    def record_success(
        self, token: str, output_tokens: int, *, reserved: int = 0
    ) -> None:
        counter_key = grant_counter_key(token)
        with self._lock:
            usage = self._usage.setdefault(counter_key, _GrantUsage())
            usage.in_flight = max(0, usage.in_flight - max(0, reserved))
            usage.output_tokens += max(0, output_tokens)
            self._breaker.record_success()

    def release(self, token: str, reserved: int) -> None:
        """Return an unspent reservation after a failed upstream call."""

        counter_key = grant_counter_key(token)
        with self._lock:
            usage = self._usage.setdefault(counter_key, _GrantUsage())
            usage.in_flight = max(0, usage.in_flight - max(0, reserved))

    def record_failure(self) -> None:
        with self._lock:
            self._breaker.record_failure()


def _reject_egress_capabilities(body: dict) -> None:
    """Refuse request features that would give the reviewer its own network.

    ``cairn-analysis-net`` is ``internal: true``, but that only constrains the
    sandbox. Anthropic's server-side tools run the outbound request from
    Anthropic's infrastructure, so a worker that declares ``web_search`` or
    ``web_fetch`` — or points the model at an MCP server — reaches the open
    internet without a single packet leaving the internal bridge. §13.5 asks
    that the agent cannot reach the open internet, so only custom tools, whose
    results the Tool Broker produces, are allowed through.
    """

    for field in ("mcp_servers", "container"):
        if body.get(field) not in (None, [], {}):
            raise tool_not_allowed(f"{field} is not permitted through the Gateway")
    tools = body.get("tools")
    if tools is None:
        return
    if not isinstance(tools, list):
        raise request_invalid("tools must be an array")
    for tool in tools:
        if not isinstance(tool, dict):
            raise request_invalid("tool definition must be an object")
        declared = tool.get("type")
        if declared is not None and declared != "custom":
            raise tool_not_allowed(
                "only custom tools may be declared through the Gateway"
            )
