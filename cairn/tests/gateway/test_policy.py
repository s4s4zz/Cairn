from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from cairn.gateway import policy as policy_module
from cairn.gateway.config import GatewaySettings
from cairn.gateway.errors import GatewayError
from cairn.gateway.policy import GatewayPolicy
from cairn.gateway.tokens import ModelGrant, mint_grant

GRANT_KEY = b"policy-grant-key-0123456789abcdef"


class FakeClock:
    """Stand-in for the ``time`` module inside ``cairn.gateway.policy``.

    The breaker's reset window is driven forward explicitly; nothing in this
    suite ever sleeps.
    """

    def __init__(self) -> None:
        self.now = 1_000.0

    def monotonic(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def settings(tmp_path: Path) -> GatewaySettings:
    return GatewaySettings(
        api_key_file=tmp_path / "api.key",
        grant_key_file=tmp_path / "grant.key",
        model_allowlist=("claude-opus-5", "claude-opus-4-8"),
        max_request_bytes=4096,
        max_output_tokens=8_000,
        circuit_failure_threshold=3,
        circuit_reset_seconds=60.0,
    )


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> FakeClock:
    fake = FakeClock()
    monkeypatch.setattr(policy_module, "time", fake)
    return fake


def token_for(**overrides: Any) -> str:
    defaults: dict[str, Any] = {
        "audit_run_id": "run-1",
        "task_id": "task-1",
        "worker": "semantic-reviewer-1",
        "model": "claude-opus-5",
        "expires_at": datetime.now(UTC) + timedelta(minutes=30),
        "max_requests": 5,
        "max_output_tokens": 4_000,
    }
    defaults.update(overrides)
    return mint_grant(ModelGrant(**defaults), GRANT_KEY)


def body(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": "claude-opus-5",
        "messages": [{"role": "user", "content": "review the module"}],
    }
    payload.update(overrides)
    return payload


def authorize(policy: GatewayPolicy, token: str, payload: dict[str, Any]) -> ModelGrant:
    return policy.authorize(token, payload, len(str(payload)))


def exchange(
    policy: GatewayPolicy,
    token: str,
    payload: dict[str, Any],
    output_tokens: int,
) -> None:
    """Drive one complete request the way `app.py` does.

    `authorize` reserves output budget so concurrent requests cannot each take
    the whole grant ceiling; the reservation is settled by `record_success` or
    `release`. A test that authorizes without settling is modelling a request
    that is still in flight, not a finished one.
    """

    authorize(policy, token, payload)
    policy.record_success(token, output_tokens, reserved=int(payload["max_tokens"]))


def test_valid_request_authorizes_and_returns_the_signed_grant(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(worker="semantic-reviewer-9")

    grant = authorize(policy, token, body())

    assert grant.worker == "semantic-reviewer-9"
    assert grant.model == "claude-opus-5"


def test_model_outside_the_allowlist_is_refused(settings: GatewaySettings) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(model="claude-shadow-9")

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body(model="claude-shadow-9"))

    assert excinfo.value.error_code == "LLM_MODEL_NOT_ALLOWED"
    assert excinfo.value.http_status == 403


def test_allowlisted_model_that_the_grant_does_not_bind_is_refused(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(model="claude-opus-4-8")

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body(model="claude-opus-5"))

    assert excinfo.value.error_code == "LLM_MODEL_NOT_ALLOWED"


def test_grant_bound_model_still_has_to_be_allowlisted(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(
        settings.model_copy(update={"model_allowlist": ("claude-opus-4-8",)}),
        GRANT_KEY,
    )
    token = token_for(model="claude-opus-5")

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body(model="claude-opus-5"))

    assert excinfo.value.error_code == "LLM_MODEL_NOT_ALLOWED"


def test_oversized_body_is_refused_before_the_grant_is_verified(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    with pytest.raises(GatewayError) as excinfo:
        policy.authorize("not-a-grant-at-all", body(), settings.max_request_bytes + 1)

    # A garbage token would be LLM_GRANT_INVALID; getting the size code proves
    # the cheap check ran first, so an oversized unauthenticated body costs
    # nothing more than a length comparison.
    assert excinfo.value.error_code == "LLM_REQUEST_TOO_LARGE"
    assert excinfo.value.http_status == 413


def test_body_exactly_at_the_size_limit_is_accepted(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    grant = policy.authorize(token_for(), body(), settings.max_request_bytes)

    assert grant.model == "claude-opus-5"


def test_invalid_grant_is_refused_before_any_budget_is_consumed(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    foreign = mint_grant(
        ModelGrant(
            audit_run_id="run-1",
            task_id="task-1",
            worker="w",
            model="claude-opus-5",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            max_requests=5,
            max_output_tokens=4_000,
        ),
        b"a-completely-different-key-012345",
    )

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, foreign, body())

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_expired_grant_is_refused(settings: GatewaySettings) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body())

    assert excinfo.value.error_code == "LLM_GRANT_EXPIRED"


@pytest.mark.parametrize(
    ("payload", "label"),
    [
        ({"messages": [{"role": "user", "content": "x"}]}, "no model"),
        ({"model": "claude-opus-5"}, "no messages"),
        ({"model": "", "messages": [{"role": "user"}]}, "empty model"),
        ({"model": 5, "messages": [{"role": "user"}]}, "model is not a string"),
        ({"model": "claude-opus-5", "messages": []}, "empty messages"),
        ({"model": "claude-opus-5", "messages": "hello"}, "messages is not a list"),
    ],
)
def test_structurally_invalid_bodies_are_refused(
    settings: GatewaySettings,
    payload: dict[str, Any],
    label: str,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token_for(), payload)

    assert excinfo.value.error_code == "LLM_REQUEST_INVALID", label
    assert excinfo.value.http_status == 422


@pytest.mark.parametrize("value", [0, -1, "4000", 12.5, True])
def test_non_positive_or_non_integer_max_tokens_is_refused(
    settings: GatewaySettings,
    value: object,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token_for(), body(max_tokens=value))

    assert excinfo.value.error_code == "LLM_REQUEST_INVALID"


def test_request_budget_is_exhausted_once_max_requests_is_reached(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(max_requests=2)

    exchange(policy, token, body(), 10)
    exchange(policy, token, body(), 10)

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body())

    assert excinfo.value.error_code == "LLM_BUDGET_EXHAUSTED"
    assert excinfo.value.http_status == 429


def test_concurrent_requests_cannot_each_take_the_whole_output_ceiling(
    settings: GatewaySettings,
) -> None:
    """The signed output-token ceiling is enforced, not advisory.

    Crediting usage only on completion would let requests that are still in
    flight each measure against the same stale remainder.
    """

    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(max_requests=10, max_output_tokens=1_000)

    first = body()
    authorize(policy, token, first)

    # Still in flight, so its reservation is not available to anyone else.
    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body())

    assert excinfo.value.error_code == "LLM_BUDGET_EXHAUSTED"
    assert first["max_tokens"] == 1_000

    # Settling it below the reservation returns the unspent remainder.
    policy.record_success(token, 100, reserved=int(first["max_tokens"]))
    second = body()
    authorize(policy, token, second)

    assert second["max_tokens"] == 900


def test_output_token_budget_is_exhausted_on_the_call_after_it_is_reached(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(max_requests=10, max_output_tokens=1_000)

    exchange(policy, token, body(), 600)
    exchange(policy, token, body(), 400)

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token, body())

    assert excinfo.value.error_code == "LLM_BUDGET_EXHAUSTED"


def test_remaining_output_budget_clamps_the_forwarded_max_tokens(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for(max_requests=10, max_output_tokens=1_000)
    exchange(policy, token, body(), 900)

    payload = body(max_tokens=1_000)
    authorize(policy, token, payload)

    assert payload["max_tokens"] == 100


def test_max_tokens_above_the_ceiling_is_clamped_rather_than_rejected(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    payload = body(max_tokens=1_000_000)

    authorize(policy, token_for(max_output_tokens=4_000), payload)

    assert payload["max_tokens"] == 4_000


def test_absent_max_tokens_is_filled_in_with_the_effective_ceiling(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    payload = body()

    authorize(policy, token_for(max_output_tokens=100_000), payload)

    # The grant asks for more than the service ceiling, so the service wins.
    assert payload["max_tokens"] == settings.max_output_tokens


def test_max_tokens_below_the_ceiling_is_left_untouched(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    payload = body(max_tokens=256)

    authorize(policy, token_for(max_output_tokens=4_000), payload)

    assert payload["max_tokens"] == 256


def test_two_distinct_grants_have_independent_budgets(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    first = token_for(task_id="task-a", max_requests=1, max_output_tokens=1_000)
    second = token_for(task_id="task-b", max_requests=1, max_output_tokens=1_000)

    authorize(policy, first, body())
    policy.record_success(first, 1_000)
    with pytest.raises(GatewayError):
        authorize(policy, first, body())

    grant = authorize(policy, second, body())

    assert grant.task_id == "task-b"


def test_circuit_opens_after_consecutive_upstream_failures(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    for _ in range(settings.circuit_failure_threshold):
        policy.record_failure()

    with pytest.raises(GatewayError) as excinfo:
        policy.check_circuit()

    assert excinfo.value.error_code == "LLM_CIRCUIT_OPEN"
    assert excinfo.value.http_status == 503


def test_failures_below_the_threshold_leave_the_circuit_closed(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    for _ in range(settings.circuit_failure_threshold - 1):
        policy.record_failure()

    policy.check_circuit()
    authorize(policy, token_for(), body())


def test_a_success_resets_the_consecutive_failure_count(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    token = token_for()

    for _ in range(settings.circuit_failure_threshold - 1):
        policy.record_failure()
    policy.record_success(token, 10)
    for _ in range(settings.circuit_failure_threshold - 1):
        policy.record_failure()

    policy.check_circuit()


def test_open_circuit_refuses_authorization_outright(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    for _ in range(settings.circuit_failure_threshold):
        policy.record_failure()

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token_for(), body())

    assert excinfo.value.error_code == "LLM_CIRCUIT_OPEN"


def test_circuit_stays_open_until_the_reset_window_elapses(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    for _ in range(settings.circuit_failure_threshold):
        policy.record_failure()

    clock.advance(settings.circuit_reset_seconds - 1)

    with pytest.raises(GatewayError) as excinfo:
        policy.check_circuit()

    assert excinfo.value.error_code == "LLM_CIRCUIT_OPEN"


def test_circuit_reopens_for_traffic_after_the_reset_window(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    for _ in range(settings.circuit_failure_threshold):
        policy.record_failure()

    clock.advance(settings.circuit_reset_seconds)

    policy.check_circuit()
    grant = authorize(policy, token_for(), body())

    assert grant.model == "claude-opus-5"


def test_reopened_circuit_starts_from_a_clean_failure_count(
    settings: GatewaySettings,
    clock: FakeClock,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    for _ in range(settings.circuit_failure_threshold):
        policy.record_failure()
    clock.advance(settings.circuit_reset_seconds)
    policy.check_circuit()

    for _ in range(settings.circuit_failure_threshold - 1):
        policy.record_failure()

    policy.check_circuit()


# --- the reviewer must not be able to give itself a network -----------------
#
# `cairn-analysis-net` is `internal: true`, but that only constrains the
# sandbox. Anthropic's server-side tools run the outbound request from
# Anthropic's infrastructure, so a request body that declares one reaches the
# open internet without a packet leaving the internal bridge (§13.5 #5).


@pytest.mark.parametrize(
    "tool_type",
    [
        "web_search_20260209",
        "web_fetch_20260209",
        "code_execution_20250825",
        "computer_20250124",
        "bash_20250124",
    ],
)
def test_server_side_tools_are_refused(
    settings: GatewaySettings,
    tool_type: str,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    with pytest.raises(GatewayError) as excinfo:
        authorize(
            policy,
            token_for(),
            body(tools=[{"type": tool_type, "name": "t"}]),
        )

    assert excinfo.value.error_code == "LLM_TOOL_NOT_ALLOWED"
    assert excinfo.value.http_status == 403


@pytest.mark.parametrize(
    "field, value",
    [
        ("mcp_servers", [{"type": "url", "url": "https://attacker.example/mcp", "name": "e"}]),
        ("container", {"id": "container-1"}),
    ],
)
def test_hosted_execution_surfaces_are_refused(
    settings: GatewaySettings,
    field: str,
    value: object,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, token_for(), body(**{field: value}))

    assert excinfo.value.error_code == "LLM_TOOL_NOT_ALLOWED"


@pytest.mark.parametrize(
    "tools",
    [
        [{"name": "read_file", "input_schema": {"type": "object"}}],
        [{"type": "custom", "name": "read_file", "input_schema": {"type": "object"}}],
    ],
)
def test_custom_tools_still_pass(settings: GatewaySettings, tools: list) -> None:
    """The Tool Broker's own tools must keep working — this is an allowlist,
    not a blanket ban on tool use."""

    policy = GatewayPolicy(settings, GRANT_KEY)

    assert authorize(policy, token_for(), body(tools=tools)).model == "claude-opus-5"


def test_a_grant_whose_lifetime_exceeds_the_maximum_is_refused(
    settings: GatewaySettings,
) -> None:
    """§9.5 puts 'short-lived' at the verifier, so a misconfigured minter
    cannot issue what amounts to a permanent bearer credential."""

    policy = GatewayPolicy(settings, GRANT_KEY)
    forever = token_for(
        expires_at=datetime.now(UTC)
        + timedelta(seconds=settings.max_grant_lifetime_seconds * 2)
    )

    with pytest.raises(GatewayError) as excinfo:
        authorize(policy, forever, body())

    assert excinfo.value.error_code == "LLM_GRANT_INVALID"


def test_a_grant_inside_the_maximum_lifetime_is_honoured(
    settings: GatewaySettings,
) -> None:
    policy = GatewayPolicy(settings, GRANT_KEY)
    normal = token_for(
        expires_at=datetime.now(UTC)
        + timedelta(seconds=settings.max_grant_lifetime_seconds / 2)
    )

    assert authorize(policy, normal, body()).worker
