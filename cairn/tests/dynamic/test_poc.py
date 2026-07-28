"""Executing an authored PoC, and deciding what it means (§7.7, §13.5).

The properties here are the ones a fake client cannot fake for itself: the
platform builds both requests so they differ at exactly one place, the nonce is
the platform's, and — the one that matters most — a criterion that fires on the
control request as well as the attack is not evidence.
"""

from __future__ import annotations

import json

import pytest

from cairn.dynamic.poc import (
    REASON_NOT_DISCRIMINATING,
    REASON_NO_ECHO,
    PocExecutor,
)
from cairn.dynamic.probes import _Response
from cairn.poc.contracts import CALLBACK_TOKEN, PocPlan


def plan(**overrides: object) -> PocPlan:
    payload: dict[str, object] = {
        "finding_id": "f-1",
        "category": "template-injection",
        "request": {
            "method": "POST",
            "path": "/render",
            "headers": {"content-type": "application/json"},
            "body": '{"tpl":"x"}',
        },
        "injection": {
            "location": "body_field",
            "name": "tpl",
            "benign": "hello",
            "payload": "${7*7}",
        },
        "criterion": {
            "kind": "contains_text",
            "match_text": "49",
            "status_code": None,
            "elapsed_ms": None,
        },
        "rationale": "SpEL evaluation of the tpl field.",
    }
    for key, value in overrides.items():
        if key in {"request", "injection", "criterion"} and isinstance(value, dict):
            payload[key] = {**payload[key], **value}  # type: ignore[dict-item]
        else:
            payload[key] = value
    return PocPlan.model_validate(payload)


class Caller:
    """Scripted HTTP, plus a real record of what was sent."""

    def __init__(self, fn) -> None:  # noqa: ANN001
        self._fn = fn
        self.sent: list[tuple[str, str, str | None]] = []

    def __call__(self, method: str, url: str, body: str | None, timeout: float):
        self.sent.append((method, url, body))
        return self._fn(method, url, body)


def bland(method: str, url: str, body: str | None) -> _Response:
    return _Response(200, "baseline", 8, 10)


def execute(plan_: PocPlan, fn, *, echo: str | None = None):
    caller = Caller(fn)
    executor = PocExecutor("http://app:8080", echo_endpoint=echo, caller=caller)
    return executor.run(plan_), caller


# --- the platform builds both requests ---------------------------------------


def test_the_two_requests_differ_only_at_the_injection_point() -> None:
    _outcome, caller = execute(plan(), bland)

    control_body = json.loads(caller.sent[0][2])
    attack_body = json.loads(caller.sent[1][2])
    assert caller.sent[0][1] == caller.sent[1][1]  # same URL
    assert set(control_body) == set(attack_body)  # same fields
    differing = [key for key in control_body if control_body[key] != attack_body[key]]
    assert differing == ["tpl"]
    assert control_body["tpl"] == "hello"
    assert attack_body["tpl"] == "${7*7}"


@pytest.mark.parametrize(
    ("location", "check"),
    [
        ("query", lambda url: "tpl=hello" in url),
        ("path", lambda url: url.endswith("/render/hello")),
    ],
)
def test_the_injection_lands_where_the_plan_says(location: str, check) -> None:
    template = {
        "query": {"path": "/render"},
        "path": {"path": "/render/{tpl}"},
    }[location]
    _outcome, caller = execute(
        plan(request=template, injection={"location": location, "name": "tpl"}),
        bland,
    )

    assert check(caller.sent[0][1])


# --- the discrimination rule --------------------------------------------------


def test_a_criterion_matching_the_attack_alone_confirms() -> None:
    outcome, _ = execute(
        plan(),
        lambda m, u, b: _Response(200, "49" if "7*7" in (b or "") else "hi", 2, 10),
    )

    assert outcome.verdict == "confirmed"
    assert outcome.payload is not None


def test_a_criterion_matching_both_requests_is_not_evidence() -> None:
    """The shape that would let a model confirm anything: 'the body contains
    <html>' fires on the control too, so it distinguishes nothing."""

    outcome, _ = execute(plan(), lambda m, u, b: _Response(200, "49 everywhere", 2, 10))

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_NOT_DISCRIMINATING


def test_a_criterion_matching_neither_request_rejects() -> None:
    outcome, _ = execute(plan(), bland)

    assert outcome.verdict == "rejected"
    assert outcome.reason_code is None


@pytest.mark.parametrize(
    ("kind", "extra", "fn"),
    [
        (
            "status_code_is",
            {"status_code": 500},
            lambda m, u, b: _Response(500 if "7*7" in (b or "") else 200, "x", 1, 5),
        ),
        (
            "status_code_differs",
            {},
            lambda m, u, b: _Response(500 if "7*7" in (b or "") else 200, "x", 1, 5),
        ),
        (
            "elapsed_exceeds_ms",
            {"elapsed_ms": 1000},
            lambda m, u, b: _Response(200, "x", 1, 1500 if "7*7" in (b or "") else 20),
        ),
    ],
)
def test_each_criterion_confirms_on_the_expected_difference(
    kind: str,
    extra: dict,
    fn,
) -> None:
    outcome, _ = execute(
        plan(criterion={"kind": kind, "match_text": None, **extra}),
        fn,
    )

    assert outcome.verdict == "confirmed"


# --- the nonce is the platform's ---------------------------------------------


def test_an_out_of_band_hit_confirms_and_the_nonce_is_not_the_models() -> None:
    observed: dict[str, str] = {}

    def echo_caller(method: str, url: str, body: str | None):
        if "__cairn/observed" in url:
            return _Response(200, json.dumps({"nonces": list(observed.values())}), 2, 5)
        for source in (url, body or ""):
            if "cairn-" in source:
                marker = source.split("cairn-", 1)[1][:32]
                observed["seen"] = f"cairn-{marker}"
        return _Response(200, "ok", 2, 10)

    poc = plan(
        injection={"payload": f"<!ENTITY x SYSTEM '{CALLBACK_TOKEN}'>"},
        criterion={"kind": "echo_nonce_observed", "match_text": None},
    )
    outcome, caller = execute(poc, echo_caller, echo="echo:8081")

    assert outcome.verdict == "confirmed"
    assert outcome.echo_observed is True
    # The nonce was generated by the platform and never appeared in the plan.
    assert outcome.nonce is not None
    assert outcome.nonce not in json.dumps(poc.model_dump(mode="json"))


def test_an_out_of_band_criterion_with_no_echo_service_is_inconclusive() -> None:
    poc = plan(
        injection={"payload": CALLBACK_TOKEN},
        criterion={"kind": "echo_nonce_observed", "match_text": None},
    )

    outcome, _ = execute(poc, bland, echo=None)

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_NO_ECHO


# --- nothing that failed rejects ---------------------------------------------


def test_an_injection_point_absent_from_the_request_is_inconclusive() -> None:
    outcome, _ = execute(
        plan(request={"path": "/render"}, injection={"location": "path", "name": "missing"}),
        bland,
    )

    assert outcome.verdict == "inconclusive"


def test_a_non_json_body_for_a_field_injection_is_inconclusive() -> None:
    outcome, _ = execute(plan(request={"body": "not json at all"}), bland)

    assert outcome.verdict == "inconclusive"


def test_a_transport_failure_on_the_attack_is_inconclusive() -> None:
    outcome, _ = execute(
        plan(),
        lambda m, u, b: (
            _Response(None, "", 0, 20, "connection reset")
            if "7*7" in (b or "")
            else _Response(200, "ok", 2, 10)
        ),
    )

    assert outcome.verdict == "inconclusive"


@pytest.mark.parametrize(
    ("label", "poc", "fn"),
    [
        ("unresolved injection", "path-missing", bland),
        ("non-json body", "bad-body", bland),
    ],
)
def test_no_failure_mode_rejects(label: str, poc: str, fn) -> None:
    plans = {
        "path-missing": plan(
            request={"path": "/x"},
            injection={"location": "path", "name": "absent"},
        ),
        "bad-body": plan(request={"body": "xxx"}),
    }
    outcome, _ = execute(plans[poc], fn)

    assert outcome.verdict != "rejected", label
