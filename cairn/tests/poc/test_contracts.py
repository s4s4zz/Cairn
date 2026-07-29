"""What a PoC plan may and may not say (§7.7, §13.5).

The plan contract is where a model's ability to confirm its own finding is
taken away. These tests are almost entirely about refusals: every shape that
would let a plan reach off the target, forge a trust signal, or assert a result
the platform did not observe is rejected here, before anything runs.
"""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from cairn.poc.contracts import (
    ALLOWED_HEADERS,
    CALLBACK_TOKEN,
    PocPlan,
    PocResult,
    poc_output_schema,
)
from cairn.poc.prompt import POC_AUTHOR_SYSTEM_PROMPT


def plan_payload(**overrides: object) -> dict[str, object]:
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
        "rationale": "The tpl field is evaluated as a SpEL expression.",
    }
    for key, value in overrides.items():
        if key in {"request", "injection", "criterion"} and isinstance(value, dict):
            payload[key] = {**payload[key], **value}  # type: ignore[dict-item]
        else:
            payload[key] = value
    return payload


def build(**overrides: object) -> PocPlan:
    return PocPlan.model_validate(plan_payload(**overrides))


# --- a plan the platform can run ---------------------------------------------


def test_a_well_formed_plan_validates() -> None:
    plan = build()

    assert plan.injection.location == "body_field"
    assert plan.criterion.kind == "contains_text"


# --- the request cannot leave the target -------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "http://evil.example/x",
        "//evil.example/x",
        "render",  # not relative to root
    ],
)
def test_a_path_that_names_a_host_is_refused(path: str) -> None:
    with pytest.raises(ValidationError):
        build(request={"path": path})


@pytest.mark.parametrize(
    "header",
    ["host", "transfer-encoding", "content-length", "x-forwarded-for"],
)
def test_a_header_that_reroutes_or_forges_trust_is_refused(header: str) -> None:
    with pytest.raises(ValidationError):
        build(request={"headers": {header: "value"}})


def test_a_header_value_with_a_line_break_is_refused() -> None:
    with pytest.raises(ValidationError):
        build(request={"headers": {"accept": "a\r\nX-Injected: 1"}})


def test_only_ordinary_request_headers_are_allowed() -> None:
    # A guardrail on the guardrail: the allowlist is what the refusals above
    # rely on, so its contents are pinned.
    assert "host" not in ALLOWED_HEADERS
    assert "transfer-encoding" not in ALLOWED_HEADERS
    assert "authorization" in ALLOWED_HEADERS


# --- the criterion cannot be forged ------------------------------------------


def test_a_control_value_equal_to_the_payload_is_refused() -> None:
    """Identical values make the two requests identical, so no criterion could
    discriminate — and that is the shape that would confirm anything."""

    with pytest.raises(ValidationError):
        build(injection={"benign": "same", "payload": "same"})


@pytest.mark.parametrize("kind", ["regex_matches", "always", "response_ok"])
def test_a_criterion_outside_the_closed_set_is_refused(kind: str) -> None:
    with pytest.raises(ValidationError):
        build(criterion={"kind": kind, "match_text": "x"})


def test_contains_text_without_text_is_refused() -> None:
    with pytest.raises(ValidationError):
        build(criterion={"kind": "contains_text", "match_text": "   "})


def test_status_code_is_without_a_code_is_refused() -> None:
    with pytest.raises(ValidationError):
        build(criterion={"kind": "status_code_is", "match_text": None, "status_code": None})


# --- the nonce belongs to the platform ---------------------------------------


def test_the_control_value_may_not_carry_a_callback_token() -> None:
    """A callback from the control request would prove nothing about the payload."""

    with pytest.raises(ValidationError):
        build(injection={"benign": f"see {CALLBACK_TOKEN}", "payload": "${7*7}"})


def test_an_out_of_band_criterion_requires_the_token_in_the_payload() -> None:
    """Otherwise the plan asserts a callback it gave the application no way to make."""

    with pytest.raises(ValidationError):
        build(
            injection={"payload": "no token here"},
            criterion={"kind": "echo_nonce_observed", "match_text": None},
        )


def test_a_plan_cannot_carry_a_nonce_field() -> None:
    """The model has nowhere to assert that a callback was observed."""

    with pytest.raises(ValidationError):
        PocPlan.model_validate({**plan_payload(), "nonce": "cairn-deadbeef"})
    with pytest.raises(ValidationError):
        PocPlan.model_validate({**plan_payload(), "echo_observed": True})


# --- bounds ------------------------------------------------------------------


def test_an_oversized_body_is_refused() -> None:
    with pytest.raises(ValidationError):
        build(request={"body": "x" * 9000})


def test_too_many_headers_are_refused() -> None:
    with pytest.raises(ValidationError):
        build(request={"headers": {name: "v" for name in list(ALLOWED_HEADERS) * 2}})


# --- the result manifest ------------------------------------------------------


def test_a_completed_result_requires_a_matching_plan() -> None:
    with pytest.raises(ValidationError):
        PocResult.model_validate(
            {
                "contract": "cairn-poc-plan-v1",
                "status": "completed",
                "tool_name": "poc-author",
                "model": "claude-opus-5",
                "finding_id": "f-1",
                "reason_code": None,
                "plan": None,
                "warnings": [],
            }
        )


def test_a_completed_result_rejects_a_plan_for_another_finding() -> None:
    with pytest.raises(ValidationError):
        PocResult.model_validate(
            {
                "contract": "cairn-poc-plan-v1",
                "status": "completed",
                "tool_name": "poc-author",
                "model": "claude-opus-5",
                "finding_id": "f-1",
                "reason_code": None,
                "plan": plan_payload(finding_id="f-2"),
                "warnings": [],
            }
        )


def test_a_failed_result_cannot_carry_a_plan() -> None:
    with pytest.raises(ValidationError):
        PocResult.model_validate(
            {
                "contract": "cairn-poc-plan-v1",
                "status": "failed",
                "tool_name": "poc-author",
                "model": "claude-opus-5",
                "finding_id": "f-1",
                "reason_code": "POC_MODEL_REFUSED",
                "plan": plan_payload(),
                "warnings": [],
            }
        )


# --- the output schema is a subset the SDK accepts ---------------------------


def test_the_output_schema_gives_the_model_no_field_to_supply_a_nonce() -> None:
    schema = poc_output_schema()
    injection = schema["properties"]["injection"]["properties"]
    criterion = schema["properties"]["criterion"]["properties"]

    # The model chooses a criterion *kind* (one of which is named for the
    # out-of-band check) but supplies no nonce value anywhere.
    assert set(injection) == {"location", "name", "benign", "payload"}
    assert set(criterion) == {"kind", "match_text", "status_code", "elapsed_ms"}
    # The token is described so the model knows how to request a callback; the
    # value it resolves to is the platform's.
    assert CALLBACK_TOKEN in json.dumps(schema)


def test_only_the_rationale_is_asked_for_in_chinese() -> None:
    """`rationale` is prose a reviewer reads; the injection values and the match
    text go on the wire and are compared byte for byte. Asking for Chinese
    everywhere would translate a payload and break the probe, so the schema has
    to draw the line, and both sides of it are stated rather than left implied.
    """

    schema = poc_output_schema()
    injection = schema["properties"]["injection"]["properties"]
    criterion = schema["properties"]["criterion"]["properties"]

    assert "中文" in schema["properties"]["rationale"]["description"]
    for field in (injection["benign"], injection["payload"], criterion["match_text"]):
        assert "verbatim" in field["description"] or "actually emits" in field[
            "description"
        ]
        assert "中文" not in field["description"]

    assert "Simplified Chinese" in POC_AUTHOR_SYSTEM_PROMPT
    assert "`rationale`" in POC_AUTHOR_SYSTEM_PROMPT
    for name in ("`injection.payload`", "`criterion.match_text`"):
        assert name in POC_AUTHOR_SYSTEM_PROMPT, name
