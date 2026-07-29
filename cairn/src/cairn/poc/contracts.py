"""What a model may propose as a proof of concept (§7.7, §13.5).

The platform's own probes (`cairn.dynamic.probes`) cover five categories. This
contract covers the rest by letting a model write the request — and nothing
else. Everything about *what counts as evidence* stays with the platform,
because a model that both writes the payload and defines success can
manufacture a confirmation out of nothing: "send GET /, confirmed if the
response contains 'html'". §13.5 says the AI may not confirm a Finding, so the
contract has to make that unrepresentable rather than merely discouraged.

Three properties do that, and each is enforced here rather than assumed:

**The model submits one request template and an injection point, not two
requests.** Letting it submit a baseline and an attack would let it make them
differ somewhere other than the payload — baseline ``GET /nope`` returning 404
against attack ``GET /`` returning 200 discriminates perfectly and proves
nothing. The platform substitutes ``benign`` and ``payload`` into one template
itself, so the two requests provably differ at exactly one place.

**The success criterion comes from a closed vocabulary.** No regex and no
expression: a regex is expressive enough to route around the discrimination
rule, quite apart from being a denial-of-service surface.

**The callback nonce belongs to the platform.** The model may write
``{{CAIRN_CALLBACK}}`` into its payload and the platform substitutes a
generated URL; the model never sees the nonce and cannot assert that one was
observed. That is checked at the echo service, not in the response.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from cairn.analysis.contracts import StrictModel

POC_CONTRACT = "cairn-poc-plan-v1"
POC_TOOL_NAME = "poc-author"

REASON_OUTPUT_INVALID = "POC_OUTPUT_INVALID"
REASON_MODEL_REFUSED = "POC_MODEL_REFUSED"
REASON_MODEL_UNAVAILABLE = "POC_MODEL_UNAVAILABLE"
REASON_OUTPUT_INCOMPLETE = "POC_OUTPUT_INCOMPLETE"
REASON_TURN_LIMIT = "POC_TURN_LIMIT_REACHED"
REASON_TOOL_BUDGET = "POC_TOOL_BUDGET_REACHED"
REASON_NO_PLAN = "POC_NO_PLAN"

# The token the platform replaces with its own callback URL. Declared here so
# the prompt, the executor and the tests all name the same string.
CALLBACK_TOKEN = "{{CAIRN_CALLBACK}}"

MAX_HEADERS = 8
MAX_HEADER_VALUE = 512
MAX_BODY_BYTES = 8192
MAX_PAYLOAD_CHARS = 2048
MAX_MATCH_TEXT = 256

# Request headers a PoC may set. Everything that changes routing, framing or
# the platform's own identity is absent: `Host` would redirect the request off
# the target, `Transfer-Encoding` and `Content-Length` invite request
# smuggling, and `X-Forwarded-*` would let a PoC forge the trust signal it is
# supposed to be testing.
ALLOWED_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "authorization",
        "content-type",
        "cookie",
        "origin",
        "referer",
        "user-agent",
        "x-requested-with",
    }
)


class PocRequest(StrictModel):
    """The request template, minus everything that would let it leave the target."""

    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"]
    # Relative only. The platform prefixes the running application's origin, so
    # a plan cannot address any other host.
    path: str = Field(min_length=1, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(default=None, max_length=MAX_BODY_BYTES)

    @model_validator(mode="after")
    def validate_request(self) -> "PocRequest":
        if not self.path.startswith("/"):
            raise ValueError("path must be relative to the application origin")
        if "://" in self.path or self.path.startswith("//"):
            raise ValueError("path must not name a host")
        if len(self.headers) > MAX_HEADERS:
            raise ValueError(f"a PoC may set at most {MAX_HEADERS} headers")
        for name, value in self.headers.items():
            if name.strip().lower() not in ALLOWED_HEADERS:
                raise ValueError(f"header {name!r} is not permitted in a PoC")
            if len(value) > MAX_HEADER_VALUE:
                raise ValueError(f"header {name!r} value is too long")
            if "\r" in value or "\n" in value:
                raise ValueError("header values must not contain line breaks")
        return self


class PocInjection(StrictModel):
    """Where the attack value goes, and what the control value is.

    One injection point per plan. That is the whole mechanism behind the
    discrimination rule: the platform builds both requests from this, so the
    only difference between them is this value.
    """

    location: Literal["query", "path", "header", "body_field"]
    name: str = Field(min_length=1, max_length=255)
    benign: str = Field(max_length=MAX_PAYLOAD_CHARS)
    payload: str = Field(max_length=MAX_PAYLOAD_CHARS)

    @model_validator(mode="after")
    def validate_injection(self) -> "PocInjection":
        if self.benign == self.payload:
            # Identical values make the two requests identical, so no criterion
            # could ever discriminate — and a plan shaped that way is either a
            # mistake or an attempt to get a criterion evaluated against one
            # response twice.
            raise ValueError("the payload must differ from the control value")
        if self.location == "header" and self.name.strip().lower() not in ALLOWED_HEADERS:
            raise ValueError(f"header {self.name!r} is not permitted in a PoC")
        if CALLBACK_TOKEN in self.benign:
            # The control request must not reach the echo service, or a hit
            # would prove nothing about the payload.
            raise ValueError("the control value must not carry a callback token")
        return self


class PocCriterion(StrictModel):
    """What the platform will look for, from a closed vocabulary.

    `match_text` and `status_code` and `elapsed_ms` are the only parameters; the
    model cannot supply a pattern, an expression or anything else the platform
    would have to evaluate.
    """

    kind: Literal[
        "contains_text",
        "status_code_is",
        "status_code_differs",
        "elapsed_exceeds_ms",
        "echo_nonce_observed",
    ]
    match_text: str | None = Field(default=None, max_length=MAX_MATCH_TEXT)
    status_code: int | None = Field(default=None, ge=100, le=599)
    elapsed_ms: int | None = Field(default=None, ge=250, le=60_000)

    @model_validator(mode="after")
    def validate_parameters(self) -> "PocCriterion":
        if self.kind == "contains_text":
            if not (self.match_text or "").strip():
                raise ValueError("contains_text requires non-empty text to match")
        elif self.kind == "status_code_is":
            if self.status_code is None:
                raise ValueError("status_code_is requires a status code")
        elif self.kind == "elapsed_exceeds_ms":
            if self.elapsed_ms is None:
                raise ValueError("elapsed_exceeds_ms requires a threshold")
        return self


class PocPlan(StrictModel):
    """One model-authored proof of concept for one Finding."""

    finding_id: str = Field(min_length=1, max_length=64)
    category: str = Field(min_length=1, max_length=255)
    request: PocRequest
    injection: PocInjection
    criterion: PocCriterion
    # Shown as evidence and never evaluated. The model explaining itself is
    # useful to a reviewer; it is not an input to the verdict.
    rationale: str = Field(min_length=1, max_length=4096)

    @model_validator(mode="after")
    def validate_plan(self) -> "PocPlan":
        if self.criterion.kind == "echo_nonce_observed":
            if CALLBACK_TOKEN not in self.injection.payload:
                # Otherwise the plan asserts an out-of-band hit it never gave
                # the application any way to make.
                raise ValueError(
                    "an out-of-band criterion requires the callback token in "
                    "the payload"
                )
        return self


class PocResult(StrictModel):
    """Per-finding manifest from the authoring sandbox."""

    contract: Literal["cairn-poc-plan-v1"]
    status: Literal["completed", "failed", "unavailable"]
    tool_name: str = Field(min_length=1, max_length=128)
    model: str = Field(min_length=1, max_length=255)
    finding_id: str = Field(min_length=1, max_length=64)
    reason_code: str | None = Field(default=None, max_length=128)
    plan: PocPlan | None = None
    warnings: list[dict[str, object]] = Field(default_factory=list, max_length=64)

    @model_validator(mode="after")
    def validate_status_payload(self) -> "PocResult":
        if self.status == "completed":
            if self.reason_code is not None:
                raise ValueError("completed result cannot contain reason_code")
            if self.plan is None:
                raise ValueError("completed result requires a plan")
            if self.plan.finding_id != self.finding_id:
                raise ValueError("the plan does not match its finding")
        else:
            if not self.reason_code:
                raise ValueError("non-completed result requires reason_code")
            if self.plan is not None:
                raise ValueError("non-completed result cannot carry a plan")
        return self


def poc_output_schema() -> dict[str, object]:
    """JSON Schema for ``output_config.format``.

    Only the supported subset, as elsewhere: the SDK strips ``minLength`` and
    friends, so this shapes the answer and the models above are the gate.
    """

    return {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "request": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "method": {
                        "type": "string",
                        "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"],
                    },
                    "path": {
                        "type": "string",
                        "description": (
                            "Path relative to the application root, starting "
                            "with '/'. You cannot name a host: the platform "
                            "supplies the origin."
                        ),
                    },
                    "headers": {
                        "type": "object",
                        "additionalProperties": {"type": "string"},
                        "description": (
                            "Optional. Permitted names: "
                            + ", ".join(sorted(ALLOWED_HEADERS))
                        ),
                    },
                    "body": {
                        "type": ["string", "null"],
                        "description": "Request body, or null.",
                    },
                },
                "required": ["method", "path", "headers", "body"],
            },
            "injection": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "location": {
                        "type": "string",
                        "enum": ["query", "path", "header", "body_field"],
                    },
                    "name": {
                        "type": "string",
                        "description": (
                            "Query parameter, path variable, header name, or "
                            "dotted JSON field path in the body."
                        ),
                    },
                    "benign": {
                        "type": "string",
                        "description": (
                            "The control value: what a legitimate request "
                            "would carry here. Sent verbatim — never a Chinese "
                            "description of the value."
                        ),
                    },
                    "payload": {
                        "type": "string",
                        "description": (
                            "The attack value, sent verbatim — never a Chinese "
                            "description of it. Write "
                            f"{CALLBACK_TOKEN} where you want the platform's "
                            "out-of-band callback URL; it is generated and "
                            "checked by the platform, not by you."
                        ),
                    },
                },
                "required": ["location", "name", "benign", "payload"],
            },
            "criterion": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": [
                            "contains_text",
                            "status_code_is",
                            "status_code_differs",
                            "elapsed_exceeds_ms",
                            "echo_nonce_observed",
                        ],
                    },
                    "match_text": {
                        "type": ["string", "null"],
                        "description": (
                            "Literal text compared against the attack response, "
                            "byte for byte. It must be what the application "
                            "actually emits — not a Chinese description of it."
                        ),
                    },
                    "status_code": {"type": ["integer", "null"]},
                    "elapsed_ms": {"type": ["integer", "null"]},
                },
                "required": ["kind", "match_text", "status_code", "elapsed_ms"],
            },
            "rationale": {
                "type": "string",
                "description": (
                    "用简体中文说明：这个请求为何能证明该弱点，而对照值为何不会。"
                    "其中的路径、参数名与载荷保留原文。"
                ),
            },
        },
        "required": ["request", "injection", "criterion", "rationale"],
    }
