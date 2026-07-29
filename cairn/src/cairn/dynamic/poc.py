"""Execute a model-authored PoC, and decide what its result means (§7.7, §13.5).

The model wrote the request. Everything here — building both variants,
generating the callback nonce, evaluating the criterion, deciding whether the
result is evidence — belongs to the platform, and that division is what stops a
model from confirming its own finding.

**The platform substitutes, so the two requests provably differ once.** It
takes one template and one injection point and builds the control and the
attack itself. A model that submitted two requests could have made them differ
anywhere; a model that submits a template and a value cannot.

**A criterion only counts when it discriminates.** It must match the attack
response and *not* the control response. "Confirmed if the body contains
'html'" matches both and is reported as no evidence at all, with its own reason
code, rather than as a confirmation.

**The nonce is generated here and checked at the echo service.** The model can
ask for a callback by writing the token; it never learns the value and has no
field in which to assert that one arrived.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import secrets
from typing import Any
import urllib.parse

from cairn.dynamic.contracts import (
    MAX_BODY_EXCERPT,
    REASON_REQUEST_FAILED,
    HttpExchange,
    ProbeOutcome,
)
from cairn.dynamic.probes import REQUEST_TIMEOUT_SECONDS, HttpCaller, default_caller
from cairn.poc.contracts import CALLBACK_TOKEN, PocPlan

REASON_NOT_DISCRIMINATING = "POC_CRITERION_NOT_DISCRIMINATING"
REASON_INJECTION_UNRESOLVED = "POC_INJECTION_UNRESOLVED"
REASON_PLAN_INVALID = "POC_PLAN_INVALID"
REASON_NO_ECHO = "POC_ECHO_UNAVAILABLE"


@dataclass(frozen=True, slots=True)
class _Built:
    method: str
    url: str
    headers: dict[str, str]
    body: str | None


class PocExecutor:
    """Runs one authored plan against the running application."""

    def __init__(
        self,
        base_url: str,
        *,
        echo_endpoint: str | None = None,
        caller: HttpCaller = default_caller,
        timeout_seconds: float = REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._echo_endpoint = echo_endpoint
        self._caller = caller
        self._timeout = timeout_seconds

    def run(self, plan: PocPlan) -> ProbeOutcome:
        needs_echo = plan.criterion.kind == "echo_nonce_observed"
        if needs_echo and not self._echo_endpoint:
            return _inconclusive(
                plan,
                REASON_NO_ECHO,
                "该 PoC 要求带外回连确认，但本次环境中没有可用的 echo 服务。",
            )

        nonce = f"cairn-{secrets.token_hex(16)}" if CALLBACK_TOKEN in plan.injection.payload else None
        try:
            control = self._build(plan, plan.injection.benign, nonce=None)
            attack = self._build(plan, plan.injection.payload, nonce=nonce)
        except _Unresolved as exc:
            return _inconclusive(plan, REASON_INJECTION_UNRESOLVED, str(exc))

        baseline_exchange, baseline_body = self._send(control)
        payload_exchange, payload_body = self._send(attack)
        if payload_exchange.error:
            return _inconclusive(
                plan,
                REASON_REQUEST_FAILED,
                f"攻击请求未能完成：{payload_exchange.error}",
                baseline=baseline_exchange,
                payload=payload_exchange,
                nonce=nonce,
            )

        echo_observed = bool(nonce) and self._echo_hit(nonce or "")
        matched_payload, matched_baseline = self._evaluate(
            plan,
            baseline=(baseline_exchange, baseline_body),
            payload=(payload_exchange, payload_body),
            echo_observed=echo_observed,
        )

        if matched_payload and matched_baseline:
            # The criterion fires on a request carrying a harmless value, so it
            # says nothing about the payload. This is the case that would let a
            # model confirm anything, and it is not a confirmation.
            return _inconclusive(
                plan,
                REASON_NOT_DISCRIMINATING,
                "成功判据在对照请求上同样命中，因此它区分不出任何东西，不构成证据。",
                baseline=baseline_exchange,
                payload=payload_exchange,
                nonce=nonce,
                echo_observed=echo_observed,
            )
        if matched_payload:
            return ProbeOutcome(
                finding_id=plan.finding_id,
                category=plan.category,
                verdict="confirmed",
                detail=_confirmed_detail(plan, echo_observed),
                baseline=baseline_exchange,
                payload=payload_exchange,
                nonce=nonce,
                echo_observed=echo_observed,
            )
        return ProbeOutcome(
            finding_id=plan.finding_id,
            category=plan.category,
            verdict="rejected",
            detail=(
                "模型编写的 PoC 已执行，但其成功判据未命中；"
                "载荷没有产生该 PoC 所预期的效果。"
            ),
            baseline=baseline_exchange,
            payload=payload_exchange,
            nonce=nonce,
            echo_observed=echo_observed,
        )

    # -- request construction ---------------------------------------------

    def _build(self, plan: PocPlan, value: str, *, nonce: str | None) -> _Built:
        """Substitute one value into the template.

        Called twice with the same template, so anything not touched here is
        identical between the two requests by construction.
        """

        resolved = value
        if nonce is not None and CALLBACK_TOKEN in resolved:
            resolved = resolved.replace(
                CALLBACK_TOKEN,
                f"http://{self._echo_endpoint}/{nonce}",
            )
        request = plan.request
        path = request.path
        headers = {name.lower(): text for name, text in request.headers.items()}
        body = request.body
        location = plan.injection.location
        name = plan.injection.name

        if location == "path":
            token = "{" + name + "}"
            if token not in path:
                raise _Unresolved(
                    f"请求路径中不存在路径变量 {token}"
                )
            path = path.replace(token, urllib.parse.quote(resolved, safe=""))
        elif location == "query":
            path = _with_query(path, name, resolved)
        elif location == "header":
            # An empty value means "omit this header", which is how an
            # unauthenticated-access PoC expresses its attack.
            if resolved:
                headers[name.lower()] = resolved
            else:
                headers.pop(name.lower(), None)
        else:
            body = _with_body_field(body, name, resolved)

        return _Built(
            method=request.method,
            url=f"{self._base_url}{path}",
            headers=headers,
            body=body,
        )

    def _send(self, built: _Built) -> tuple[HttpExchange, str]:
        response = self._caller(built.method, built.url, built.body, self._timeout)
        exchange = HttpExchange(
            method=built.method,
            url=built.url[:4096],
            request_body=(built.body or "")[:MAX_BODY_EXCERPT] or None,
            status_code=response.status_code,
            response_excerpt=response.body[:MAX_BODY_EXCERPT] or None,
            response_bytes=response.byte_count,
            elapsed_ms=response.elapsed_ms,
            error=response.error,
        )
        return exchange, response.body

    def _echo_hit(self, nonce: str) -> bool:
        if not self._echo_endpoint:
            return False
        response = self._caller(
            "GET",
            f"http://{self._echo_endpoint}/__cairn/observed",
            None,
            self._timeout,
        )
        if response.status_code != 200:
            return False
        try:
            payload = json.loads(response.body)
        except (TypeError, ValueError):
            return False
        return nonce in set(payload.get("nonces") or [])

    # -- criterion evaluation ----------------------------------------------

    def _evaluate(
        self,
        plan: PocPlan,
        *,
        baseline: tuple[HttpExchange, str],
        payload: tuple[HttpExchange, str],
        echo_observed: bool,
    ) -> tuple[bool, bool]:
        """Return (matched_payload, matched_baseline).

        Three of the five criteria are differential by construction — they
        compare the two responses — so their baseline match is always False and
        the discrimination rule is satisfied structurally. The two absolute
        ones are the reason the rule exists.
        """

        criterion = plan.criterion
        baseline_exchange, baseline_body = baseline
        payload_exchange, payload_body = payload

        if criterion.kind == "contains_text":
            needle = criterion.match_text or ""
            return (needle in payload_body, needle in baseline_body)
        if criterion.kind == "status_code_is":
            wanted = criterion.status_code
            return (
                payload_exchange.status_code == wanted,
                baseline_exchange.status_code == wanted,
            )
        if criterion.kind == "status_code_differs":
            return (
                payload_exchange.status_code != baseline_exchange.status_code,
                False,
            )
        if criterion.kind == "elapsed_exceeds_ms":
            threshold = criterion.elapsed_ms or 0
            delta = payload_exchange.elapsed_ms - baseline_exchange.elapsed_ms
            return (delta >= threshold, False)
        # echo_nonce_observed: the control value cannot carry the callback token
        # (the contract refuses it), so a hit can only have come from the
        # payload.
        return (echo_observed, False)


class _Unresolved(Exception):
    """The injection point does not exist in the request the model described."""


def _with_query(path: str, name: str, value: str) -> str:
    parsed = urllib.parse.urlsplit(path)
    pairs = [
        (key, existing)
        for key, existing in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != name
    ]
    pairs.append((name, value))
    return urllib.parse.urlunsplit(
        ("", "", parsed.path, urllib.parse.urlencode(pairs), parsed.fragment)
    )


def _with_body_field(body: str | None, name: str, value: str) -> str:
    """Set a dotted field path in a JSON body.

    A body that is not JSON cannot carry a field, and inventing one would send
    a request the plan did not describe.
    """

    try:
        document: Any = json.loads(body) if body else {}
    except (TypeError, ValueError) as exc:
        raise _Unresolved("请求体不是 JSON，因此不存在可注入的字段") from exc
    if not isinstance(document, dict):
        raise _Unresolved("请求体不是 JSON 对象")
    parts = [part for part in name.split(".") if part]
    if not parts:
        raise _Unresolved("注入点没有指明请求体字段")
    cursor = document
    for part in parts[:-1]:
        nested = cursor.get(part)
        if not isinstance(nested, dict):
            nested = {}
            cursor[part] = nested
        cursor = nested
    cursor[parts[-1]] = value
    return json.dumps(document)


def _confirmed_detail(plan: PocPlan, echo_observed: bool) -> str:
    if echo_observed:
        return (
            "应用执行了载荷所植入的带外回连：平台的 nonce 抵达了隔离的 echo 服务，"
            "而对照请求没有产生任何回连。"
        )
    return (
        f"模型编写的 PoC 成功：其 {plan.criterion.kind} 判据在攻击请求上命中、"
        "在对照请求上未命中，而两次请求仅在注入取值处不同。"
    )


def _inconclusive(
    plan: PocPlan,
    reason_code: str,
    detail: str,
    *,
    baseline: HttpExchange | None = None,
    payload: HttpExchange | None = None,
    nonce: str | None = None,
    echo_observed: bool = False,
) -> ProbeOutcome:
    return ProbeOutcome(
        finding_id=plan.finding_id,
        category=plan.category,
        verdict="inconclusive",
        reason_code=reason_code,
        detail=detail,
        baseline=baseline,
        payload=payload,
        nonce=nonce,
        echo_observed=echo_observed,
    )
