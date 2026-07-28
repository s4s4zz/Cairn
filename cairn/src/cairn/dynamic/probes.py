"""Deterministic differential probes (§7.7).

The platform writes these, not a model. Each is a pair of requests — a baseline
and a payload — against the same route, and a verdict drawn from a difference
the platform can state in advance: a marker in the response, an out-of-band hit
on the echo service, or a delay the baseline did not have.

**Only a probe that ran and found nothing returns ``rejected``.** An unknown
route, an unsupported category, a transport failure and a timeout all return
``inconclusive`` with a reason. §7.7 requires it, and the asymmetry is
deliberate: a missed vulnerability that stays in the human queue is recoverable,
one deleted by a probe that never really ran is not.

Two mechanisms carry the confirmations:

*Out-of-band.* SSRF and XXE make the **application** fetch a URL, and the
application is a JVM with a working network stack, so a nonce arriving at the
echo service is proof the payload executed — no response-body heuristic needed.

*Time.* Command execution cannot use the echo service: the injected command runs
inside the validation container, which deliberately ships no HTTP client, so
there is nothing for it to call out with. A `sleep` the baseline did not
experience needs no client and no output reflection, and is the standard blind
technique for exactly this situation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import secrets
import time
from typing import Callable
import urllib.error
import urllib.parse
import urllib.request

from cairn.dynamic.contracts import (
    MAX_BODY_EXCERPT,
    REASON_CATEGORY_UNSUPPORTED,
    REASON_REQUEST_FAILED,
    REASON_ROUTE_UNKNOWN,
    HttpExchange,
    ProbeOutcome,
)

# A delay long enough to be unmistakable against normal jitter, short enough
# that a per-probe budget still covers a handful of findings.
SLEEP_SECONDS = 5
DELAY_THRESHOLD_MS = int(SLEEP_SECONDS * 1000 * 0.6)
REQUEST_TIMEOUT_SECONDS = 20.0

# Response markers that only appear if the payload actually did something.
PASSWD_MARKER = "root:x:0:0"
SQL_ERROR_MARKERS = (
    "sqlexception",
    "syntax error at or near",
    "unterminated quoted string",
    "you have an error in your sql syntax",
    "org.postgresql.util.psqlexception",
    "java.sql.sqlsyntaxerrorexception",
)

BASELINE_VALUE = "1"


@dataclass(frozen=True, slots=True)
class ProbeTarget:
    """One Finding to exercise, as the index described its entrypoint."""

    finding_id: str
    category: str
    http_method: str = "GET"
    route: str | None = None
    route_prefixes: tuple[str, ...] = ()
    parameter: str | None = None


@dataclass(slots=True)
class _Attempt:
    exchange: HttpExchange
    body: str


HttpCaller = Callable[[str, str, str | None, float], "_Response"]


@dataclass(frozen=True, slots=True)
class _Response:
    status_code: int | None
    body: str
    byte_count: int
    elapsed_ms: int
    error: str | None = None


def default_caller(
    method: str,
    url: str,
    body: str | None,
    timeout: float,
) -> _Response:
    """Issue one bounded request with the standard library.

    No third-party client, and the response is read up to a cap: the body comes
    from an application the platform started over a repository's code, so it is
    untrusted data of unbounded size.
    """

    data = body.encode("utf-8") if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(MAX_BODY_EXCERPT * 8)
            return _Response(
                status_code=int(response.status),
                body=raw.decode("utf-8", errors="replace"),
                byte_count=len(raw),
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
    except urllib.error.HTTPError as exc:
        raw = exc.read(MAX_BODY_EXCERPT * 8) if hasattr(exc, "read") else b""
        return _Response(
            status_code=int(exc.code),
            body=raw.decode("utf-8", errors="replace"),
            byte_count=len(raw),
            elapsed_ms=int((time.monotonic() - started) * 1000),
        )
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return _Response(
            status_code=None,
            body="",
            byte_count=0,
            elapsed_ms=int((time.monotonic() - started) * 1000),
            error=str(exc)[:512],
        )


class ProbeRunner:
    """Runs the platform's probes against one running application."""

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

    # -- entry point -------------------------------------------------------

    def run(self, target: ProbeTarget) -> ProbeOutcome:
        handler = _HANDLERS.get(target.category)
        if handler is None:
            return _inconclusive(
                target,
                REASON_CATEGORY_UNSUPPORTED,
                (
                    f"No deterministic probe exists for the {target.category!r} "
                    "category; this finding was not exercised at runtime."
                ),
            )
        routes = self.candidate_routes(target)
        if not routes:
            return _inconclusive(
                target,
                REASON_ROUTE_UNKNOWN,
                (
                    "The index recorded no route for this entrypoint, so no "
                    "request could be addressed to it."
                ),
            )
        return handler(self, target, routes)

    @staticmethod
    def candidate_routes(target: ProbeTarget) -> tuple[str, ...]:
        """Routes to try, in order.

        The index records the method-level mapping value and does not resolve a
        class-level ``@RequestMapping`` prefix, so a route may be a suffix. The
        bare route is tried first, then each recorded prefix joined to it. When
        none of them answers, the probe is inconclusive — guessing further would
        mean reporting on an endpoint nobody identified.
        """

        if not target.route:
            return ()
        bare = "/" + target.route.strip("/")
        routes = [bare]
        for prefix in target.route_prefixes:
            joined = "/" + "/".join(
                part for part in (prefix.strip("/"), target.route.strip("/")) if part
            )
            if joined not in routes:
                routes.append(joined)
        return tuple(routes)

    # -- request construction ---------------------------------------------

    def _url(self, route: str, value: str | None) -> str:
        # `{name}` style path variables are filled with the probe value so the
        # route resolves; otherwise the value rides a query parameter.
        path = route
        substituted = False
        while "{" in path and "}" in path and value is not None:
            start = path.index("{")
            end = path.index("}", start)
            path = f"{path[:start]}{urllib.parse.quote(value, safe='')}{path[end + 1:]}"
            substituted = True
        url = f"{self._base_url}{path}"
        if value is not None and not substituted:
            url = f"{url}?{urllib.parse.urlencode({'q': value})}"
        return url

    def _send(
        self,
        target: ProbeTarget,
        route: str,
        value: str | None,
    ) -> tuple[HttpExchange, str]:
        method = target.http_method.upper()
        url = self._url(route, value)
        body: str | None = None
        if method in {"POST", "PUT", "PATCH"} and value is not None:
            field_name = target.parameter or "value"
            body = json.dumps({field_name: value})
        response = self._caller(method, url, body, self._timeout)
        exchange = HttpExchange(
            method=method,
            url=url[:4096],
            request_body=body[:MAX_BODY_EXCERPT] if body else None,
            status_code=response.status_code,
            response_excerpt=response.body[:MAX_BODY_EXCERPT] or None,
            response_bytes=response.byte_count,
            elapsed_ms=response.elapsed_ms,
            error=response.error,
        )
        return exchange, response.body

    def _baseline(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> tuple[str, HttpExchange, str] | None:
        """Find the first route the application actually serves.

        A 404 on every candidate means the entrypoint was not located, which is
        an inconclusive probe rather than a rejection.
        """

        for route in routes:
            exchange, body = self._send(target, route, BASELINE_VALUE)
            if exchange.status_code is not None and exchange.status_code != 404:
                return route, exchange, body
        return None

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

    # -- per-category probes ------------------------------------------------

    def _probe_sql_injection(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> ProbeOutcome:
        located = self._baseline(target, routes)
        if located is None:
            return _route_not_served(target)
        route, baseline, baseline_body = located

        payload, payload_body = self._send(target, route, "1' OR '1'='1")
        if payload.error:
            return _transport_failed(target, baseline, payload)
        lowered = payload_body.lower()
        if any(marker in lowered for marker in SQL_ERROR_MARKERS):
            return _confirmed(
                target,
                baseline,
                payload,
                "The payload produced a SQL syntax or driver error in the "
                "response, so the value reached the SQL parser as syntax.",
            )
        if _diverged(baseline, payload):
            return _confirmed(
                target,
                baseline,
                payload,
                "The quoted payload changed the response where a literal value "
                "did not, which is the signature of unparameterised SQL.",
            )
        return _rejected(
            target,
            baseline,
            payload,
            "The payload produced no SQL error and no change in the response; "
            "the value does not appear to reach the SQL parser as syntax.",
        )

    def _probe_path_traversal(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> ProbeOutcome:
        located = self._baseline(target, routes)
        if located is None:
            return _route_not_served(target)
        route, baseline, _ = located

        payload, payload_body = self._send(
            target,
            route,
            "../../../../etc/passwd",
        )
        if payload.error:
            return _transport_failed(target, baseline, payload)
        if PASSWD_MARKER in payload_body:
            return _confirmed(
                target,
                baseline,
                payload,
                "The response contained the contents of /etc/passwd, so the "
                "traversal sequence resolved outside the intended directory.",
            )
        return _rejected(
            target,
            baseline,
            payload,
            "The traversal sequence did not return a file outside the intended "
            "directory.",
        )

    def _probe_out_of_band(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
        *,
        build_value,
        confirmed_detail: str,
        rejected_detail: str,
    ) -> ProbeOutcome:
        if not self._echo_endpoint:
            return _inconclusive(
                target,
                REASON_CATEGORY_UNSUPPORTED,
                "No echo service was available, so no out-of-band confirmation "
                "was possible for this category.",
            )
        located = self._baseline(target, routes)
        if located is None:
            return _route_not_served(target)
        route, baseline, _ = located

        nonce = f"cairn-{secrets.token_hex(16)}"
        payload, _ = self._send(target, route, build_value(self._echo_endpoint, nonce))
        if payload.error:
            return _transport_failed(target, baseline, payload, nonce=nonce)
        if self._echo_hit(nonce):
            return _confirmed(
                target,
                baseline,
                payload,
                confirmed_detail,
                nonce=nonce,
                echo_observed=True,
            )
        return _rejected(
            target,
            baseline,
            payload,
            rejected_detail,
            nonce=nonce,
        )

    def _probe_ssrf(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> ProbeOutcome:
        return self._probe_out_of_band(
            target,
            routes,
            build_value=lambda echo, nonce: f"http://{echo}/{nonce}",
            confirmed_detail=(
                "The application fetched a URL supplied in the request: the "
                "planted nonce arrived at the isolated echo service."
            ),
            rejected_detail=(
                "The supplied URL was not fetched; no request carrying the "
                "nonce reached the echo service."
            ),
        )

    def _probe_xxe(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> ProbeOutcome:
        return self._probe_out_of_band(
            target,
            routes,
            build_value=lambda echo, nonce: (
                '<?xml version="1.0"?>'
                f'<!DOCTYPE cairn [<!ENTITY x SYSTEM "http://{echo}/{nonce}">]>'
                "<cairn>&x;</cairn>"
            ),
            confirmed_detail=(
                "The XML parser resolved an external entity: the planted nonce "
                "arrived at the isolated echo service."
            ),
            rejected_detail=(
                "The external entity was not resolved; no request carrying the "
                "nonce reached the echo service."
            ),
        )

    def _probe_command_execution(
        self,
        target: ProbeTarget,
        routes: tuple[str, ...],
    ) -> ProbeOutcome:
        located = self._baseline(target, routes)
        if located is None:
            return _route_not_served(target)
        route, baseline, _ = located

        # `sleep` rather than an out-of-band callback: the injected command runs
        # in the validation container, which ships no HTTP client, so there is
        # nothing there to call out with. A delay needs neither.
        payload, payload_body = self._send(
            target,
            route,
            f"1; sleep {SLEEP_SECONDS}",
        )
        if payload.error:
            return _transport_failed(target, baseline, payload)
        delay = payload.elapsed_ms - baseline.elapsed_ms
        if delay >= DELAY_THRESHOLD_MS:
            return _confirmed(
                target,
                baseline,
                payload,
                f"The request carrying `; sleep {SLEEP_SECONDS}` took "
                f"{delay} ms longer than the baseline, so the shell metacharacter "
                "was interpreted rather than treated as data.",
            )
        if PASSWD_MARKER in payload_body:
            return _confirmed(
                target,
                baseline,
                payload,
                "The response reflected command output, so the injected command "
                "was executed.",
            )
        return _rejected(
            target,
            baseline,
            payload,
            "Neither a timing difference nor reflected command output appeared; "
            "the value does not appear to reach a shell.",
        )


def _diverged(baseline: HttpExchange, payload: HttpExchange) -> bool:
    """A response difference a literal value did not produce."""

    if baseline.status_code != payload.status_code:
        return True
    # A body that changed size substantially is the classic tautology signal:
    # `' OR '1'='1` widens the result set.
    if baseline.response_bytes and payload.response_bytes:
        larger = max(baseline.response_bytes, payload.response_bytes)
        smaller = min(baseline.response_bytes, payload.response_bytes)
        return larger >= smaller * 2
    return False


def _confirmed(
    target: ProbeTarget,
    baseline: HttpExchange,
    payload: HttpExchange,
    detail: str,
    *,
    nonce: str | None = None,
    echo_observed: bool = False,
) -> ProbeOutcome:
    return ProbeOutcome(
        finding_id=target.finding_id,
        category=target.category,
        verdict="confirmed",
        detail=detail,
        baseline=baseline,
        payload=payload,
        nonce=nonce,
        echo_observed=echo_observed,
    )


def _rejected(
    target: ProbeTarget,
    baseline: HttpExchange,
    payload: HttpExchange,
    detail: str,
    *,
    nonce: str | None = None,
) -> ProbeOutcome:
    return ProbeOutcome(
        finding_id=target.finding_id,
        category=target.category,
        verdict="rejected",
        detail=detail,
        baseline=baseline,
        payload=payload,
        nonce=nonce,
    )


def _inconclusive(
    target: ProbeTarget,
    reason_code: str,
    detail: str,
    *,
    baseline: HttpExchange | None = None,
    payload: HttpExchange | None = None,
    nonce: str | None = None,
) -> ProbeOutcome:
    return ProbeOutcome(
        finding_id=target.finding_id,
        category=target.category,
        verdict="inconclusive",
        reason_code=reason_code,
        detail=detail,
        baseline=baseline,
        payload=payload,
        nonce=nonce,
    )


def _route_not_served(target: ProbeTarget) -> ProbeOutcome:
    return _inconclusive(
        target,
        REASON_ROUTE_UNKNOWN,
        (
            "None of the candidate routes was served by the running "
            "application, so the entrypoint could not be reached. The index "
            "does not resolve class-level @RequestMapping prefixes, which is "
            "the usual cause."
        ),
    )


def _transport_failed(
    target: ProbeTarget,
    baseline: HttpExchange,
    payload: HttpExchange,
    *,
    nonce: str | None = None,
) -> ProbeOutcome:
    return _inconclusive(
        target,
        REASON_REQUEST_FAILED,
        f"The payload request did not complete: {payload.error}",
        baseline=baseline,
        payload=payload,
        nonce=nonce,
    )


# Categories with no deterministic probe are absent on purpose: `run` reports
# them as unsupported rather than reaching for a weaker signal.
_HANDLERS: dict[str, Callable[[ProbeRunner, ProbeTarget, tuple[str, ...]], ProbeOutcome]] = {
    "sql-injection": ProbeRunner._probe_sql_injection,
    "path-traversal": ProbeRunner._probe_path_traversal,
    "ssrf": ProbeRunner._probe_ssrf,
    "xxe": ProbeRunner._probe_xxe,
    "command-execution": ProbeRunner._probe_command_execution,
}

PROBEABLE_CATEGORIES = frozenset(_HANDLERS)
