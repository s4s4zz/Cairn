"""The deterministic probe table (§7.7).

The property that matters most is negative: **no failure mode may produce a
rejection.** §7.7 says an environment problem yields `inconclusive`, and a
probe that never really ran is an environment problem wearing a different hat.
Every "could not run" path is asserted individually and then again as a class.
"""

from __future__ import annotations

import json
import re

import pytest

from cairn.dynamic.contracts import (
    REASON_CATEGORY_UNSUPPORTED,
    REASON_REQUEST_FAILED,
    REASON_ROUTE_UNKNOWN,
)
from cairn.dynamic.probes import (
    PROBEABLE_CATEGORIES,
    ProbeRunner,
    ProbeTarget,
    _Response,
)

ECHO = "cairn-sandbox-svc-echo-1:8081"
NONCE = re.compile(r"cairn-[0-9a-f]{32}")


class ScriptedCaller:
    """Answers requests from predicate rules, defaulting to a bland 200."""

    def __init__(self, rules=(), *, echo_hits: bool = False) -> None:
        self.rules = list(rules)
        self.calls: list[tuple[str, str, str | None]] = []
        self.echo_hits = echo_hits
        self.planted: str | None = None

    def __call__(self, method: str, url: str, body: str | None, timeout: float):
        del timeout
        self.calls.append((method, url, body))
        if "__cairn/observed" in url:
            seen = [self.planted] if (self.echo_hits and self.planted) else []
            return _Response(200, json.dumps({"nonces": seen}), 2, 5)
        for source in (url, body or ""):
            # The echo hostname also begins with `cairn-`, so match the nonce
            # format rather than the prefix.
            found = NONCE.search(source)
            if found:
                self.planted = found.group(0)
        for matches, response in self.rules:
            if matches(method, url, body):
                return response
        return _Response(200, "baseline", 8, 10)


def target(category: str, **overrides) -> ProbeTarget:
    payload = {
        "finding_id": "f-1",
        "category": category,
        "route": "/items/{id}",
    }
    payload.update(overrides)
    return ProbeTarget(**payload)


def run(category: str, rules=(), *, echo_hits: bool = False, **overrides):
    caller = ScriptedCaller(rules, echo_hits=echo_hits)
    runner = ProbeRunner(
        "http://app:8080",
        echo_endpoint=ECHO,
        caller=caller,
    )
    return runner.run(target(category, **overrides)), caller


# --- confirmations ------------------------------------------------------------


def test_a_sql_error_in_the_response_confirms_injection() -> None:
    outcome, _ = run(
        "sql-injection",
        [
            (
                lambda m, u, b: "OR" in u,
                _Response(500, "org.postgresql.util.PSQLException: unterminated", 60, 12),
            )
        ],
    )

    assert outcome.verdict == "confirmed"
    assert outcome.payload is not None


def test_a_tautology_that_widens_the_response_confirms_injection() -> None:
    outcome, _ = run(
        "sql-injection",
        [(lambda m, u, b: "OR" in u, _Response(200, "x" * 400, 400, 12))],
    )

    assert outcome.verdict == "confirmed"


def test_passwd_in_the_response_confirms_traversal() -> None:
    outcome, _ = run(
        "path-traversal",
        [
            (
                lambda m, u, b: "passwd" in u,
                _Response(200, "root:x:0:0:root:/root:/bin/bash", 31, 9),
            )
        ],
    )

    assert outcome.verdict == "confirmed"


@pytest.mark.parametrize("category", ["ssrf", "xxe"])
def test_an_out_of_band_hit_confirms_without_reading_the_response(
    category: str,
) -> None:
    """The application fetched the planted URL; its own response is irrelevant."""

    outcome, _ = run(category, echo_hits=True)

    assert outcome.verdict == "confirmed"
    assert outcome.echo_observed is True
    assert outcome.nonce is not None


def test_a_delay_confirms_command_execution() -> None:
    """No echo callback is possible: the injected command runs in a container
    that deliberately ships no HTTP client. A delay needs none."""

    outcome, _ = run(
        "command-execution",
        [(lambda m, u, b: "sleep" in u, _Response(200, "ok", 2, 5200))],
    )

    assert outcome.verdict == "confirmed"
    assert "sleep" in outcome.detail


def test_reflected_command_output_also_confirms() -> None:
    outcome, _ = run(
        "command-execution",
        [
            (
                lambda m, u, b: "sleep" in u,
                _Response(200, "root:x:0:0:root:/root:/bin/sh", 29, 15),
            )
        ],
    )

    assert outcome.verdict == "confirmed"


# --- rejections, only from a probe that ran -----------------------------------


@pytest.mark.parametrize(
    "category",
    ["sql-injection", "path-traversal", "ssrf", "xxe", "command-execution"],
)
def test_an_unchanged_response_rejects(category: str) -> None:
    outcome, _ = run(category)

    assert outcome.verdict == "rejected"
    assert outcome.reason_code is None
    assert outcome.baseline is not None and outcome.payload is not None


# --- nothing that failed may reject -------------------------------------------


def test_an_unknown_route_is_inconclusive() -> None:
    outcome, _ = run("ssrf", route=None)

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_ROUTE_UNKNOWN


def test_a_category_with_no_probe_is_inconclusive() -> None:
    outcome, _ = run("open-redirect")

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_CATEGORY_UNSUPPORTED


def test_a_route_the_application_does_not_serve_is_inconclusive() -> None:
    outcome, _ = run(
        "sql-injection",
        [(lambda m, u, b: True, _Response(404, "", 0, 3))],
    )

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_ROUTE_UNKNOWN


def test_a_transport_failure_is_inconclusive() -> None:
    outcome, _ = run(
        "sql-injection",
        [
            (
                lambda m, u, b: "OR" in u,
                _Response(None, "", 0, 20, "connection reset by peer"),
            )
        ],
    )

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_REQUEST_FAILED


def test_no_echo_service_makes_out_of_band_categories_inconclusive() -> None:
    runner = ProbeRunner("http://app:8080", caller=ScriptedCaller())

    outcome = runner.run(target("ssrf"))

    assert outcome.verdict == "inconclusive"
    assert outcome.reason_code == REASON_CATEGORY_UNSUPPORTED


@pytest.mark.parametrize(
    ("label", "kwargs"),
    [
        ("unknown route", {"route": None}),
        ("unsupported category", {"category_override": "deserialization"}),
    ],
)
def test_no_failure_mode_ever_rejects(label: str, kwargs: dict) -> None:
    category = kwargs.pop("category_override", "sql-injection")
    outcome, _ = run(category, **kwargs)

    assert outcome.verdict != "rejected", label


# --- route resolution ----------------------------------------------------------


def test_the_bare_route_is_tried_before_a_class_level_prefix() -> None:
    """The index does not resolve class-level @RequestMapping prefixes, so the
    probe offers them as fallbacks rather than assuming one."""

    routes = ProbeRunner.candidate_routes(
        ProbeTarget(
            finding_id="f",
            category="ssrf",
            route="/items/{id}",
            route_prefixes=("/api/v1", "/api/v2"),
        )
    )

    assert routes == ("/items/{id}", "/api/v1/items/{id}", "/api/v2/items/{id}")


def test_a_prefix_is_actually_tried_when_the_bare_route_404s() -> None:
    outcome, caller = run(
        "path-traversal",
        [
            (lambda m, u, b: "/api/" not in u, _Response(404, "", 0, 3)),
            (lambda m, u, b: "passwd" in u,
             _Response(200, "root:x:0:0:root:/root:/bin/bash", 31, 9)),
        ],
        route_prefixes=("/api",),
    )

    assert outcome.verdict == "confirmed"
    assert any("/api/items/" in url for _m, url, _b in caller.calls)


# --- the closed category set ---------------------------------------------------


def test_only_categories_with_a_real_probe_are_advertised() -> None:
    assert PROBEABLE_CATEGORIES == {
        "sql-injection",
        "path-traversal",
        "ssrf",
        "xxe",
        "command-execution",
        "authorization",
    }
