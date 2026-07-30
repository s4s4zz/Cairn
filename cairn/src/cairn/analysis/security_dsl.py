"""Parse Spring Security's Java lambda DSL into interceptor records (图二②).

The modern ``http.authorizeHttpRequests(a -> a.requestMatchers(...).hasRole(...))``
form is code, not configuration, but its shape is regular enough to read with
regexes: a matcher call carrying URL literals, immediately followed by an access
decision. This produces the same ``security-chain`` interceptor records as the
XML path (:func:`cairn.analysis.webxml._parse_spring_security`), so the
authorization topology consumes them without knowing the difference.

Parsed from the ORIGINAL source text, never the comment/literal-stripped form:
the URLs live in string literals, which stripping erases. A comment that happens
to contain ``requestMatchers("/x").permitAll()`` is a rare, low-cost false
positive — it would only ever mark an endpoint as *covered*, never unprotected.
"""

from __future__ import annotations

import re


_STRING_LITERAL = re.compile(r"""["']([^"']+)["']""")
_PERMISSIVE_DECISIONS = frozenset({"permitall", "anonymous"})
_DECISION = (
    r"(permitAll|denyAll|authenticated|fullyAuthenticated|hasRole|hasAnyRole|"
    r"hasAuthority|hasAnyAuthority|anonymous|rememberMe)"
)

# A matcher call carrying URL literals, then the access decision applied to it.
# `[^()]*` keeps the capture inside one matcher call — matcher arguments hold no
# nested parentheses. `(?s)` lets a chained `.hasRole(...)` sit on the next line.
_MATCHER_DECISION = re.compile(
    r"(?s)\b(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^()]*)\)\s*\.\s*"
    + _DECISION
    + r"\b"
)
_ANY_REQUEST = re.compile(r"(?s)\banyRequest\s*\(\s*\)\s*\.\s*" + _DECISION + r"\b")
# `web.ignoring().requestMatchers(...)` skips the security chain entirely, which
# is a permitAll in effect.
_IGNORING = re.compile(
    r"(?s)\.ignoring\s*\(\s*\)\s*\.\s*"
    r"(?:requestMatchers|antMatchers|mvcMatchers)\s*\(([^()]*)\)"
)


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _interceptor(url: str, decision: str, path: str, line: int) -> dict[str, object]:
    return {
        "kind": "security-chain",
        "class_name": f"spring-security:{decision}",
        "url_patterns": [url],
        "dispatcher_types": [],
        "order": None,
        "enforces_auth": decision.lower() not in _PERMISSIVE_DECISIONS,
        "source": "java-config",
        "path": path,
        "line": line,
    }


def parse_security_dsl(source_text: str, path: str) -> list[dict[str, object]]:
    """Return ``security-chain`` interceptor dicts for one Java source file.

    Deterministic in content and order.
    """

    records: list[dict[str, object]] = []
    for match in _MATCHER_DECISION.finditer(source_text):
        line = _line_of(source_text, match.start())
        for url in _STRING_LITERAL.findall(match.group(1)):
            records.append(_interceptor(url, match.group(2), path, line))
    for match in _ANY_REQUEST.finditer(source_text):
        records.append(
            _interceptor("/**", match.group(1), path, _line_of(source_text, match.start()))
        )
    for match in _IGNORING.finditer(source_text):
        line = _line_of(source_text, match.start())
        for url in _STRING_LITERAL.findall(match.group(1)):
            records.append(_interceptor(url, "permitAll", path, line))
    return sorted(
        records,
        key=lambda record: (
            str(record["path"]).encode("utf-8"),
            int(record["line"]),
            str(record["url_patterns"][0]),
            str(record["class_name"]),
        ),
    )
