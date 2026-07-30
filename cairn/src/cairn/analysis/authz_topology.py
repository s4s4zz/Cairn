"""Deterministic authorization topology and structural-bypass candidates (图二).

Given the inventory's entrypoints, interceptors, permission annotations and
sinks, this module answers one question per HTTP entrypoint without reading a
single handler body: *is it structurally reachable without authorization?*

Two things it does, and one it refuses to do:

* It draws the topology — which auth-enforcing interceptor's URL patterns cover
  which entrypoint — into ``AuthBinding`` rows the semantic task consults.
* It emits high-confidence ``CandidateFinding`` rows for **structural** bypass:
  an explicit ``permitAll`` over a sensitive endpoint (CWE-862), or a sensitive
  endpoint no auth interceptor and no auth annotation covers (CWE-306).
* It never judges whether an interceptor's *logic* is correct. That is a
  semantic question; a covered endpoint yields a binding, never a candidate.

The candidate side is deliberately conservative — a structural candidate
becomes a Finding, so a false one is costly. The strongest guard: when any
auth-enforcing interceptor has an unknown coverage set (an ``implements Filter``
bean with no ``@WebFilter``/``web.xml`` mapping — very likely a global filter),
the module does not claim any endpoint is unprotected. It hands reachability to
the semantic stage instead of guessing.
"""

from __future__ import annotations

from cairn.analysis.normalizers import NormalizationError, SourceCatalog, _candidate


AUTHZ_TOOL_NAME = "authz-topology"

_HTTP_ENTRYPOINT_KINDS = frozenset({"http-controller", "http-route", "servlet"})
_AUTH_PERMISSION_KINDS = frozenset(
    {"pre-authorize", "post-authorize", "secured", "roles-allowed", "deny-all"}
)
# A route or handler name carrying one of these is treated as sensitive enough
# that missing authorization is worth a candidate on its own, even when no sink
# was indexed in the same file.
_SENSITIVE_MARKERS = (
    "admin",
    "manage",
    "manager",
    "internal",
    "actuator",
    "config",
    "system",
    "console",
    "debug",
    "delete",
    "remove",
    "export",
    "import",
    "upload",
    "download",
    "exec",
    "shell",
    "root",
    "backup",
    "setting",
    "privilege",
)

_RULE_MISSING_AUTH = "CAIRN-AUTHZ-MISSING-AUTHENTICATION"
_RULE_PERMITALL_SENSITIVE = "CAIRN-AUTHZ-PERMITALL-SENSITIVE"


def url_pattern_matches(pattern: str, path: str) -> bool:
    """Match a servlet/Ant URL pattern against a request path, leniently.

    Leniency is intentional and directional: this decides whether an
    entrypoint is *covered* by an auth interceptor, so matching broadly errs
    toward "protected", which suppresses false unprotected candidates rather
    than manufacturing them. Handles exact, ``/prefix/*``, ``/prefix/**``,
    ``*.ext`` and the catch-alls ``/``, ``/*``, ``/**``.
    """

    pattern = (pattern or "").strip()
    if not pattern:
        return False
    normalized = "/" + str(path or "").strip().lstrip("/")
    if pattern in {"/", "/*", "/**"}:
        return True
    if pattern.startswith("*."):
        return normalized.endswith(pattern[1:])
    base = pattern
    for suffix in ("/**", "/*", "**", "*"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    base = "/" + base.strip("/")
    if base == "/":
        return True
    return normalized == base or normalized.startswith(base + "/")


def _entry_routes(route: str, sibling_routes: list[str]) -> list[str]:
    """Full routes to test: the method route, and it under sibling prefixes.

    The index does not resolve a class-level ``@RequestMapping`` prefix, so a
    method route may be a suffix. Every other route recorded in the same file
    is offered as a possible prefix — the same accommodation the dynamic probe
    makes.
    """

    bare = "/" + route.strip("/")
    routes = {bare}
    for prefix in sibling_routes:
        prefix = (prefix or "").strip()
        if not prefix or prefix == route:
            continue
        joined = "/" + "/".join(
            part for part in (prefix.strip("/"), route.strip("/")) if part
        )
        routes.add(joined)
    return sorted(routes)


def _is_sensitive(routes: list[str], symbol: str, path: str, sink_paths: set[str]) -> bool:
    if path in sink_paths:
        return True
    haystack = (" ".join(routes) + " " + symbol).lower()
    return any(marker in haystack for marker in _SENSITIVE_MARKERS)


def _declared_auth(path: str, permissions: list[dict[str, object]]) -> list[str]:
    """Auth annotations in the entrypoint's file (class-level covers methods).

    Matching by file rather than exact symbol is deliberately broad: a
    class-level ``@PreAuthorize`` guards every handler in it, and treating a
    file with any auth annotation as declared-protected errs toward *not*
    raising a structural candidate.
    """

    declared: set[str] = set()
    for record in permissions:
        if str(record.get("kind")) not in _AUTH_PERMISSION_KINDS:
            continue
        if str(record.get("path")) != path:
            continue
        declared.add(str(record.get("expression") or record.get("kind")))
    return sorted(value for value in declared if value)


def _looks_like_type(symbol: str) -> bool:
    """A class-qualified symbol (``com.x.FooController``) marks a class-level
    ``@RequestMapping`` container rather than a callable handler method — the
    real endpoints are the method-level entrypoints under it.
    """

    if "." not in symbol:
        return False
    last = symbol.rsplit(".", 1)[-1]
    return bool(last) and last[0].isupper()


def build_authz_topology(
    inventory: dict[str, object],
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Return ``(auth_bindings, candidates)`` for one inventory.

    Deterministic in content and order: bindings are ordered by entrypoint,
    candidates by fingerprint (via ``_candidate``), so two runs over one
    Snapshot agree byte for byte.
    """

    entrypoints = [
        record
        for record in _records(inventory, "entrypoints")
        if str(record.get("kind")) in _HTTP_ENTRYPOINT_KINDS and record.get("route")
    ]
    interceptors = _records(inventory, "interceptors")
    permissions = _records(inventory, "permissions")
    sink_paths = {str(record.get("path")) for record in _records(inventory, "sinks")}

    enforcing = [record for record in interceptors if record.get("enforces_auth")]
    permits = [
        record
        for record in interceptors
        if record.get("kind") == "security-chain" and not record.get("enforces_auth")
    ]
    # A global auth interceptor whose coverage set is unknown (no url patterns)
    # very likely guards everything; while one exists we cannot honestly claim
    # any endpoint is unprotected.
    unknown_global_guard = any(
        record.get("enforces_auth") and not record.get("url_patterns")
        for record in interceptors
    )

    routes_by_file: dict[str, list[str]] = {}
    for record in entrypoints:
        routes_by_file.setdefault(str(record.get("path")), []).append(
            str(record.get("route"))
        )

    bindings: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for record in sorted(
        entrypoints,
        key=lambda item: (
            str(item.get("path")).encode("utf-8"),
            int(item.get("line", 1)),
            str(item.get("route")),
        ),
    ):
        path = str(record.get("path"))
        route = str(record.get("route"))
        symbol = str(record.get("symbol") or "")
        siblings = [value for value in routes_by_file.get(path, []) if value != route]
        routes = _entry_routes(route, siblings)

        covered_by = sorted(
            {
                str(interceptor.get("class_name"))
                for interceptor in enforcing
                for pattern in interceptor.get("url_patterns") or []
                if any(url_pattern_matches(pattern, candidate) for candidate in routes)
            }
        )
        permit_hits = sorted(
            {
                str(interceptor.get("class_name"))
                for interceptor in permits
                for pattern in interceptor.get("url_patterns") or []
                if any(url_pattern_matches(pattern, candidate) for candidate in routes)
            }
        )
        declared = _declared_auth(path, permissions)
        sensitive = _is_sensitive(routes, symbol, path, sink_paths)
        # A class-level @RequestMapping is a container, not a callable endpoint:
        # its symbol is the class's qualified name, and the real handlers are the
        # method-level entrypoints under it, which carry the candidates.
        is_container = _looks_like_type(symbol)

        protected = bool(covered_by or declared)
        # A permitAll over an endpoint is an explicit pass, not protection.
        unprotected = not protected and not permit_hits and not unknown_global_guard
        reason = None
        if permit_hits and not covered_by:
            reason = "被 permitAll 之类的放行规则覆盖，未强制鉴权"
        elif not protected and unknown_global_guard:
            reason = "存在覆盖范围未知的全局鉴权拦截器，可达性交语义复核"
        elif unprotected:
            reason = "没有任何鉴权拦截器的 URL 模式覆盖该入口，且入口方法/类上没有鉴权注解"

        bindings.append(
            {
                "entrypoint_path": path,
                "entrypoint_line": int(record.get("line", 1)),
                "entrypoint_symbol": symbol or None,
                "route": route,
                "covered_by": covered_by,
                "declared_auth": declared,
                "unprotected": unprotected,
                "reason": reason,
            }
        )

        if not sensitive or declared or is_container:
            continue
        candidate = None
        if permit_hits and not covered_by:
            candidate = _authz_candidate(
                catalog=catalog,
                snapshot_sha256=snapshot_sha256,
                record=record,
                rule_id=_RULE_PERMITALL_SENSITIVE,
                cwe_ids=["CWE-862"],
                message=(
                    f"敏感入口 {symbol or route} 被显式放行规则（permitAll 之类）覆盖，"
                    "未强制任何鉴权即可访问。"
                ),
                preconditions=(
                    "攻击者无需认证或任何角色即可访问该入口；"
                    f"命中该入口的放行规则来自 {', '.join(permit_hits)}。"
                ),
            )
        elif unprotected:
            candidate = _authz_candidate(
                catalog=catalog,
                snapshot_sha256=snapshot_sha256,
                record=record,
                rule_id=_RULE_MISSING_AUTH,
                cwe_ids=["CWE-306"],
                message=(
                    f"敏感入口 {symbol or route} 没有被任何鉴权拦截器或鉴权注解保护，"
                    "疑似可被未认证用户直接访问。"
                ),
                preconditions=(
                    "索引中没有任何鉴权拦截器的 URL 模式覆盖该入口，"
                    "入口方法与所在类上也没有鉴权注解。"
                ),
            )
        if candidate is not None:
            candidates.append(candidate)

    return bindings, candidates


def _authz_candidate(
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
    record: dict[str, object],
    rule_id: str,
    cwe_ids: list[str],
    message: str,
    preconditions: str,
) -> dict[str, object] | None:
    try:
        location = catalog.location(
            str(record.get("path")),
            int(record.get("line", 1)),
            int(record.get("line", 1)),
            symbol=str(record.get("symbol") or "") or None,
            role="related",
        )
    except NormalizationError:
        return None
    candidate = _candidate(
        snapshot_sha256=snapshot_sha256,
        catalog=catalog,
        tool_name=AUTHZ_TOOL_NAME,
        rule_id=rule_id,
        message=message,
        locations=[location],
        severity="high",
        confidence="high",
        cwe_ids=cwe_ids,
        category="authorization",
        sink=None,
    )
    candidate["attack_preconditions"] = preconditions
    candidate["impact"] = (
        "未授权访问该入口可能泄露或篡改其背后的数据与操作，具体影响取决于该入口暴露的功能。"
    )
    candidate["recommended_verification"] = (
        "不携带任何认证凭证向该入口发起请求，若返回受保护数据（而非 401/403 或登录跳转），"
        "即证实其未授权可达。"
    )
    return candidate


def _records(inventory: dict[str, object], key: str) -> list[dict[str, object]]:
    values = inventory.get(key)
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]
