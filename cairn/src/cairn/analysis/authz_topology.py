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

from cairn.analysis.contracts import CodeLocationV2, ProgramIndexV2
from cairn.analysis.fingerprints import candidate_identity, normalize_cwe_ids
from cairn.analysis.normalizers import NormalizationError, SourceCatalog, _candidate
from cairn.analysis.webxml import parse_descriptor_content


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


def _classify(
    routes: list[str],
    enforcing: list[dict[str, object]],
    permits: list[dict[str, object]],
    has_declared_auth: bool,
    unknown_global_guard: bool,
) -> tuple[list[str], list[str], bool, str | None]:
    """Shared structural classification of one endpoint's routes (图二).

    Source and bytecode paths differ only in how they derive routes and build
    candidates — not in how coverage is judged — so that judgement lives here.
    Returns ``(covered_by, permit_hits, unprotected, reason)``.
    """

    def _hits(interceptors: list[dict[str, object]]) -> tuple[list[str], list[str]]:
        specific: set[str] = set()
        catch_all: set[str] = set()
        for interceptor in interceptors:
            for pattern in interceptor.get("url_patterns") or []:
                if any(url_pattern_matches(pattern, candidate) for candidate in routes):
                    bucket = catch_all if pattern.strip() in {"/", "/*", "/**"} else specific
                    bucket.add(str(interceptor.get("class_name")))
        return sorted(specific), sorted(catch_all)

    enforce_specific, enforce_catch_all = _hits(enforcing)
    permit_specific, permit_catch_all = _hits(permits)
    # A specific rule wins over a catch-all (anyRequest / `/*`): a permitAll on
    # /admin/** is an explicit pass even when anyRequest().authenticated() would
    # also match. This is the one slice of Spring Security precedence the regex
    # tier models; full matcher ordering needs an AST.
    if enforce_specific:
        covered_by, permit_hits = enforce_specific, []
    elif permit_specific:
        covered_by, permit_hits = [], permit_specific
    elif enforce_catch_all:
        covered_by, permit_hits = enforce_catch_all, []
    elif permit_catch_all:
        covered_by, permit_hits = [], permit_catch_all
    else:
        covered_by, permit_hits = [], []
    protected = bool(covered_by or has_declared_auth)
    unprotected = not protected and not permit_hits and not unknown_global_guard
    reason = None
    if permit_hits and not covered_by:
        reason = "被 permitAll 之类的放行规则覆盖，未强制鉴权"
    elif not protected and unknown_global_guard:
        reason = "存在覆盖范围未知的全局鉴权拦截器，可达性交语义复核"
    elif unprotected:
        reason = "没有任何鉴权拦截器的 URL 模式覆盖该入口，且入口方法/类上没有鉴权注解"
    return covered_by, permit_hits, unprotected, reason


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

        declared = _declared_auth(path, permissions)
        covered_by, permit_hits, unprotected, reason = _classify(
            routes, enforcing, permits, bool(declared), unknown_global_guard
        )
        sensitive = _is_sensitive(routes, symbol, path, sink_paths)
        # A class-level @RequestMapping is a container, not a callable endpoint:
        # its symbol is the class's qualified name; the method-level entrypoints
        # under it carry the candidates.
        is_container = _looks_like_type(symbol)

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


# --- bytecode path (图二 v2) --------------------------------------------------

_MAPPING_ANNOTATIONS = (
    "GetMapping",
    "PostMapping",
    "PutMapping",
    "DeleteMapping",
    "PatchMapping",
    "RequestMapping",
)
_AUTH_ANNOTATIONS = ("PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed")
_CONTROLLER_ANNOTATIONS = ("Controller", "RestController")
_BC_FILTER_SUPERTYPES = frozenset(
    {
        "Filter",
        "OncePerRequestFilter",
        "GenericFilterBean",
        "HttpFilter",
        "DelegatingFilterProxy",
        "AbstractAuthenticationProcessingFilter",
    }
)
_BC_INTERCEPTOR_SUPERTYPES = frozenset(
    {
        "HandlerInterceptor",
        "AsyncHandlerInterceptor",
        "WebRequestInterceptor",
        "HandlerInterceptorAdapter",
    }
)
_BC_SECURITY_CHAIN_SUPERTYPES = frozenset({"WebSecurityConfigurerAdapter"})
_BC_AUTH_MARKERS = (
    "auth",
    "security",
    "login",
    "token",
    "jwt",
    "sso",
    "permission",
    "access",
    "session",
    "principal",
    "oauth",
    "saml",
    "credential",
    "guard",
    "shiro",
    "satoken",
)


def _simple_name(descriptor: str) -> str:
    """`Lorg/springframework/.../GetMapping;` -> `GetMapping`."""

    inner = descriptor.strip()
    if inner.startswith("L") and inner.endswith(";"):
        inner = inner[1:-1]
    inner = inner.rsplit("/", 1)[-1]
    return inner.rsplit("$", 1)[-1]


def _simple_from_dotted(name: object) -> str:
    return str(name or "").rsplit(".", 1)[-1]


def _first_str(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            if isinstance(item, str):
                return item
    return None


def _members_by_simple(details: object) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for detail in details or []:
        result[_simple_name(detail.descriptor)] = dict(detail.members)
    return result


def _mapping_route(simples: dict[str, dict[str, object]]) -> str | None:
    for name in _MAPPING_ANNOTATIONS:
        members = simples.get(name)
        if members is not None:
            route = _first_str(members.get("value")) or _first_str(members.get("path"))
            return route or ""
    return None


def _auth_expressions(simples: dict[str, dict[str, object]]) -> list[str]:
    exprs: list[str] = []
    for name in _AUTH_ANNOTATIONS:
        members = simples.get(name)
        if members is not None:
            exprs.append(_first_str(members.get("value")) or name)
    return exprs


def _interceptor_kind(super_name: object, interfaces: object) -> str | None:
    names = {_simple_from_dotted(super_name)} | {
        _simple_from_dotted(item) for item in (interfaces or [])
    }
    if names & _BC_FILTER_SUPERTYPES:
        return "servlet-filter"
    if names & _BC_INTERCEPTOR_SUPERTYPES:
        return "spring-interceptor"
    if names & _BC_SECURITY_CHAIN_SUPERTYPES:
        return "security-chain"
    return None


def _webfilter_patterns(members: dict[str, object]) -> list[str]:
    raw = members.get("urlPatterns") or members.get("value")
    if isinstance(raw, str):
        return [raw]
    if isinstance(raw, list):
        return [item for item in raw if isinstance(item, str)]
    return []


def _order_value(members: dict[str, object] | None) -> int | None:
    if not members:
        return None
    value = _first_str(members.get("value"))
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _join_route(prefix: str, route: str) -> str:
    parts = [
        segment.strip("/")
        for segment in (prefix, route)
        if segment and segment.strip("/")
    ]
    return "/" + "/".join(parts) if parts else "/"


def _bytecode_sink_classes(index: ProgramIndexV2, snapshot_sha256: str) -> set[str]:
    from cairn.analysis.bytecode_sinks import bytecode_sink_candidates

    classes: set[str] = set()
    for candidate in bytecode_sink_candidates(index, snapshot_sha256=snapshot_sha256):
        for location in candidate.locations:
            name = getattr(location, "class_name", None)
            if name:
                classes.add(str(name))
    return classes


def build_authz_topology_bytecode(
    index: ProgramIndexV2,
    *,
    descriptors: object = (),
    snapshot_sha256: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """``(auth_bindings, candidates)`` for a bytecode artifact (图二 v2).

    Same structural judgement as the source path (:func:`_classify`), but
    endpoints, interceptors and permissions are derived from the bytecode
    index's annotation values and supertypes plus web.xml text, and candidates
    carry a ``CodeLocationV2`` rather than a source location. Class-level
    ``@RequestMapping`` never becomes an endpoint here (only methods do), so no
    container de-duplication is needed.
    """

    interceptors: list[dict[str, object]] = []
    class_prefix: dict[str, str] = {}
    permissions_by_class: dict[str, list[str]] = {}
    class_by_name: dict[str, object] = {}

    for record in index.classes:
        class_by_name[record.class_name] = record
        simples = _members_by_simple(record.annotation_details)
        request_mapping = simples.get("RequestMapping")
        if request_mapping is not None:
            class_prefix[record.class_name] = (
                _first_str(request_mapping.get("value"))
                or _first_str(request_mapping.get("path"))
                or ""
            )
        class_exprs = _auth_expressions(simples)
        if class_exprs:
            permissions_by_class.setdefault(record.class_name, []).extend(class_exprs)
        kind = _interceptor_kind(record.super_name, record.interfaces)
        if kind is not None:
            webfilter = simples.get("WebFilter")
            lowered = record.class_name.lower()
            interceptors.append(
                {
                    "kind": kind,
                    "class_name": record.class_name,
                    "url_patterns": sorted(set(_webfilter_patterns(webfilter)))
                    if webfilter
                    else [],
                    "order": _order_value(simples.get("Order")),
                    "enforces_auth": kind == "security-chain"
                    or any(marker in lowered for marker in _BC_AUTH_MARKERS),
                    "source": "annotation",
                }
            )

    for resource in descriptors or ():
        content = getattr(resource, "content", None)
        if content:
            interceptors.extend(
                parse_descriptor_content(
                    content, getattr(resource, "logical_path", "web.xml")
                )
            )

    endpoints: list[dict[str, object]] = []
    for method in index.methods:
        simples = _members_by_simple(method.annotation_details)
        method_exprs = _auth_expressions(simples)
        if method_exprs:
            permissions_by_class.setdefault(method.class_name, []).extend(method_exprs)
        route = _mapping_route(simples)
        if route is None:
            continue
        record = class_by_name.get(method.class_name)
        endpoints.append(
            {
                "class_name": method.class_name,
                "method_name": method.method_name,
                "method_descriptor": method.method_descriptor,
                "route": _join_route(class_prefix.get(method.class_name, ""), route),
                "entry_path": getattr(record, "entry_path", None),
                "container_path": getattr(record, "container_path", None),
                "source_line": method.start_line,
            }
        )

    sink_classes = _bytecode_sink_classes(index, snapshot_sha256)
    enforcing = [item for item in interceptors if item.get("enforces_auth")]
    permits = [
        item
        for item in interceptors
        if item.get("kind") == "security-chain" and not item.get("enforces_auth")
    ]
    unknown_global_guard = any(
        item.get("enforces_auth") and not item.get("url_patterns")
        for item in interceptors
    )
    routes_by_class: dict[str, list[str]] = {}
    for endpoint in endpoints:
        routes_by_class.setdefault(str(endpoint["class_name"]), []).append(
            str(endpoint["route"])
        )

    bindings: list[dict[str, object]] = []
    candidates: list[dict[str, object]] = []
    for endpoint in sorted(
        endpoints,
        key=lambda item: (
            str(item["class_name"]).encode("utf-8"),
            str(item["route"]),
            str(item["method_name"]),
        ),
    ):
        class_name = str(endpoint["class_name"])
        route = str(endpoint["route"])
        symbol = f"{class_name}.{endpoint['method_name']}"
        siblings = [value for value in routes_by_class.get(class_name, []) if value != route]
        routes = _entry_routes(route, siblings)
        declared = sorted(set(permissions_by_class.get(class_name, [])))
        covered_by, permit_hits, unprotected, reason = _classify(
            routes, enforcing, permits, bool(declared), unknown_global_guard
        )
        sensitive = class_name in sink_classes or any(
            marker in (route + " " + symbol).lower() for marker in _SENSITIVE_MARKERS
        )
        bindings.append(
            {
                "entrypoint_path": str(endpoint.get("entry_path") or class_name),
                "entrypoint_line": int(endpoint.get("source_line") or 1),
                "entrypoint_symbol": symbol,
                "route": route,
                "covered_by": covered_by,
                "declared_auth": declared,
                "unprotected": unprotected,
                "reason": reason,
            }
        )
        if not sensitive or declared:
            continue
        candidate = None
        if permit_hits and not covered_by:
            candidate = _bytecode_authz_candidate(
                snapshot_sha256=snapshot_sha256,
                endpoint=endpoint,
                rule_id=_RULE_PERMITALL_SENSITIVE,
                cwe_ids=["CWE-862"],
                message=(
                    f"敏感入口 {symbol} 被显式放行规则（permitAll 之类）覆盖，"
                    "未强制任何鉴权即可访问。"
                ),
                preconditions=(
                    "攻击者无需认证或任何角色即可访问该入口；"
                    f"命中该入口的放行规则来自 {', '.join(permit_hits)}。"
                ),
            )
        elif unprotected:
            candidate = _bytecode_authz_candidate(
                snapshot_sha256=snapshot_sha256,
                endpoint=endpoint,
                rule_id=_RULE_MISSING_AUTH,
                cwe_ids=["CWE-306"],
                message=(
                    f"敏感入口 {symbol} 没有被任何鉴权拦截器或鉴权注解保护，"
                    "疑似可被未认证用户直接访问。"
                ),
                preconditions=(
                    "字节码索引中没有任何鉴权拦截器的 URL 模式覆盖该入口，"
                    "入口方法与所在类上也没有鉴权注解。"
                ),
            )
        if candidate is not None:
            candidates.append(candidate)
    return bindings, candidates


def _bytecode_authz_candidate(
    *,
    snapshot_sha256: str,
    endpoint: dict[str, object],
    rule_id: str,
    cwe_ids: list[str],
    message: str,
    preconditions: str,
) -> dict[str, object] | None:
    try:
        location = CodeLocationV2(
            origin_kind="bytecode",
            container_path=endpoint.get("container_path"),
            entry_path=endpoint.get("entry_path"),
            class_name=str(endpoint["class_name"]),
            method_name=str(endpoint["method_name"]),
            method_descriptor=str(endpoint["method_descriptor"]),
            symbol=f"{endpoint['class_name']}.{endpoint['method_name']}",
            role="related",
        ).model_dump(mode="json")
    except ValueError:
        return None
    normalized_cwes = normalize_cwe_ids(cwe_ids)
    fingerprint, root_cause_key = candidate_identity(
        snapshot_sha256=snapshot_sha256,
        rule_id=rule_id,
        cwe_ids=normalized_cwes,
        category="authorization",
        primary_location=location,
        sink=None,
        tool_name=AUTHZ_TOOL_NAME,
    )
    return {
        "rule_id": rule_id,
        "cwe_ids": normalized_cwes,
        "category": "authorization",
        "severity": "high",
        "confidence": "high",
        "message": message,
        "locations": [location],
        "sink": None,
        "fingerprint": fingerprint,
        "root_cause_key": root_cause_key,
        "discovered_by": [AUTHZ_TOOL_NAME],
        "source_rules": [rule_id],
        "attack_preconditions": preconditions,
        "impact": (
            "未授权访问该入口可能泄露或篡改其背后的数据与操作，具体影响取决于该入口暴露的功能。"
        ),
        "recommended_verification": (
            "不携带任何认证凭证向该入口发起请求，若返回受保护数据（而非 401/403 或登录跳转），"
            "即证实其未授权可达。"
        ),
    }
