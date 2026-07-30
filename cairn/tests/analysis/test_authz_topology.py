"""Authorization topology (图二): indexer, web.xml, matching, candidates."""

from __future__ import annotations

from pathlib import Path

from cairn.analysis.authz_topology import build_authz_topology, url_pattern_matches
from cairn.analysis.indexer import build_inventory
from cairn.analysis.normalizers import SourceCatalog
from cairn.analysis.tree_hash import source_tree_sha256
from cairn.analysis.webxml import parse_web_descriptors


_ADMIN_CTRL = """package com.acme.admin;
@RestController
@RequestMapping("/admin")
public class AdminController {
  @GetMapping("/delete")
  public String delete(@RequestParam String id){ return jdbc.queryForObject("select * from t where id="+id); }
}
"""

_WEB_XML_AUTH = (
    "<web-app><filter><filter-name>af</filter-name>"
    "<filter-class>com.acme.AuthFilter</filter-class></filter>"
    "<filter-mapping><filter-name>af</filter-name>"
    "<url-pattern>/admin/*</url-pattern><dispatcher>REQUEST</dispatcher>"
    "</filter-mapping></web-app>"
)


def _write(root: Path, files: dict[str, str]) -> None:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")


def _topology(root: Path):
    inventory = build_inventory(root)
    return build_authz_topology(
        inventory,
        catalog=SourceCatalog(root),
        snapshot_sha256=source_tree_sha256(root),
    )


# --- indexer: interceptor detection -------------------------------------------


def test_indexer_detects_filter_supertype_and_patterns(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "SecFilter.java": (
                "package a;\n"
                '@WebFilter(urlPatterns={"/x/*","/y/*"})\n'
                "public class SecurityFilter extends OncePerRequestFilter {}\n"
            )
        },
    )
    interceptors = build_inventory(tmp_path)["interceptors"]
    record = next(i for i in interceptors if i["class_name"] == "a.SecurityFilter")
    assert record["kind"] == "servlet-filter"
    assert record["enforces_auth"] is True
    assert record["url_patterns"] == ["/x/*", "/y/*"]


def test_indexer_business_interceptor_is_not_auth(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "L.java": (
                "package a;\n"
                "public class LoggingInterceptor implements HandlerInterceptor {}\n"
            )
        },
    )
    interceptors = build_inventory(tmp_path)["interceptors"]
    record = next(i for i in interceptors if i["class_name"] == "a.LoggingInterceptor")
    assert record["kind"] == "spring-interceptor"
    assert record["enforces_auth"] is False


# --- web.xml / spring-security XML ---------------------------------------------


def test_webxml_filter_mapping(tmp_path: Path) -> None:
    _write(tmp_path, {"WEB-INF/web.xml": _WEB_XML_AUTH})
    records = parse_web_descriptors(tmp_path)
    assert len(records) == 1
    assert records[0]["class_name"] == "com.acme.AuthFilter"
    assert records[0]["url_patterns"] == ["/admin/*"]
    assert records[0]["dispatcher_types"] == ["REQUEST"]
    assert records[0]["enforces_auth"] is True


def test_spring_security_permitall_is_not_enforcing(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "s.xml": (
                '<b:beans xmlns:b="http://www.springframework.org/schema/beans" '
                'xmlns="http://www.springframework.org/schema/security">'
                '<http><intercept-url pattern="/admin/**" access="permitAll"/>'
                '<intercept-url pattern="/api/**" access="hasRole(\'USER\')"/>'
                "</http></b:beans>"
            )
        },
    )
    records = {r["url_patterns"][0]: r for r in parse_web_descriptors(tmp_path)}
    assert records["/admin/**"]["enforces_auth"] is False
    assert records["/api/**"]["enforces_auth"] is True


# --- url pattern matching ------------------------------------------------------


def test_url_pattern_matching() -> None:
    assert url_pattern_matches("/admin/*", "/admin/delete")
    assert url_pattern_matches("/admin/**", "/admin/a/b")
    assert url_pattern_matches("/admin/*", "/admin")
    assert url_pattern_matches("*.do", "/x/y.do")
    assert url_pattern_matches("/*", "/anything")
    assert not url_pattern_matches("/user/*", "/admin/x")
    assert not url_pattern_matches("/admin", "/administrator")


# --- topology + structural candidates -----------------------------------------


def test_unprotected_sensitive_endpoint_yields_306(tmp_path: Path) -> None:
    _write(tmp_path, {"AdminController.java": _ADMIN_CTRL})
    _, candidates = _topology(tmp_path)
    assert [c["cwe_ids"][0] for c in candidates] == ["CWE-306"]
    assert candidates[0]["category"] == "authorization"
    assert candidates[0]["confidence"] == "high"


def test_auth_filter_coverage_suppresses_candidate(tmp_path: Path) -> None:
    _write(tmp_path, {"AdminController.java": _ADMIN_CTRL, "WEB-INF/web.xml": _WEB_XML_AUTH})
    bindings, candidates = _topology(tmp_path)
    assert candidates == []
    assert all(not b["unprotected"] for b in bindings)
    assert any("com.acme.AuthFilter" in b["covered_by"] for b in bindings)


def test_permitall_over_sensitive_yields_862(tmp_path: Path) -> None:
    _write(
        tmp_path,
        {
            "AdminController.java": _ADMIN_CTRL,
            "s.xml": (
                '<b:beans xmlns:b="http://www.springframework.org/schema/beans" '
                'xmlns="http://www.springframework.org/schema/security">'
                '<http><intercept-url pattern="/admin/**" access="permitAll"/>'
                "</http></b:beans>"
            ),
        },
    )
    _, candidates = _topology(tmp_path)
    assert [c["cwe_ids"][0] for c in candidates] == ["CWE-862"]


def test_method_annotation_suppresses_candidate(tmp_path: Path) -> None:
    ctrl = _ADMIN_CTRL.replace(
        '  @GetMapping("/delete")',
        '  @PreAuthorize("hasRole(\'ADMIN\')")\n  @GetMapping("/delete")',
    )
    _write(tmp_path, {"AdminController.java": ctrl})
    _, candidates = _topology(tmp_path)
    assert candidates == []


def test_unknown_global_guard_suppresses_candidate(tmp_path: Path) -> None:
    # An auth filter with no URL patterns (unknown coverage) is very likely
    # global, so the platform declines to claim any endpoint is unprotected.
    _write(
        tmp_path,
        {
            "AdminController.java": _ADMIN_CTRL,
            "SecFilter.java": (
                "package a;\n"
                "public class SecurityFilter extends OncePerRequestFilter {}\n"
            ),
        },
    )
    _, candidates = _topology(tmp_path)
    assert candidates == []


def test_class_level_container_is_deduped(tmp_path: Path) -> None:
    _write(tmp_path, {"AdminController.java": _ADMIN_CTRL})
    _, candidates = _topology(tmp_path)
    assert [c["locations"][0]["symbol"] for c in candidates] == ["delete"]


def test_topology_is_reproducible(tmp_path: Path) -> None:
    _write(tmp_path, {"AdminController.java": _ADMIN_CTRL})
    bindings_a, candidates_a = _topology(tmp_path)
    bindings_b, candidates_b = _topology(tmp_path)
    assert [c["fingerprint"] for c in candidates_a] == [
        c["fingerprint"] for c in candidates_b
    ]
    assert bindings_a == bindings_b


# --- broker tool ---------------------------------------------------------------


def test_broker_describe_endpoint_authz(tmp_path: Path) -> None:
    from cairn.semantic.broker import ToolBroker

    _write(tmp_path, {"AdminController.java": _ADMIN_CTRL})
    broker = ToolBroker(tmp_path)
    result = broker.invoke("describe_endpoint_authz", {"route": "/admin", "symbol": None})
    assert any(binding["unprotected"] for binding in result["bindings"])


# --- unauthenticated probe -----------------------------------------------------


def test_unauthenticated_probe_confirms_open_endpoint() -> None:
    from cairn.dynamic.probes import ProbeRunner, ProbeTarget, _Response

    def caller(method, url, body, timeout):
        return _Response(status_code=200, body="<html>secret</html>", byte_count=19, elapsed_ms=5)

    target = ProbeTarget(finding_id="f1", category="authorization", route="admin")
    outcome = ProbeRunner("http://app", caller=caller).run(target)
    assert outcome.verdict == "confirmed"


def test_unauthenticated_probe_rejects_when_denied() -> None:
    from cairn.dynamic.probes import ProbeRunner, ProbeTarget, _Response

    def caller(method, url, body, timeout):
        return _Response(status_code=403, body="forbidden", byte_count=9, elapsed_ms=5)

    target = ProbeTarget(finding_id="f1", category="authorization", route="admin")
    outcome = ProbeRunner("http://app", caller=caller).run(target)
    assert outcome.verdict == "rejected"
