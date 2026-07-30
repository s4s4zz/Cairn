"""Spring Security Java lambda DSL parsing (图二②)."""

from __future__ import annotations

import tempfile
from pathlib import Path

from cairn.analysis.authz_topology import build_authz_topology
from cairn.analysis.indexer import build_inventory
from cairn.analysis.normalizers import SourceCatalog
from cairn.analysis.security_dsl import parse_security_dsl
from cairn.analysis.tree_hash import source_tree_sha256


def _by_url(text: str) -> dict[str, dict[str, object]]:
    return {
        str(record["url_patterns"][0]): record
        for record in parse_security_dsl(text, "SecurityConfig.java")
    }


# --- parser units --------------------------------------------------------------


def test_matcher_hasrole_enforces() -> None:
    record = _by_url(
        'http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").hasRole("ADMIN"));'
    )["/admin/**"]
    assert record["enforces_auth"] is True
    assert record["kind"] == "security-chain"
    assert record["source"] == "java-config"


def test_permitall_not_enforcing() -> None:
    assert _by_url('a.requestMatchers("/public/**").permitAll();')["/public/**"][
        "enforces_auth"
    ] is False


def test_multiple_urls_in_one_matcher() -> None:
    assert set(_by_url('a.requestMatchers("/a", "/b").permitAll();')) == {"/a", "/b"}


def test_any_request() -> None:
    assert _by_url("a.anyRequest().authenticated();")["/**"]["enforces_auth"] is True


def test_ignoring_is_permit() -> None:
    assert _by_url('web.ignoring().requestMatchers("/static/**");')["/static/**"][
        "enforces_auth"
    ] is False


def test_http_method_argument_skipped() -> None:
    assert set(_by_url('a.requestMatchers(HttpMethod.GET, "/api/**").authenticated();')) == {
        "/api/**"
    }


def test_cross_line_chain() -> None:
    text = (
        "http.authorizeHttpRequests(auth -> auth\n"
        '        .requestMatchers("/admin/**")\n'
        '        .hasRole("ADMIN"));'
    )
    assert _by_url(text)["/admin/**"]["enforces_auth"] is True


def test_no_dsl_no_records() -> None:
    assert parse_security_dsl("public class Foo {}", "Foo.java") == []


# --- end-to-end through the authorization topology -----------------------------

_CTRL = """package com.acme.admin;
@RestController
@RequestMapping("/admin")
public class AdminController {
  @GetMapping("/delete")
  public String delete(@RequestParam String id){ return jdbc.queryForObject("select * from t where id="+id); }
}
"""


def _authz_cwes(security_config: str) -> list[str]:
    root = Path(tempfile.mkdtemp())
    (root / "AdminController.java").write_text(_CTRL)
    (root / "SecurityConfig.java").write_text(security_config)
    inventory = build_inventory(root)
    _, candidates = build_authz_topology(
        inventory, catalog=SourceCatalog(root), snapshot_sha256=source_tree_sha256(root)
    )
    return [c["cwe_ids"][0] for c in candidates]


def test_dsl_hasrole_covers_endpoint() -> None:
    sec = """package com.acme.config;
public class SecurityConfig {
  SecurityFilterChain chain(HttpSecurity http) {
    http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").hasRole("ADMIN").anyRequest().authenticated());
    return http.build();
  }
}
"""
    assert _authz_cwes(sec) == []


def test_dsl_permitall_wins_over_anyrequest() -> None:
    sec = """package com.acme.config;
public class SecurityConfig {
  SecurityFilterChain chain(HttpSecurity http) {
    http.authorizeHttpRequests(a -> a.requestMatchers("/admin/**").permitAll().anyRequest().authenticated());
    return http.build();
  }
}
"""
    assert _authz_cwes(sec) == ["CWE-862"]
