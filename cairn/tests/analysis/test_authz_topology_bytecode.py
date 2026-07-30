"""Bytecode-path authorization topology (图二 v2)."""

from __future__ import annotations

from cairn.analysis.authz_topology import build_authz_topology_bytecode
from cairn.analysis.contracts import (
    AnnotationDetail,
    BinaryResource,
    BytecodeClassRecord,
    BytecodeMethodRecord,
    CandidateFinding,
    ProgramIndexV2,
)


def _ann(simple: str, **members: object) -> AnnotationDetail:
    return AnnotationDetail(descriptor=f"Lorg/x/{simple};", members=members)


def _class(
    name: str,
    *,
    super_name: str = "java.lang.Object",
    interfaces: tuple[str, ...] = (),
    annotations: tuple[AnnotationDetail, ...] = (),
) -> BytecodeClassRecord:
    return BytecodeClassRecord(
        logical_path=f"{name}.class",
        entry_path=f"{name}.class",
        class_sha256="0" * 64,
        class_name=name,
        super_name=super_name,
        interfaces=list(interfaces),
        access=1,
        classfile_major=61,
        annotation_details=list(annotations),
    )


def _method(
    class_name: str,
    method_name: str,
    *,
    annotations: tuple[AnnotationDetail, ...] = (),
) -> BytecodeMethodRecord:
    return BytecodeMethodRecord(
        logical_path=f"{class_name}.class",
        entry_path=f"{class_name}.class",
        class_sha256="0" * 64,
        class_name=class_name,
        method_name=method_name,
        method_descriptor="()V",
        access=1,
        annotation_details=list(annotations),
        start_line=10,
        end_line=12,
    )


def _index(
    classes: list[BytecodeClassRecord], methods: list[BytecodeMethodRecord]
) -> ProgramIndexV2:
    return ProgramIndexV2(
        contract="cairn-program-index-v2",
        asm_version="9.8",
        target_java_version=17,
        components=[],
        resources=[],
        classes=classes,
        methods=methods,
        fields=[],
        calls=[],
        field_accesses=[],
        decompiled_views=[],
        coverage_gaps=[],
        classes_total=len(classes),
        classes_parsed=len(classes),
    )


def _web_resource(content: str) -> BinaryResource:
    return BinaryResource(
        logical_path="app.war!/WEB-INF/web.xml",
        container_path="app.war",
        entry_path="WEB-INF/web.xml",
        kind="deployment-descriptor",
        sha256="0" * 64,
        size_bytes=len(content),
        content=content,
    )


_ADMIN = _index(
    [_class("com.acme.AdminApi", annotations=(_ann("RequestMapping", value=["/admin"]),))],
    [_method("com.acme.AdminApi", "delete", annotations=(_ann("GetMapping", value=["/delete"]),))],
)


def test_bytecode_full_route_and_missing_auth() -> None:
    bindings, candidates = build_authz_topology_bytecode(
        _ADMIN, descriptors=[], snapshot_sha256="a" * 64
    )
    # Class-level @RequestMapping prefix joined to the method path — precision
    # the source path cannot reach.
    assert [b["route"] for b in bindings] == ["/admin/delete"]
    assert bindings[0]["unprotected"] is True
    assert [c["cwe_ids"][0] for c in candidates] == ["CWE-306"]
    assert candidates[0]["locations"][0]["origin_kind"] == "bytecode"
    CandidateFinding.model_validate(candidates[0])


def test_bytecode_webxml_filter_coverage_suppresses() -> None:
    webxml = (
        "<web-app><filter><filter-name>af</filter-name>"
        "<filter-class>com.acme.AuthFilter</filter-class></filter>"
        "<filter-mapping><filter-name>af</filter-name>"
        "<url-pattern>/admin/*</url-pattern></filter-mapping></web-app>"
    )
    bindings, candidates = build_authz_topology_bytecode(
        _ADMIN, descriptors=[_web_resource(webxml)], snapshot_sha256="a" * 64
    )
    assert candidates == []
    assert bindings[0]["unprotected"] is False
    assert "com.acme.AuthFilter" in bindings[0]["covered_by"]


def test_bytecode_permitall_yields_862() -> None:
    sec = (
        '<b:beans xmlns:b="http://www.springframework.org/schema/beans" '
        'xmlns="http://www.springframework.org/schema/security">'
        '<http><intercept-url pattern="/admin/**" access="permitAll"/></http></b:beans>'
    )
    resource = BinaryResource(
        logical_path="app.war!/WEB-INF/spring-security.xml",
        container_path="app.war",
        entry_path="WEB-INF/spring-security.xml",
        kind="xml",
        sha256="0" * 64,
        size_bytes=len(sec),
        content=sec,
    )
    _, candidates = build_authz_topology_bytecode(
        _ADMIN, descriptors=[resource], snapshot_sha256="a" * 64
    )
    assert [c["cwe_ids"][0] for c in candidates] == ["CWE-862"]


def test_bytecode_method_annotation_suppresses() -> None:
    index = _index(
        [_class("com.acme.AdminApi", annotations=(_ann("RequestMapping", value=["/admin"]),))],
        [
            _method(
                "com.acme.AdminApi",
                "delete",
                annotations=(
                    _ann("GetMapping", value=["/delete"]),
                    _ann("PreAuthorize", value="hasRole('ADMIN')"),
                ),
            )
        ],
    )
    _, candidates = build_authz_topology_bytecode(
        index, descriptors=[], snapshot_sha256="a" * 64
    )
    assert candidates == []


def test_bytecode_filter_supertype_recognized() -> None:
    index = _index(
        [
            _class("com.acme.AdminApi", annotations=(_ann("RequestMapping", value=["/admin"]),)),
            _class(
                "com.acme.SecurityFilter",
                super_name="org.springframework.web.filter.OncePerRequestFilter",
                annotations=(_ann("WebFilter", urlPatterns=["/admin/*"]),),
            ),
        ],
        [_method("com.acme.AdminApi", "delete", annotations=(_ann("GetMapping", value=["/delete"]),))],
    )
    _, candidates = build_authz_topology_bytecode(
        index, descriptors=[], snapshot_sha256="a" * 64
    )
    # The @WebFilter over /admin/* is an auth filter (name), so the endpoint is
    # covered and no structural candidate is raised.
    assert candidates == []


def test_bytecode_reproducible() -> None:
    a = build_authz_topology_bytecode(_ADMIN, descriptors=[], snapshot_sha256="a" * 64)
    b = build_authz_topology_bytecode(_ADMIN, descriptors=[], snapshot_sha256="a" * 64)
    assert [c["fingerprint"] for c in a[1]] == [c["fingerprint"] for c in b[1]]
    assert a[0] == b[0]
