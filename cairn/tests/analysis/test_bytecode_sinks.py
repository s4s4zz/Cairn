from __future__ import annotations

from cairn.analysis.bytecode_sinks import bytecode_sink_candidates
from cairn.analysis.contracts import ProgramIndexV2


def _index(*calls: dict[str, object]) -> ProgramIndexV2:
    return ProgramIndexV2.model_validate(
        {
            "contract": "cairn-program-index-v2",
            "asm_version": "9.8",
            "target_java_version": 17,
            "components": [],
            "resources": [],
            "classes": [],
            "methods": [],
            "fields": [],
            "calls": list(calls),
            "field_accesses": [],
            "decompiled_views": [],
            "coverage_gaps": [],
            "classes_total": 0,
            "classes_parsed": 0,
        }
    )


def _call(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "logical_path": "application.war!/WEB-INF/classes/app/Action.class",
        "container_path": "application.war",
        "entry_path": "WEB-INF/classes/app/Action.class",
        "class_sha256": "a" * 64,
        "class_name": "app.Action",
        "method_name": "lookup",
        "method_descriptor": "(Ljava/lang/String;)V",
        "bytecode_offset": 17,
        "source_line": None,
        "opcode": 185,
        "edge_kind": "inferred",
        "target_owner": "java.sql.Statement",
        "target_name": "executeQuery",
        "target_descriptor": "(Ljava/lang/String;)Ljava/sql/ResultSet;",
        "interface": True,
        "callsite_name": None,
        "callsite_descriptor": None,
        "bootstrap_owner": None,
        "bootstrap_name": None,
        "bootstrap_descriptor": None,
    }
    payload.update(overrides)
    return payload


def test_symbolic_sql_call_becomes_an_honest_bytecode_candidate() -> None:
    candidates = bytecode_sink_candidates(
        _index(_call()),
        snapshot_sha256="b" * 64,
    )

    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.cwe_ids == ["CWE-89"]
    assert candidate.confidence.value == "low"
    assert "尚未确认" in candidate.message
    location = candidate.locations[0]
    assert location.origin_kind == "bytecode"
    assert location.entry_path == "WEB-INF/classes/app/Action.class"
    assert location.method_descriptor == "(Ljava/lang/String;)V"
    assert location.bytecode_offset == 17
    assert location.start_line is None


def test_invokedynamic_bootstrap_is_not_misreported_as_a_sink() -> None:
    dynamic = _call(
        opcode=186,
        edge_kind="inferred",
        target_owner=None,
        target_name=None,
        target_descriptor=None,
        interface=False,
        callsite_name="run",
        callsite_descriptor="()Ljava/lang/Runnable;",
        bootstrap_owner="java.lang.invoke.LambdaMetafactory",
        bootstrap_name="metafactory",
        bootstrap_descriptor="()V",
    )

    assert bytecode_sink_candidates(
        _index(dynamic),
        snapshot_sha256="b" * 64,
    ) == []


def test_candidate_identity_ignores_offset_and_decompiler_presentation() -> None:
    first = bytecode_sink_candidates(
        _index(_call(bytecode_offset=3)),
        snapshot_sha256="b" * 64,
    )[0]
    second = bytecode_sink_candidates(
        _index(_call(bytecode_offset=99)),
        snapshot_sha256="b" * 64,
    )[0]

    assert first.fingerprint == second.fingerprint
    assert first.root_cause_key == second.root_cause_key
