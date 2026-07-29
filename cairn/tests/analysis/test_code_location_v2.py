from uuid import uuid4

from pydantic import ValidationError
import pytest

from cairn.analysis.contracts import (
    CandidateFinding,
    CodeCallChainStepV2,
    CodeLocationV2,
)


def _candidate(location: dict[str, object]) -> CandidateFinding:
    return CandidateFinding.model_validate(
        {
            "rule_id": "bytecode-sql-sink",
            "cwe_ids": ["CWE-89"],
            "category": "sql-injection",
            "severity": "high",
            "confidence": "high",
            "message": "Request data reaches Statement.execute.",
            "locations": [location],
            "sink": "java.sql.Statement.execute",
            "fingerprint": "a" * 64,
            "root_cause_key": "b" * 64,
            "discovered_by": ["asm-index"],
            "source_rules": ["bytecode-sql-sink"],
        }
    )


def _bytecode_location(**overrides: object) -> dict[str, object]:
    location: dict[str, object] = {
        "origin_kind": "bytecode",
        "container_path": "sample.war",
        "entry_path": "WEB-INF/lib/app.jar!/demo/Action.class",
        "class_name": "demo.Action",
        "method_name": "execute",
        "method_descriptor": "(Ljava/lang/String;)V",
        "bytecode_offset": 18,
        "source_path": None,
        "start_line": None,
        "end_line": None,
        "decompiled_artifact_id": None,
        "decompiled_start_line": None,
        "decompiled_end_line": None,
        "symbol": "demo.Action.execute",
        "role": "sink",
    }
    location.update(overrides)
    return location


def test_v1_candidate_location_serialization_is_unchanged() -> None:
    candidate = _candidate(
        {
            "path": "src/main/java/demo/Action.java",
            "start_line": 12,
            "end_line": 12,
            "symbol": "demo.Action.execute",
            "role": "sink",
        }
    )

    assert candidate.model_dump(mode="json")["locations"] == [
        {
            "path": "src/main/java/demo/Action.java",
            "start_line": 12,
            "end_line": 12,
            "start_column": None,
            "end_column": None,
            "symbol": "demo.Action.execute",
            "role": "sink",
        }
    ]


def test_bytecode_location_without_source_lines_round_trips_as_v2() -> None:
    candidate = _candidate(_bytecode_location())

    location = candidate.locations[0]
    assert isinstance(location, CodeLocationV2)
    assert location.start_line is None
    assert location.bytecode_offset == 18
    assert candidate.model_dump(mode="json")["locations"][0]["origin_kind"] == (
        "bytecode"
    )


def test_decompiled_lines_are_separate_from_source_lines() -> None:
    artifact_id = uuid4()
    location = CodeLocationV2.model_validate(
        _bytecode_location(
            origin_kind="decompiled",
            decompiled_artifact_id=str(artifact_id),
            decompiled_start_line=31,
            decompiled_end_line=34,
        )
    )

    assert location.start_line is None
    assert location.end_line is None
    assert location.decompiled_artifact_id == artifact_id
    assert (location.decompiled_start_line, location.decompiled_end_line) == (31, 34)


@pytest.mark.parametrize(
    "entry_path",
    [
        "/demo/Action.class",
        "demo/../Action.class",
        "app.jar!/../demo/Action.class",
        "app.jar!/",
        "demo\\Action.class",
        "demo/Action\x7f.class",
        "demo/cafe\u0301.class",
    ],
)
def test_code_path_rejects_noncanonical_archive_entries(entry_path: str) -> None:
    with pytest.raises(ValidationError):
        CodeLocationV2.model_validate(_bytecode_location(entry_path=entry_path))


@pytest.mark.parametrize(
    "overrides",
    [
        {"end_line": 10},
        {"method_descriptor": None},
        {"method_name": None, "method_descriptor": None, "bytecode_offset": 1},
        {"entry_path": None},
        {"class_name": None},
        {"decompiled_start_line": 4, "decompiled_end_line": 5},
    ],
)
def test_incomplete_bytecode_location_is_rejected(
    overrides: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        CodeLocationV2.model_validate(_bytecode_location(**overrides))


def test_v2_call_chain_step_requires_a_method_identity() -> None:
    with pytest.raises(ValidationError):
        CodeCallChainStepV2.model_validate(
            _bytecode_location(
                method_name=None,
                method_descriptor=None,
                bytecode_offset=None,
                role="sink",
                note="invokevirtual",
            )
        )
