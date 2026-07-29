from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from cairn.benchmarks.contracts import (
    AuditRunExport,
    BenchmarkMetrics,
    BenchmarkResult,
    ClosedPlatformGoldManifest,
    ExportedFinding,
    GoldSample,
    MetricValue,
)
from cairn.benchmarks.runner import BenchmarkInputError, load_contract


SCHEMA_ROOT = Path(__file__).parents[2] / "src/cairn/benchmarks/schemas"


def test_gold_contract_rejects_unknown_fields_and_wrong_version(
    valid_gold_payload: dict[str, object],
) -> None:
    with_unknown = deepcopy(valid_gold_payload)
    with_unknown["decompiled_text"] = "must-not-be-accepted"
    with pytest.raises(ValidationError):
        ClosedPlatformGoldManifest.model_validate(with_unknown)

    wrong_version = deepcopy(valid_gold_payload)
    wrong_version["schema_version"] = "closed-platform-gold-v2"
    with pytest.raises(ValidationError):
        ClosedPlatformGoldManifest.model_validate(wrong_version)


def test_private_gold_requires_secret_and_key_references(
    valid_gold_payload: dict[str, object],
) -> None:
    private = deepcopy(valid_gold_payload)
    private["visibility"] = "private"
    private["label_status"] = "human-adjudicated"
    with pytest.raises(ValidationError, match="secret://"):
        ClosedPlatformGoldManifest.model_validate(private)

    sample = private["samples"][0]  # type: ignore[index]
    artifact = sample["artifact"]  # type: ignore[index]
    artifact["artifact_ref"] = "secret://benchmarks/sample-10"  # type: ignore[index]
    artifact["decryption_key_ref"] = "key://benchmarks/sample-10"  # type: ignore[index]
    for collection in ("entrypoints", "findings", "coverage_units"):
        for label in sample[collection]:  # type: ignore[index]
            for evidence in label["evidence"]:
                suffix = evidence["sha256"]
                evidence["evidence_ref"] = f"secret://benchmarks/evidence-{suffix}"
                evidence["decryption_key_ref"] = f"key://benchmarks/evidence-{suffix}"

    manifest = ClosedPlatformGoldManifest.model_validate(private)
    assert manifest.visibility.value == "private"


def test_private_gold_cannot_use_provisional_labels(
    valid_gold_payload: dict[str, object],
) -> None:
    private = deepcopy(valid_gold_payload)
    private["visibility"] = "private"

    with pytest.raises(ValidationError, match="human-adjudicated"):
        ClosedPlatformGoldManifest.model_validate(private)


def test_authorization_and_independent_annotation_are_mandatory(
    valid_gold_payload: dict[str, object],
) -> None:
    no_static = deepcopy(valid_gold_payload)
    no_static["authorization"]["permits_static_analysis"] = False  # type: ignore[index]
    with pytest.raises(ValidationError, match="permit static analysis"):
        ClosedPlatformGoldManifest.model_validate(no_static)

    same_reviewer = deepcopy(valid_gold_payload)
    protocol = same_reviewer["annotation_protocol"]  # type: ignore[assignment]
    protocol["reviewer_refs"] = [  # type: ignore[index]
        "record://reviewers/one",
        "record://reviewers/one",
    ]
    with pytest.raises(ValidationError, match="independent reviewers"):
        ClosedPlatformGoldManifest.model_validate(same_reviewer)


def test_export_contract_rejects_duplicates_and_unexplained_gaps(
    valid_audit_run_payload: dict[str, object],
) -> None:
    duplicate = deepcopy(valid_audit_run_payload)
    duplicate["findings"].append(deepcopy(duplicate["findings"][0]))  # type: ignore[index,union-attr]
    with pytest.raises(ValidationError, match="fingerprints must be unique"):
        AuditRunExport.model_validate(duplicate)

    unexplained = deepcopy(valid_audit_run_payload)
    unexplained["coverage_units"][1].pop("reason_code")  # type: ignore[index,union-attr]
    with pytest.raises(ValidationError, match="require reason_code"):
        AuditRunExport.model_validate(unexplained)


def test_loader_rejects_duplicate_json_keys_without_echoing_values(tmp_path: Path) -> None:
    marker = "PRIVATE-DECOMPILED-BODY-MUST-NOT-LEAK"
    path = tmp_path / "gold.json"
    path.write_text(
        '{"schema_version":"closed-platform-gold-v1",'
        f'"schema_version":"{marker}"}}',
        encoding="utf-8",
    )

    with pytest.raises(BenchmarkInputError) as caught:
        load_contract(path, ClosedPlatformGoldManifest)

    assert "duplicate JSON object key" in str(caught.value)
    assert marker not in str(caught.value)


def test_published_json_schemas_are_strict_objects() -> None:
    expected = {
        "closed-platform-gold-v1.schema.json",
        "audit-run-export-v1.schema.json",
        "benchmark-result-v1.schema.json",
    }
    paths = set(SCHEMA_ROOT.glob("*.json"))
    assert {path.name for path in paths} == expected

    for path in paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert schema["$schema"].endswith("2020-12/schema")
        _assert_object_nodes_forbid_extras(schema)


def test_published_schema_required_fields_match_runtime_models() -> None:
    gold = json.loads(
        (SCHEMA_ROOT / "closed-platform-gold-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    audit_run = json.loads(
        (SCHEMA_ROOT / "audit-run-export-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    result = json.loads(
        (SCHEMA_ROOT / "benchmark-result-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert set(gold["required"]) == _required_fields(ClosedPlatformGoldManifest)
    assert set(gold["$defs"]["sample"]["required"]) == _required_fields(GoldSample)
    assert set(audit_run["required"]) == _required_fields(AuditRunExport)
    assert set(audit_run["$defs"]["finding"]["required"]) == _required_fields(
        ExportedFinding
    )
    assert set(result["required"]) == _required_fields(BenchmarkResult)
    assert set(result["properties"]["metrics"]["required"]) == _required_fields(
        BenchmarkMetrics
    )
    assert set(result["$defs"]["metric"]["required"]) == _required_fields(
        MetricValue
    )

    for schema in (gold, audit_run, result):
        invariants = schema.get("x-cairn-runtime-invariants")
        assert isinstance(invariants, list)
        assert invariants


def test_runtime_rejects_collections_and_metric_values_omitted_from_schema(
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    for field in ("entrypoints", "findings", "coverage_units"):
        gold = deepcopy(valid_gold_payload)
        gold["samples"][0].pop(field)  # type: ignore[index,union-attr]
        with pytest.raises(ValidationError):
            ClosedPlatformGoldManifest.model_validate(gold)

        audit_run = deepcopy(valid_audit_run_payload)
        audit_run.pop(field)
        with pytest.raises(ValidationError):
            AuditRunExport.model_validate(audit_run)

    no_evidence = deepcopy(valid_audit_run_payload)
    no_evidence["findings"][0].pop("evidence")  # type: ignore[index,union-attr]
    with pytest.raises(ValidationError):
        AuditRunExport.model_validate(no_evidence)

    with pytest.raises(ValidationError):
        MetricValue.model_validate({"numerator": 0, "denominator": 0})


def test_result_contract_rejects_unknown_metrics() -> None:
    payload = {
        "schema_version": "benchmark-result-v1",
        "benchmark_id": "benchmark",
        "dataset_visibility": "synthetic",
        "label_status": "provisional",
        "gold_manifest_sha256": "1" * 64,
        "audit_run_export_sha256": "2" * 64,
        "audit_run_id": "run-1",
        "sample_sha256": "3" * 64,
        "metrics": {
            name: {"numerator": 0, "denominator": 0, "value": None}
            for name in (
                "entrypoint_recall",
                "critical_high_recall",
                "precision",
                "evidence_completeness",
                "dynamic_reproduction",
                "coverage_gap",
            )
        },
    }
    payload["metrics"]["rule_count"] = 12
    with pytest.raises(ValidationError):
        BenchmarkResult.model_validate(payload)


def _assert_object_nodes_forbid_extras(value: object) -> None:
    if isinstance(value, dict):
        if value.get("type") == "object":
            assert value.get("additionalProperties") is False
        for child in value.values():
            _assert_object_nodes_forbid_extras(child)
    elif isinstance(value, list):
        for child in value:
            _assert_object_nodes_forbid_extras(child)


def _required_fields(model: type[BaseModel]) -> set[str]:
    return {
        name
        for name, field in model.model_fields.items()
        if field.is_required()
    }
