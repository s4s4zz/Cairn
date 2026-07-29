from __future__ import annotations

from copy import deepcopy

from cairn.benchmarks.contracts import AuditRunExport, ClosedPlatformGoldManifest
from cairn.benchmarks.runner import evaluate_benchmark, render_result


def test_metrics_are_computed_from_gold_and_export(
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    result = evaluate_benchmark(
        ClosedPlatformGoldManifest.model_validate(valid_gold_payload),
        AuditRunExport.model_validate(valid_audit_run_payload),
    )

    assert result.dataset_visibility.value == "synthetic"
    assert result.label_status.value == "provisional"
    assert result.metrics.entrypoint_recall.model_dump() == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert result.metrics.critical_high_recall.model_dump() == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert result.metrics.precision.model_dump() == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert result.metrics.evidence_completeness.model_dump() == {
        "numerator": 2,
        "denominator": 6,
        "value": 0.333333,
    }
    assert result.metrics.dynamic_reproduction.model_dump() == {
        "numerator": 1,
        "denominator": 2,
        "value": 0.5,
    }
    assert result.metrics.coverage_gap.model_dump() == {
        "numerator": 2,
        "denominator": 3,
        "value": 0.666667,
    }


def test_zero_denominators_are_null(
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    sample = valid_gold_payload["samples"][0]  # type: ignore[index]
    sample["entrypoints"] = []
    sample["findings"] = []
    sample["coverage_units"] = []
    valid_audit_run_payload["entrypoints"] = []
    valid_audit_run_payload["findings"] = []
    valid_audit_run_payload["coverage_units"] = []

    result = evaluate_benchmark(
        ClosedPlatformGoldManifest.model_validate(valid_gold_payload),
        AuditRunExport.model_validate(valid_audit_run_payload),
    )

    for metric in result.metrics:
        value = getattr(result.metrics, metric[0])
        assert value.numerator == 0
        assert value.denominator == 0
        assert value.value is None


def test_semantically_reordered_inputs_render_identically(
    valid_gold_payload: dict[str, object],
    valid_audit_run_payload: dict[str, object],
) -> None:
    reversed_gold = deepcopy(valid_gold_payload)
    sample = reversed_gold["samples"][0]  # type: ignore[index]
    for field in ("entrypoints", "findings", "coverage_units"):
        sample[field].reverse()
    reversed_export = deepcopy(valid_audit_run_payload)
    for field in ("entrypoints", "findings", "coverage_units"):
        reversed_export[field].reverse()  # type: ignore[union-attr]

    first = evaluate_benchmark(
        ClosedPlatformGoldManifest.model_validate(valid_gold_payload),
        AuditRunExport.model_validate(valid_audit_run_payload),
    )
    second = evaluate_benchmark(
        ClosedPlatformGoldManifest.model_validate(reversed_gold),
        AuditRunExport.model_validate(reversed_export),
    )

    assert render_result(first) == render_result(second)
