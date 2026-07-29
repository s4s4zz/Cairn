from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from cairn.benchmarks.contracts import (
    AuditRunExport,
    BenchmarkMetrics,
    BenchmarkResult,
    ClosedPlatformGoldManifest,
    CoverageStatus,
    FindingSeverity,
    MetricValue,
)


MAX_CONTRACT_BYTES = 8 * 1024 * 1024
ContractT = TypeVar("ContractT", bound=BaseModel)


class BenchmarkInputError(ValueError):
    """A safe-to-display benchmark input error that never embeds input data."""


def load_contract(path: Path, contract: type[ContractT]) -> ContractT:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BenchmarkInputError(f"cannot read contract: {path.name}") from exc
    if size > MAX_CONTRACT_BYTES:
        raise BenchmarkInputError(
            f"contract exceeds {MAX_CONTRACT_BYTES} bytes: {path.name}"
        )
    try:
        raw = path.read_text(encoding="utf-8")
        if len(raw.encode("utf-8")) > MAX_CONTRACT_BYTES:
            raise BenchmarkInputError(
                f"contract exceeds {MAX_CONTRACT_BYTES} bytes: {path.name}"
            )
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_keys)
    except UnicodeError as exc:
        raise BenchmarkInputError(f"contract is not UTF-8 JSON: {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise BenchmarkInputError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {path.name}"
        ) from exc
    except OSError as exc:
        raise BenchmarkInputError(f"cannot read contract: {path.name}") from exc
    except _DuplicateKeyError as exc:
        raise BenchmarkInputError(f"duplicate JSON object key: {path.name}") from exc

    try:
        return contract.model_validate(payload)
    except ValidationError as exc:
        locations = sorted(
            {".".join(str(part) for part in error["loc"]) for error in exc.errors()}
        )
        location_text = ", ".join(locations[:8]) or "root"
        raise BenchmarkInputError(
            f"contract validation failed at {location_text}: {path.name}"
        ) from exc


def evaluate_benchmark(
    gold: ClosedPlatformGoldManifest,
    audit_run: AuditRunExport,
) -> BenchmarkResult:
    samples = {
        sample.artifact.sha256: sample
        for sample in gold.samples
    }
    sample = samples.get(audit_run.sample_sha256)
    if sample is None:
        raise BenchmarkInputError(
            "AuditRun export sample_sha256 is not present in the gold manifest"
        )

    expected_entrypoints = {item.fingerprint for item in sample.entrypoints}
    actual_entrypoints = {item.fingerprint for item in audit_run.entrypoints}
    matched_entrypoints = expected_entrypoints & actual_entrypoints

    expected_findings = {item.fingerprint: item for item in sample.findings}
    actual_findings = {item.fingerprint: item for item in audit_run.findings}
    matched_findings = set(expected_findings) & set(actual_findings)
    critical_high = {
        fingerprint
        for fingerprint, finding in expected_findings.items()
        if finding.severity in {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
    }

    required_evidence_count = 0
    present_evidence_count = 0
    for fingerprint, gold_finding in expected_findings.items():
        required = set(gold_finding.required_evidence)
        required_evidence_count += len(required)
        actual = actual_findings.get(fingerprint)
        if actual is not None:
            present_evidence_count += len(required & set(actual.evidence))

    dynamic_targets = {
        fingerprint
        for fingerprint, finding in expected_findings.items()
        if finding.dynamic_reproducible
    }
    dynamically_reproduced = {
        fingerprint
        for fingerprint in dynamic_targets
        if (
            fingerprint in actual_findings
            and actual_findings[fingerprint].dynamic_reproduced
        )
    }

    expected_coverage = {item.fingerprint for item in sample.coverage_units}
    reported_coverage = {
        item.fingerprint: item.status
        for item in audit_run.coverage_units
    }
    coverage_gaps = {
        fingerprint
        for fingerprint in expected_coverage
        if reported_coverage.get(fingerprint) != CoverageStatus.COVERED
    }

    metrics = BenchmarkMetrics(
        entrypoint_recall=_metric(len(matched_entrypoints), len(expected_entrypoints)),
        critical_high_recall=_metric(
            len(critical_high & matched_findings),
            len(critical_high),
        ),
        precision=_metric(len(matched_findings), len(actual_findings)),
        evidence_completeness=_metric(
            present_evidence_count,
            required_evidence_count,
        ),
        dynamic_reproduction=_metric(
            len(dynamically_reproduced),
            len(dynamic_targets),
        ),
        coverage_gap=_metric(len(coverage_gaps), len(expected_coverage)),
    )
    return BenchmarkResult(
        schema_version="benchmark-result-v1",
        benchmark_id=gold.benchmark_id,
        dataset_visibility=gold.visibility,
        label_status=gold.label_status,
        gold_manifest_sha256=_contract_sha256(gold),
        audit_run_export_sha256=_contract_sha256(audit_run),
        audit_run_id=audit_run.audit_run_id,
        sample_sha256=audit_run.sample_sha256,
        metrics=metrics,
    )


def render_result(result: BenchmarkResult) -> str:
    return json.dumps(
        result.model_dump(mode="json"),
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    ) + "\n"


def _metric(numerator: int, denominator: int) -> MetricValue:
    return MetricValue(
        numerator=numerator,
        denominator=denominator,
        value=None if denominator == 0 else round(numerator / denominator, 6),
    )


def _contract_sha256(contract: BaseModel) -> str:
    canonical = json.dumps(
        contract.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError
        result[key] = value
    return result
