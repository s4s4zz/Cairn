from __future__ import annotations

import hashlib
from pathlib import Path

from cairn.benchmarks.contracts import (
    AuditRunExport,
    BenchmarkResult,
    ClosedPlatformGoldManifest,
)
from cairn.benchmarks.runner import evaluate_benchmark, load_contract, render_result

from .fixture_builder import build_fixture_archives


FIXTURE_ROOT = Path(__file__).parent / "fixtures"
BASELINE_ROOT = FIXTURE_ROOT / "baselines"
EVIDENCE_FILES = {
    "fixture://closed-platform/fixture-matrix": "fixture-matrix-v1.json",
    "fixture://closed-platform/web-xml": "web/WEB-INF/web.xml",
    "fixture://closed-platform/action-config": "web/WEB-INF/action-config.xml",
    "fixture://closed-platform/lookup-jsp": "web/views/lookup.jsp",
    "fixture://closed-platform/platform-request": (
        "src/org/cairn/fixture/PlatformRequest.java"
    ),
    "fixture://closed-platform/platform-sql": "src/org/cairn/fixture/PlatformSql.java",
    "fixture://closed-platform/synthetic-action": (
        "src/org/cairn/fixture/SyntheticAction.java"
    ),
    "fixture://closed-platform/authorization-guard": (
        "src/org/cairn/fixture/AuthorizationGuard.java"
    ),
    "fixture://closed-platform/tenant-guard": (
        "src/org/cairn/fixture/TenantGuard.java"
    ),
}


def test_committed_synthetic_baseline_is_reproducible(tmp_path: Path) -> None:
    gold = load_contract(
        BASELINE_ROOT / "synthetic-gold-v1.json",
        ClosedPlatformGoldManifest,
    )
    audit_run = load_contract(
        BASELINE_ROOT / "synthetic-export-v1.json",
        AuditRunExport,
    )
    expected = load_contract(
        BASELINE_ROOT / "synthetic-result-v1.json",
        BenchmarkResult,
    )

    generated = build_fixture_archives(FIXTURE_ROOT, tmp_path / "generated")
    assert generated["synthetic-enterprise.ear"] == gold.samples[0].artifact.sha256
    assert render_result(evaluate_benchmark(gold, audit_run)) == render_result(expected)
    assert expected.dataset_visibility.value == "synthetic"
    assert expected.label_status.value == "provisional"


def test_every_synthetic_gold_conclusion_has_content_addressed_evidence() -> None:
    gold = load_contract(
        BASELINE_ROOT / "synthetic-gold-v1.json",
        ClosedPlatformGoldManifest,
    )
    sample = gold.samples[0]
    evidence = [
        item
        for conclusion in [
            *sample.entrypoints,
            *sample.findings,
            *sample.coverage_units,
        ]
        for item in conclusion.evidence
    ]

    for item in evidence:
        relative = EVIDENCE_FILES[item.evidence_ref]
        assert _sha256(FIXTURE_ROOT / relative) == item.sha256

    assert gold.authorization.scope_sha256 == _sha256(
        FIXTURE_ROOT / "fixture-matrix-v1.json"
    )
    assert gold.annotation_protocol.instructions_sha256 == _sha256(
        FIXTURE_ROOT / "GOLD_LABELS.md"
    )
    assert sample.artifact.provenance.custody_record_sha256 == _sha256(
        FIXTURE_ROOT / "AUTHORIZATION.md"
    )
    assert sample.artifact.provenance.acquisition_record_sha256 == _sha256(
        FIXTURE_ROOT / "README.md"
    )
    assert {
        gold.authorization.authorization_ref,
        *gold.annotation_protocol.reviewer_refs,
        gold.annotation_protocol.adjudicator_ref,
    } == {
        "record://cairn/cp0/synthetic-authorization",
        "record://cairn/cp0/config-first-review",
        "record://cairn/cp0/dataflow-first-review",
        "record://cairn/cp0/synthetic-contract-reconciliation",
    }


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
