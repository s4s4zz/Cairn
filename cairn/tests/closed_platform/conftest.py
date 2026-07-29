from __future__ import annotations

from copy import deepcopy

import pytest


def sha256_value(number: int) -> str:
    return f"{number:064x}"


def label_evidence(number: int) -> dict[str, object]:
    return {
        "sha256": sha256_value(number),
        "evidence_ref": f"fixture://closed-platform/evidence-{number}",
    }


def gold_payload() -> dict[str, object]:
    return {
        "schema_version": "closed-platform-gold-v1",
        "benchmark_id": "synthetic-cp0-v1",
        "visibility": "synthetic",
        "label_status": "provisional",
        "authorization": {
            "authorization_ref": "record://authorization/synthetic-cp0",
            "scope_sha256": sha256_value(1),
            "permits_static_analysis": True,
            "permits_decompilation": True,
            "permits_dynamic_execution": True,
        },
        "annotation_protocol": {
            "reviewer_refs": [
                "record://reviewers/one",
                "record://reviewers/two",
            ],
            "adjudicator_ref": "record://reviewers/adjudicator",
            "instructions_sha256": sha256_value(2),
        },
        "samples": [
            {
                "sample_id": "synthetic-enterprise",
                "artifact": {
                    "sha256": sha256_value(10),
                    "kind": "ear",
                    "artifact_ref": "fixture://closed-platform/synthetic-enterprise",
                    "provenance": {
                        "custody_record_ref": "record://custody/synthetic-enterprise",
                        "custody_record_sha256": sha256_value(3),
                        "acquisition_record_ref": "record://acquisition/synthetic-enterprise",
                        "acquisition_record_sha256": sha256_value(4),
                    },
                },
                "entrypoints": [
                    {
                        "fingerprint": sha256_value(20),
                        "evidence": [label_evidence(120)],
                    },
                    {
                        "fingerprint": sha256_value(21),
                        "evidence": [label_evidence(121)],
                    },
                ],
                "findings": [
                    {
                        "fingerprint": sha256_value(30),
                        "severity": "high",
                        "required_evidence": ["entrypoint", "sink", "runtime"],
                        "dynamic_reproducible": True,
                        "evidence": [label_evidence(130)],
                    },
                    {
                        "fingerprint": sha256_value(31),
                        "severity": "medium",
                        "required_evidence": ["input", "sink"],
                        "dynamic_reproducible": False,
                        "evidence": [label_evidence(131)],
                    },
                    {
                        "fingerprint": sha256_value(32),
                        "severity": "critical",
                        "required_evidence": ["call-chain"],
                        "dynamic_reproducible": True,
                        "evidence": [label_evidence(132)],
                    },
                ],
                "coverage_units": [
                    {
                        "fingerprint": sha256_value(40),
                        "evidence": [label_evidence(140)],
                    },
                    {
                        "fingerprint": sha256_value(41),
                        "evidence": [label_evidence(141)],
                    },
                    {
                        "fingerprint": sha256_value(42),
                        "evidence": [label_evidence(142)],
                    },
                ],
            }
        ],
    }


def audit_run_payload() -> dict[str, object]:
    return {
        "schema_version": "audit-run-export-v1",
        "audit_run_id": "run-synthetic-001",
        "sample_sha256": sha256_value(10),
        "entrypoints": [
            {"fingerprint": sha256_value(20)},
            {"fingerprint": sha256_value(29)},
        ],
        "findings": [
            {
                "fingerprint": sha256_value(30),
                "severity": "high",
                "evidence": ["sink", "entrypoint"],
                "dynamic_reproduced": True,
            },
            {
                "fingerprint": sha256_value(39),
                "severity": "low",
                "evidence": ["sink"],
                "dynamic_reproduced": False,
            },
        ],
        "coverage_units": [
            {
                "fingerprint": sha256_value(40),
                "status": "covered",
            },
            {
                "fingerprint": sha256_value(41),
                "status": "gap",
                "reason_code": "unresolved-reflection",
            },
        ],
    }


@pytest.fixture
def valid_gold_payload() -> dict[str, object]:
    return deepcopy(gold_payload())


@pytest.fixture
def valid_audit_run_payload() -> dict[str, object]:
    return deepcopy(audit_run_payload())
