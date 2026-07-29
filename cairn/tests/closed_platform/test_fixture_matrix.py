from __future__ import annotations

import json
from pathlib import Path


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_fixture_matrix_covers_cp0_formats_and_platform_concepts() -> None:
    matrix = json.loads(
        (FIXTURE_ROOT / "fixture-matrix-v1.json").read_text(encoding="utf-8")
    )
    features = {item["feature"] for item in matrix["feature_matrix"]}

    assert features == {
        "nested-jar",
        "war",
        "ear",
        "standalone-class",
        "jsp",
        "web.xml",
        "xml-action",
        "platform-request",
        "platform-sql",
        "authorization-guard",
        "tenant-guard",
    }
    assert matrix["provenance"] == {
        "origin": "cairn-project-authored-synthetic",
        "contains_vendor_code": False,
        "contains_binaries": False,
        "contains_decompiled_text": False,
        "generated_artifacts_must_be_temporary": True,
    }


def test_fixture_references_exist_and_no_binary_is_committed() -> None:
    matrix = json.loads(
        (FIXTURE_ROOT / "fixture-matrix-v1.json").read_text(encoding="utf-8")
    )
    source_references = {
        path
        for artifact in matrix["archive_topology"]
        for path in artifact.get("generated_from", [])
    }
    source_references.update(
        item["locator"]
        for item in matrix["feature_matrix"]
        if item["locator"].startswith(("src/", "web/"))
    )
    assert source_references
    assert all((FIXTURE_ROOT / path).is_file() for path in source_references)

    committed_binary_suffixes = {".class", ".jar", ".war", ".ear"}
    assert not {
        path
        for path in FIXTURE_ROOT.rglob("*")
        if path.suffix.lower() in committed_binary_suffixes
    }


def test_fixture_contains_no_commercial_product_identifiers() -> None:
    forbidden = ("yonyou", "yonbip", "uap", "ecology", "weaver")
    text = "\n".join(
        path.read_text(encoding="utf-8", errors="strict").lower()
        for path in FIXTURE_ROOT.rglob("*")
        if path.is_file()
    )
    assert all(name not in text for name in forbidden)
