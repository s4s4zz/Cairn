import json
from pathlib import Path

import pytest

from cairn.analysis.config_rules import scan_config
from cairn.analysis.contracts import CandidateFinding
from cairn.analysis.fingerprints import merge_candidates
from cairn.analysis.normalizers import (
    NormalizationError,
    SourceCatalog,
    normalize_dependency_check,
    normalize_findsecbugs,
    normalize_gitleaks,
    normalize_sarif,
    normalize_semgrep,
    normalize_trivy,
)


SOURCE_ROOT = Path(__file__).parent / "fixtures" / "maven-multi"
SNAPSHOT_SHA = "a" * 64
JAVA_PATH = "core/src/main/java/dev/cairn/UserRepository.java"


def write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def validate_candidates(candidates: list[dict[str, object]]) -> None:
    for candidate in candidates:
        CandidateFinding.model_validate(candidate)


def test_semgrep_and_sarif_normalize_and_merge_same_root(tmp_path: Path) -> None:
    semgrep_path = write_json(
        tmp_path / "semgrep.json",
        {
            "results": [
                {
                    "check_id": "java.sql.concatenated-query",
                    "path": JAVA_PATH,
                    "start": {"line": 7, "col": 9},
                    "end": {"line": 7, "col": 73},
                    "extra": {
                        "message": "Concatenated SQL reaches Statement.execute",
                        "severity": "ERROR",
                        "metadata": {
                            "cwe": ["CWE-89"],
                            "category": "sql-injection",
                            "confidence": "HIGH",
                        },
                    },
                }
            ]
        },
    )
    sarif_path = write_json(
        tmp_path / "codeql.sarif",
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": [
                                {
                                    "id": "java/sql-injection",
                                    "properties": {
                                        "tags": ["external/cwe/cwe-89"],
                                        "precision": "high",
                                        "problem.severity": "error",
                                    },
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "java/sql-injection",
                            "level": "error",
                            "message": {"text": "Query is built from user input"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": JAVA_PATH},
                                        "region": {
                                            "startLine": 7,
                                            "endLine": 7,
                                        },
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        },
    )
    catalog = SourceCatalog(SOURCE_ROOT)

    candidates = normalize_semgrep(
        semgrep_path,
        catalog=catalog,
        snapshot_sha256=SNAPSHOT_SHA,
    ) + normalize_sarif(
        sarif_path,
        catalog=catalog,
        snapshot_sha256=SNAPSHOT_SHA,
    )
    merged = merge_candidates(candidates)

    validate_candidates(candidates)
    validate_candidates(merged)
    assert len(merged) == 1
    assert merged[0]["cwe_ids"] == ["CWE-89"]
    assert merged[0]["discovered_by"] == ["codeql", "semgrep"]
    assert merged[0]["source_rules"] == [
        "java.sql.concatenated-query",
        "java/sql-injection",
    ]
    assert merged[0]["fingerprint"] == merged[0]["root_cause_key"]


def test_secret_dependency_trivy_and_findsecbugs_formats(tmp_path: Path) -> None:
    catalog = SourceCatalog(SOURCE_ROOT)
    gitleaks = write_json(
        tmp_path / "gitleaks.json",
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "pom.xml",
                "StartLine": 1,
                "EndLine": 1,
                "StartColumn": 1,
                "EndColumn": 5,
                "Secret": "must-not-be-copied",
            }
        ],
    )
    dependency = write_json(
        tmp_path / "dependency-check.json",
        {
            "dependencies": [
                {
                    "filePath": "/work/source/pom.xml",
                    "fileName": "pom.xml",
                    "vulnerabilities": [
                        {
                            "name": "CVE-2026-0001",
                            "description": "Fixture vulnerability",
                            "severity": "CRITICAL",
                            "cwes": ["CWE-1104"],
                        }
                    ],
                }
            ]
        },
    )
    trivy = write_json(
        tmp_path / "trivy.json",
        {
            "Results": [
                {
                    "Target": "web/src/main/resources/application.yml",
                    "Misconfigurations": [
                        {
                            "ID": "AVD-SPRING-0001",
                            "Message": "Stack traces are disclosed",
                            "Severity": "MEDIUM",
                            "CauseMetadata": {"StartLine": 3, "EndLine": 3},
                        }
                    ],
                }
            ]
        },
    )
    findsecbugs = tmp_path / "findsecbugs.xml"
    findsecbugs.write_text(
        """<?xml version="1.0"?>
<BugCollection>
  <BugInstance type="SQL_INJECTION_JDBC" priority="1" category="SECURITY">
    <CWE id="89" />
    <LongMessage>Untrusted SQL reaches JDBC</LongMessage>
    <SourceLine sourcepath="dev/cairn/UserRepository.java" start="7" end="7" />
  </BugInstance>
</BugCollection>
""",
        encoding="utf-8",
    )

    candidates = [
        *normalize_gitleaks(
            gitleaks,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
        *normalize_dependency_check(
            dependency,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
        *normalize_trivy(
            trivy,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
        *normalize_findsecbugs(
            findsecbugs,
            catalog=catalog,
            snapshot_sha256=SNAPSHOT_SHA,
        ),
    ]

    validate_candidates(candidates)
    assert {candidate["discovered_by"][0] for candidate in candidates} == {
        "dependency-check",
        "findsecbugs",
        "gitleaks",
        "trivy",
    }
    assert all(
        "must-not-be-copied" not in str(candidate) for candidate in candidates
    )


def test_config_rules_are_versioned_normalized_candidates() -> None:
    candidates = scan_config(SOURCE_ROOT, snapshot_sha256=SNAPSHOT_SHA)

    validate_candidates(candidates)
    assert [
        (candidate["rule_id"], candidate["severity"])
        for candidate in candidates
    ] == [("CAIRN-SPRING-STACKTRACE-DISCLOSURE", "medium")]


def test_scanner_absolute_path_outside_snapshot_is_rejected() -> None:
    catalog = SourceCatalog(SOURCE_ROOT)

    with pytest.raises(NormalizationError):
        catalog.location("/etc/passwd", 1, 1)


def test_dependency_cache_path_falls_back_to_snapshot_pom(tmp_path: Path) -> None:
    result = write_json(
        tmp_path / "dependency-check.json",
        {
            "dependencies": [
                {
                    "filePath": (
                        "/work/scratch/home/.m2/repository/org/example/"
                        "fixture/1.0/fixture-1.0.jar"
                    ),
                    "fileName": "fixture-1.0.jar",
                    "vulnerabilities": [
                        {
                            "name": "CVE-2026-0002",
                            "description": "Cached Maven dependency",
                            "severity": "HIGH",
                        }
                    ],
                }
            ]
        },
    )

    candidates = normalize_dependency_check(
        result,
        catalog=SourceCatalog(SOURCE_ROOT),
        snapshot_sha256=SNAPSHOT_SHA,
    )

    validate_candidates(candidates)
    assert candidates[0]["locations"][0]["path"] == "pom.xml"


def test_dependency_cache_path_prefers_gradle_lockfile(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    source.joinpath("build.gradle.kts").write_text("plugins { java }\n")
    source.joinpath("gradle.lockfile").write_text(
        "org.example:fixture:1.0=runtimeClasspath\n"
    )
    result = write_json(
        tmp_path / "dependency-check.json",
        {
            "dependencies": [
                {
                    "filePath": (
                        "/work/scratch/gradle-home/caches/modules-2/files-2.1/"
                        "org.example/fixture/1.0/fixture-1.0.jar"
                    ),
                    "fileName": "fixture-1.0.jar",
                    "vulnerabilities": [
                        {
                            "name": "CVE-2026-0003",
                            "description": "Cached Gradle dependency",
                            "severity": "MEDIUM",
                        }
                    ],
                }
            ]
        },
    )

    candidates = normalize_dependency_check(
        result,
        catalog=SourceCatalog(source),
        snapshot_sha256=SNAPSHOT_SHA,
    )

    validate_candidates(candidates)
    assert candidates[0]["locations"][0]["path"] == "gradle.lockfile"
