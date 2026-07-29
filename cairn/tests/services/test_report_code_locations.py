from typing import cast
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from cairn.server.artifacts import ArtifactStore
from cairn.server.persistence.models import (
    AuditCoverage,
    AuditRun,
    Finding,
    FindingLocation,
)
from cairn.server.services.reports import ReportService


RUN_ID = UUID("00000000-0000-0000-0000-000000000100")
SNAPSHOT_SHA = "b" * 64


def _finding(
    location: FindingLocation,
    *,
    fingerprint_character: str,
    title: str,
) -> Finding:
    finding = Finding(
        id=uuid4(),
        audit_run_id=RUN_ID,
        fingerprint=fingerprint_character * 64,
        title=title,
        description="A controlled value reaches a sensitive operation.",
        category="injection",
        cwe_id="CWE-89",
        severity="high",
        confidence="high",
        status="confirmed",
        attack_preconditions="Attacker controls the input.",
        impact="Sensitive data may be exposed.",
        remediation="Validate the input and use a safe API.",
        runtime_verification="not_applicable",
        discovered_by="asm-index",
    )
    finding.locations = [location]
    return finding


def _run(*findings: Finding) -> AuditRun:
    run = AuditRun(
        id=RUN_ID,
        repository_id=UUID("00000000-0000-0000-0000-000000000101"),
        source_request={"type": "binary_upload", "upload_id": "upload-1"},
        policy_id=UUID("00000000-0000-0000-0000-000000000102"),
        policy_version=1,
        status="human_review",
        progress=90,
        warning_count=0,
        created_by="fixture",
    )
    run.findings = list(findings)
    run.coverage = AuditCoverage(
        audit_run_id=RUN_ID,
        modules_total=1,
        modules_analyzed=1,
        java_files_total=0,
        java_files_analyzed=0,
        entrypoints_total=1,
        entrypoints_analyzed=1,
        sensitive_sinks_total=1,
        sensitive_sinks_analyzed=1,
        build_status="success",
        static_tools_completed={},
        skipped_paths=[],
        unsupported_components=[],
        coverage_warnings=[],
    )
    return run


def _html(run: AuditRun) -> str:
    summary: dict[str, object] = {
        "overall_risk": "high",
        "severity_counts": {
            "critical": 0,
            "high": len(run.findings),
            "medium": 0,
            "low": 0,
            "info": 0,
        },
    }
    with Session() as session:
        service = ReportService(session, cast(ArtifactStore, object()))
        return service._html(run, summary)


def test_reports_preserve_binary_and_decompiled_location_evidence() -> None:
    artifact_id = UUID("00000000-0000-0000-0000-000000000104")
    bytecode = FindingLocation(
        role="sink",
        origin_kind="bytecode",
        file_path=None,
        start_line=None,
        end_line=None,
        symbol="demo.Action.execute",
        code_snippet=None,
        container_path="sample.war",
        entry_path="WEB-INF/lib/app.jar!/demo/Action.class",
        class_name="demo.Action",
        method_name="execute",
        method_descriptor="(Ljava/lang/String;)V",
        bytecode_offset=18,
        decompiled_artifact_id=None,
        decompiled_start_line=None,
        decompiled_end_line=None,
        snapshot_sha=SNAPSHOT_SHA,
        ordinal=0,
    )
    decompiled = FindingLocation(
        role="sink",
        origin_kind="decompiled",
        file_path=None,
        start_line=None,
        end_line=None,
        symbol="legacy.Job.run",
        code_snippet=None,
        container_path="legacy.ear",
        entry_path="app.war!/WEB-INF/classes/legacy/Job.class",
        class_name="legacy.Job",
        method_name="run",
        method_descriptor="()V",
        bytecode_offset=24,
        decompiled_artifact_id=artifact_id,
        decompiled_start_line=40,
        decompiled_end_line=44,
        snapshot_sha=SNAPSHOT_SHA,
        ordinal=0,
    )
    bytecode_finding = _finding(
        bytecode,
        fingerprint_character="a",
        title="Bytecode SQL sink",
    )
    decompiled_finding = _finding(
        decompiled,
        fingerprint_character="c",
        title="Decompiled SQL sink",
    )
    run = _run(bytecode_finding, decompiled_finding)

    bytecode_json = ReportService._finding_dict(bytecode_finding)["locations"][0]
    assert bytecode_json == {
        "role": "sink",
        "origin_kind": "bytecode",
        "file_path": None,
        "source_path": None,
        "start_line": None,
        "end_line": None,
        "symbol": "demo.Action.execute",
        "code_snippet": None,
        "container_path": "sample.war",
        "entry_path": "WEB-INF/lib/app.jar!/demo/Action.class",
        "class_name": "demo.Action",
        "method_name": "execute",
        "method_descriptor": "(Ljava/lang/String;)V",
        "bytecode_offset": 18,
        "decompiled_artifact_id": None,
        "decompiled_start_line": None,
        "decompiled_end_line": None,
        "snapshot_sha": SNAPSHOT_SHA,
        "ordinal": 0,
    }
    decompiled_json = ReportService._finding_dict(decompiled_finding)["locations"][0]
    assert decompiled_json == {
        "role": "sink",
        "origin_kind": "decompiled",
        "file_path": None,
        "source_path": None,
        "start_line": None,
        "end_line": None,
        "symbol": "legacy.Job.run",
        "code_snippet": None,
        "container_path": "legacy.ear",
        "entry_path": "app.war!/WEB-INF/classes/legacy/Job.class",
        "class_name": "legacy.Job",
        "method_name": "run",
        "method_descriptor": "()V",
        "bytecode_offset": 24,
        "decompiled_artifact_id": str(artifact_id),
        "decompiled_start_line": 40,
        "decompiled_end_line": 44,
        "snapshot_sha": SNAPSHOT_SHA,
        "ordinal": 0,
    }

    sarif_results = ReportService._sarif(run)["runs"][0]["results"]
    bytecode_sarif, decompiled_sarif = sarif_results
    bytecode_location = bytecode_sarif["locations"][0]
    assert bytecode_location["physicalLocation"] == {
        "artifactLocation": {
            "uri": "sample.war!/WEB-INF/lib/app.jar!/demo/Action.class"
        }
    }
    assert bytecode_location["properties"] == {
        "originKind": "bytecode",
        "containerPath": "sample.war",
        "entryPath": "WEB-INF/lib/app.jar!/demo/Action.class",
        "className": "demo.Action",
        "methodName": "execute",
        "methodDescriptor": "(Ljava/lang/String;)V",
        "bytecodeOffset": 18,
    }
    decompiled_location = decompiled_sarif["locations"][0]
    assert decompiled_location["physicalLocation"] == {
        "artifactLocation": {
            "uri": "legacy.ear!/app.war!/WEB-INF/classes/legacy/Job.class"
        }
    }
    assert decompiled_location["properties"] == {
        "originKind": "decompiled",
        "containerPath": "legacy.ear",
        "entryPath": "app.war!/WEB-INF/classes/legacy/Job.class",
        "className": "legacy.Job",
        "methodName": "run",
        "methodDescriptor": "()V",
        "bytecodeOffset": 24,
        "decompiledArtifactId": str(artifact_id),
    }

    html = _html(run)
    assert "sample.war!/WEB-INF/lib/app.jar!/demo/Action.class" in html
    assert "legacy.ear!/app.war!/WEB-INF/classes/legacy/Job.class" in html
    assert "demo.Action.execute(Ljava/lang/String;)V@18" in html
    assert "legacy.Job.run()V@24" in html
    assert "<pre><code>" not in html


def test_reports_keep_legacy_source_uri_region_and_snippet() -> None:
    source = FindingLocation(
        role="sink",
        origin_kind="source",
        file_path="src/main/java/demo/Action.java",
        start_line=12,
        end_line=14,
        symbol="demo.Action.execute",
        code_snippet="dangerous(input);",
        container_path=None,
        entry_path=None,
        class_name=None,
        method_name=None,
        method_descriptor=None,
        bytecode_offset=None,
        decompiled_artifact_id=None,
        decompiled_start_line=None,
        decompiled_end_line=None,
        snapshot_sha=SNAPSHOT_SHA,
        ordinal=0,
    )
    finding = _finding(
        source,
        fingerprint_character="d",
        title="Source SQL sink",
    )
    run = _run(finding)

    location_json = ReportService._finding_dict(finding)["locations"][0]
    assert location_json["file_path"] == "src/main/java/demo/Action.java"
    assert location_json["source_path"] == "src/main/java/demo/Action.java"
    assert location_json["start_line"] == 12
    assert location_json["end_line"] == 14
    assert location_json["code_snippet"] == "dangerous(input);"

    result = ReportService._sarif(run)["runs"][0]["results"][0]
    physical_location = result["locations"][0]["physicalLocation"]
    assert physical_location == {
        "artifactLocation": {"uri": "src/main/java/demo/Action.java"},
        "region": {"startLine": 12, "endLine": 14},
    }

    html = _html(run)
    assert "src/main/java/demo/Action.java:12-14" in html
    assert "<pre><code>dangerous(input);</code></pre>" in html
