from io import BytesIO
import json
import tarfile
from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.domain.enums import UserRole
from cairn.server.persistence.models import (
    Artifact,
    AuditCoverage,
    AuditPolicy,
    AuditRun,
    AuditTask,
    Finding,
    FindingLocation,
    HumanReview,
    Report,
    Repository,
    SourceSnapshot,
    Verification,
)
from cairn.server.persistence.models.identity import AuditLogEntry


def _snapshot_bytes() -> BytesIO:
    archive = BytesIO()
    source = b"package demo;\nclass Demo {\n  void query(String input) {}\n}\n"
    with tarfile.open(fileobj=archive, mode="w") as output:
        member = tarfile.TarInfo("src/main/java/demo/Demo.java")
        member.size = len(source)
        member.mode = 0o444
        output.addfile(member, BytesIO(source))
    archive.seek(0)
    return archive


def _seed_review_run(
    client: TestClient,
    session_factory: sessionmaker[Session],
    *,
    coverage_warning: bool = False,
    unrecorded_entrypoint_gap: bool = False,
) -> dict[str, UUID]:
    stored = client.app.state.artifact_store.put_stream(_snapshot_bytes())
    session = session_factory()
    try:
        repository = Repository(
            name=f"workbench-{stored.sha256[:12]}-{UUID(int=id(session) % 2**128)}",
            source_type="zip",
            created_by="fixture",
        )
        policy = AuditPolicy(
            name=f"workbench-policy-{UUID(int=id(repository) % 2**128)}",
            version=1,
            include_paths=["**"],
            exclude_paths=[],
            enabled_scanners=[],
            dynamic_verification="required",
            severity_thresholds={},
            resource_budget={},
            semantic_budget={},
            verification_budget={},
            dynamic_budget={},
            active=True,
        )
        source_artifact = Artifact(
            kind="source_snapshot",
            storage_key=stored.storage_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type="application/x-tar",
            access_level="sensitive",
        )
        session.add_all([repository, policy, source_artifact])
        session.flush()
        snapshot = SourceSnapshot(
            repository_id=repository.id,
            content_sha256="b" * 64,
            artifact_id=source_artifact.id,
            file_count=1,
            total_bytes=64,
            java_file_count=1,
            build_system="maven",
            status="ready",
        )
        session.add(snapshot)
        session.flush()
        run = AuditRun(
            repository_id=repository.id,
            source_request={"type": "snapshot", "snapshot_id": str(snapshot.id)},
            snapshot_id=snapshot.id,
            policy_id=policy.id,
            policy_version=policy.version,
            status="human_review",
            current_stage="human_review",
            progress=90,
            warning_count=1 if coverage_warning else 0,
            created_by="fixture",
        )
        session.add(run)
        session.flush()
        inventory_task = AuditTask(
            audit_run_id=run.id,
            type="inventory",
            scope_key="deterministic:inventory",
            scope={},
            required_capabilities=["inventory"],
            status="succeeded",
            worker_name="inventory-worker",
            attempt=1,
            max_attempts=3,
            timeout_seconds=900,
            input_artifact_ids=[str(source_artifact.id)],
            output_artifact_ids=[],
        )
        warnings = (
            [
                {
                    "reason_code": "BUILD_PARTIAL",
                    "tool": "build",
                    "detail": "one optional module",
                }
            ]
            if coverage_warning
            else []
        )
        coverage = AuditCoverage(
            audit_run_id=run.id,
            modules_total=1,
            modules_analyzed=1,
            java_files_total=1,
            java_files_analyzed=1,
            entrypoints_total=2 if unrecorded_entrypoint_gap else 1,
            entrypoints_analyzed=1,
            sensitive_sinks_total=1,
            sensitive_sinks_analyzed=1,
            build_status="partial" if coverage_warning else "success",
            static_tools_completed={},
            skipped_paths=[],
            unsupported_components=[],
            coverage_warnings=warnings,
        )
        finding = Finding(
            audit_run_id=run.id,
            fingerprint="a" * 64,
            title="SQL injection",
            description="Untrusted input reaches a query.",
            category="injection",
            cwe_id="CWE-89",
            severity="high",
            confidence="high",
            status="awaiting_human_review",
            attack_preconditions="Attacker controls input.",
            impact="Database compromise.",
            remediation="Use parameters.",
            runtime_verification="unverified",
            discovered_by="semgrep",
        )
        finding.locations = [
            FindingLocation(
                role="sink",
                file_path="src/main/java/demo/Demo.java",
                start_line=3,
                end_line=3,
                symbol="Demo.query",
                code_snippet="void query(String input) {}",
                snapshot_sha=snapshot.content_sha256,
                ordinal=0,
            )
        ]
        finding.verifications = [
            Verification(
                method="dynamic_poc",
                verdict="inconclusive",
                verifier="dynamic-verifier",
                evidence_ids=[],
                reasoning="No runnable environment was available.",
            ),
            Verification(
                method="independent_agent",
                verdict="confirmed",
                verifier="independent-reviewer",
                evidence_ids=[],
                reasoning="Independent trace reaches the same sink.",
            )
        ]
        session.add_all([inventory_task, coverage, finding])
        session.commit()
        return {
            "run": run.id,
            "finding": finding.id,
            "snapshot": snapshot.id,
            "source_artifact": source_artifact.id,
        }
    finally:
        session.close()


def test_review_is_strict_role_checked_and_audited(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    login_as(UserRole.VIEWER, "workbench-viewer")
    denied = client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed"},
    )
    assert denied.status_code == 403

    login_as(UserRole.REVIEWER, "workbench-reviewer")
    extra = client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed", "unexpected": True},
    )
    assert extra.status_code == 422
    response = client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={
            "verdict": "confirmed",
            "final_severity": "medium",
            "comment": "Validated compensating controls.",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "confirmed"
    assert response.json()["severity"] == "medium"
    assert response.json()["human_reviews"][0]["verdict"] == "confirmed"

    with session_factory() as session:
        review = session.scalars(select(HumanReview)).one()
        entry = session.scalars(
            select(AuditLogEntry).where(
                AuditLogEntry.action == "finding_reviewed"
            )
        ).one()
        assert review.final_severity == "medium"
        assert entry.target_id == str(ids["finding"])


def test_review_and_audit_log_roll_back_together(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _seed_review_run(client, session_factory)
    login_as(UserRole.REVIEWER, "rollback-reviewer")

    def fail_audit(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("audit log unavailable")

    monkeypatch.setattr(AuditLogService, "record", fail_audit)
    with pytest.raises(RuntimeError, match="audit log unavailable"):
        client.post(
            f"/api/v1/findings/{ids['finding']}/review",
            json={"verdict": "confirmed"},
        )

    with session_factory() as session:
        finding = session.get(Finding, ids["finding"])
        assert finding is not None
        assert finding.status == "awaiting_human_review"
        assert session.scalars(select(HumanReview)).all() == []


def test_reverify_queues_task_and_blocks_completion(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    login_as(UserRole.REVIEWER, "no-reverify-reviewer")
    assert client.post(
        f"/api/v1/findings/{ids['finding']}/reverify",
        json={"comment": "Try again."},
    ).status_code == 403

    login_as(UserRole.AUDITOR, "reverify-auditor")
    response = client.post(
        f"/api/v1/findings/{ids['finding']}/reverify",
        json={
            "method": "dynamic_poc",
            "comment": "Runtime evidence was inconclusive.",
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["finding"]["status"] == "validating"

    blocked = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")
    assert blocked.status_code == 409
    assert blocked.json()["error_code"] == "audit_run_completion_gate_failed"
    with session_factory() as session:
        task = session.scalars(
            select(AuditTask).where(AuditTask.type == "dynamic_verify")
        ).one()
        assert task.type == "dynamic_verify"
        assert task.status == "queued"


@pytest.mark.parametrize(
    ("coverage_warning", "expected_status"),
    [(False, "completed"), (True, "completed_with_warnings")],
)
def test_report_generation_completes_run_and_downloads_all_formats(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
    coverage_warning: bool,
    expected_status: str,
) -> None:
    ids = _seed_review_run(
        client,
        session_factory,
        coverage_warning=coverage_warning,
    )
    login_as(UserRole.REVIEWER, f"report-reviewer-{coverage_warning}")
    assert client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed", "comment": "Evidence accepted."},
    ).status_code == 200
    login_as(UserRole.ADMIN, f"report-admin-{coverage_warning}")

    generated = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")
    assert generated.status_code == 201, generated.text
    report = generated.json()
    assert set(report) >= {
        "html_artifact_id",
        "json_artifact_id",
        "sarif_artifact_id",
    }
    persisted_reports = client.get(
        "/api/v1/reports",
        params={"audit_run_id": str(ids["run"])},
    )
    persisted_tasks = client.get(f"/api/v1/audit-runs/{ids['run']}/tasks")
    assert persisted_reports.status_code == 200
    assert [item["id"] for item in persisted_reports.json()["items"]] == [
        report["id"]
    ]
    assert persisted_reports.json()["meta"]["total"] == 1
    assert persisted_tasks.status_code == 200
    assert {item["type"] for item in persisted_tasks.json()["items"]} >= {
        "inventory",
        "coverage_check",
        "report",
    }
    with session_factory() as session:
        run = session.get(AuditRun, ids["run"])
        assert run is not None
        assert run.status == expected_status
        assert float(run.progress) == 100

    html = client.get(f"/api/v1/reports/{report['id']}")
    machine = client.get(
        f"/api/v1/reports/{report['id']}", params={"format": "json"}
    )
    sarif = client.get(
        f"/api/v1/reports/{report['id']}", params={"format": "sarif"}
    )
    assert html.status_code == machine.status_code == sarif.status_code == 200
    assert "Cairn Java Audit Report" in html.text
    assert "Attack preconditions" in html.text
    assert "Attacker controls input." in html.text
    assert "Call chain and locations" in html.text
    assert "Machine verification" in html.text
    assert "Independent trace reaches the same sink." in html.text
    assert "Skipped paths" in html.text
    assert "Unsupported components" in html.text
    assert machine.json()["schema_version"] == "cairn-report-v1"
    assert sarif.json()["version"] == "2.1.0"
    assert sarif.json()["runs"][0]["results"][0]["ruleId"] == "CWE-89"


def test_report_and_audit_log_roll_back_together(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ids = _seed_review_run(client, session_factory)
    login_as(UserRole.REVIEWER, "report-rollback-reviewer")
    assert client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed"},
    ).status_code == 200
    login_as(UserRole.ADMIN, "report-rollback-admin")

    def fail_audit(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("audit log unavailable")

    monkeypatch.setattr(AuditLogService, "record", fail_audit)
    with pytest.raises(RuntimeError, match="audit log unavailable"):
        client.post(f"/api/v1/audit-runs/{ids['run']}/reports")

    with session_factory() as session:
        run = session.get(AuditRun, ids["run"])
        assert run is not None
        assert run.status == "human_review"
        assert session.scalars(select(Report)).all() == []
        report_tasks = session.scalars(
            select(AuditTask).where(AuditTask.type == "report")
        ).all()
        assert report_tasks == []
        report_artifacts = session.scalars(
            select(Artifact).where(Artifact.kind == "report")
        ).all()
        assert report_artifacts == []


def test_machine_rejected_severe_candidate_still_requires_human_disposition(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    with session_factory.begin() as session:
        finding = session.get(Finding, ids["finding"])
        assert finding is not None
        finding.status = "rejected"

    login_as(UserRole.ADMIN, "machine-rejection-admin")
    generated = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")

    assert generated.status_code == 409
    assert "lacks human review" in generated.json()["message"]
    with session_factory() as session:
        run = session.get(AuditRun, ids["run"])
        assert run is not None
        assert run.status == "human_review"


@pytest.mark.parametrize(
    ("method", "expected_blocker"),
    [
        ("independent_agent", "lacks independent verification"),
        ("dynamic_poc", "lacks dynamic verification"),
    ],
)
def test_machine_rejected_severe_candidate_still_requires_machine_evidence(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
    method: str,
    expected_blocker: str,
) -> None:
    ids = _seed_review_run(client, session_factory)
    with session_factory.begin() as session:
        finding = session.get(Finding, ids["finding"])
        assert finding is not None
        finding.status = "rejected"
        verification = session.scalars(
            select(Verification).where(
                Verification.finding_id == finding.id,
                Verification.method == method,
            )
        ).one()
        session.delete(verification)

    login_as(UserRole.ADMIN, f"missing-{method}-admin")
    generated = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")

    assert generated.status_code == 409
    assert expected_blocker in generated.json()["message"]


def test_completion_gate_rejects_unrecorded_coverage_gap(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(
        client,
        session_factory,
        unrecorded_entrypoint_gap=True,
    )
    login_as(UserRole.REVIEWER, "gap-reviewer")
    client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed"},
    )
    login_as(UserRole.ADMIN, "gap-admin")
    response = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")
    assert response.status_code == 409
    assert "entrypoint coverage gap" in response.json()["message"]


def test_build_warning_does_not_explain_unrecorded_entrypoint_gap(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(
        client,
        session_factory,
        coverage_warning=True,
        unrecorded_entrypoint_gap=True,
    )
    login_as(UserRole.REVIEWER, "combined-gap-reviewer")
    assert client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed"},
    ).status_code == 200
    login_as(UserRole.ADMIN, "combined-gap-admin")

    response = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")

    assert response.status_code == 409
    assert "entrypoint coverage gap" in response.json()["message"]


def test_completion_gate_requires_successful_inventory_task(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    with session_factory.begin() as session:
        inventory = session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == ids["run"],
                AuditTask.type == "inventory",
            )
        ).one()
        session.delete(inventory)
    login_as(UserRole.REVIEWER, "missing-inventory-reviewer")
    assert client.post(
        f"/api/v1/findings/{ids['finding']}/review",
        json={"verdict": "confirmed"},
    ).status_code == 200
    login_as(UserRole.ADMIN, "missing-inventory-admin")

    response = client.post(f"/api/v1/audit-runs/{ids['run']}/reports")

    assert response.status_code == 409
    assert "successful inventory task is missing" in response.json()["message"]


def test_source_view_is_bounded_role_checked_and_rejects_traversal(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    login_as(UserRole.VIEWER, "source-viewer")
    denied = client.get(
        f"/api/v1/snapshots/{ids['snapshot']}/source",
        params={"path": "src/main/java/demo/Demo.java"},
    )
    assert denied.status_code == 403

    login_as(UserRole.AUDITOR, "source-auditor")
    source = client.get(
        f"/api/v1/snapshots/{ids['snapshot']}/source",
        params={
            "path": "src/main/java/demo/Demo.java",
            "start_line": 2,
            "end_line": 3,
        },
    )
    assert source.status_code == 200, source.text
    assert source.json()["content"].startswith("class Demo")
    assert source.json()["snapshot_sha"] == "b" * 64
    escaped = client.get(
        f"/api/v1/snapshots/{ids['snapshot']}/source",
        params={"path": "../etc/passwd"},
    )
    assert escaped.status_code == 422
    assert escaped.json()["error_code"] == "snapshot_source_path_invalid"
    noncanonical = client.get(
        f"/api/v1/snapshots/{ids['snapshot']}/source",
        params={"path": "src//main/java/demo/Demo.java"},
    )
    assert noncanonical.status_code == 422
    assert noncanonical.json()["error_code"] == "snapshot_source_path_invalid"


def test_coverage_and_terminal_sse_are_readable(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as,
) -> None:
    ids = _seed_review_run(client, session_factory)
    with session_factory() as session:
        run = session.get(AuditRun, ids["run"])
        assert run is not None
        run.status = "failed"
        run.failure_code = "TEST_FAILURE"
        session.commit()
    login_as(UserRole.VIEWER, "event-viewer")

    coverage = client.get(f"/api/v1/audit-runs/{ids['run']}/coverage")
    events = client.get(f"/api/v1/audit-runs/{ids['run']}/events")
    assert coverage.status_code == 200
    assert coverage.json()["java_files_analyzed"] == 1
    assert events.status_code == 200
    assert events.headers["content-type"].startswith("text/event-stream")
    assert "event: audit-run" in events.text
    payload = json.loads(events.text.split("data: ", 1)[1].split("\n", 1)[0])
    assert payload["status"] == "failed"
    assert payload["failure_code"] == "TEST_FAILURE"
    event_id = events.text.split("id: ", 1)[1].split("\n", 1)[0]
    reconnect = client.get(
        f"/api/v1/audit-runs/{ids['run']}/events",
        headers={"Last-Event-ID": event_id},
    )
    assert reconnect.status_code == 200
    assert reconnect.text == ""
