from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import UserRole
from cairn.server.persistence.models import (
    Artifact,
    AuditPolicy,
    AuditRun,
    AuditTask,
    Report,
    Repository,
)

from .conftest import create_account, login


def _seed_runs(session_factory: sessionmaker[Session]) -> tuple[UUID, UUID]:
    with session_factory.begin() as session:
        repository = Repository(
            name="listing-repository",
            source_type="git",
            remote_url="https://example.invalid/listing.git",
            created_by="fixture",
        )
        policy = AuditPolicy(
            name="listing-policy",
            version=1,
            include_paths=["**"],
            exclude_paths=[],
            enabled_scanners=[],
            dynamic_verification="disabled",
            severity_thresholds={},
            resource_budget={},
            semantic_budget={},
            verification_budget={},
            dynamic_budget={},
            active=True,
        )
        session.add_all([repository, policy])
        session.flush()
        runs = [
            AuditRun(
                repository_id=repository.id,
                source_request={"type": "git_ref", "ref": ref},
                policy_id=policy.id,
                policy_version=policy.version,
                status="created",
                progress=0,
                warning_count=0,
                created_by="fixture",
            )
            for ref in ("main", "release")
        ]
        session.add_all(runs)
        session.flush()
        return runs[0].id, runs[1].id


def _seed_tasks(session_factory: sessionmaker[Session], run_id: UUID) -> list[UUID]:
    later = datetime(2026, 7, 29, 10, 0, tzinfo=UTC)
    expected_ids = [UUID(int=19), UUID(int=11), UUID(int=12)]
    tasks = [
        AuditTask(
            id=expected_ids[2],
            audit_run_id=run_id,
            type="build",
            scope_key="listing:later-b",
            scope={},
            required_capabilities=[],
            status="failed",
            worker_name="builder-b",
            attempt=2,
            max_attempts=3,
            timeout_seconds=60,
            input_artifact_ids=[],
            output_artifact_ids=[],
            error_code="BUILD_FAILED",
            created_at=later,
        ),
        AuditTask(
            id=expected_ids[0],
            audit_run_id=run_id,
            type="inventory",
            scope_key="listing:earlier",
            scope={},
            required_capabilities=[],
            status="succeeded",
            worker_name="inventory-a",
            attempt=1,
            max_attempts=3,
            timeout_seconds=60,
            input_artifact_ids=[],
            output_artifact_ids=[str(UUID(int=900))],
            started_at=later - timedelta(minutes=3),
            finished_at=later - timedelta(minutes=2),
            created_at=later - timedelta(minutes=5),
        ),
        AuditTask(
            id=expected_ids[1],
            audit_run_id=run_id,
            type="sast",
            scope_key="listing:later-a",
            scope={},
            required_capabilities=[],
            status="running",
            worker_name=None,
            attempt=1,
            max_attempts=3,
            timeout_seconds=60,
            input_artifact_ids=[],
            output_artifact_ids=[],
            created_at=later,
        ),
    ]
    with session_factory.begin() as session:
        session.add_all(tasks)
    return expected_ids


def _artifact(run_id: UUID, *, value: int) -> Artifact:
    return Artifact(
        id=UUID(int=value),
        audit_run_id=run_id,
        kind="report",
        storage_key=f"reports/listing-{value}",
        sha256=f"{value:064x}",
        size_bytes=1,
        media_type="application/json",
        access_level="normal",
    )


def _seed_reports(
    session_factory: sessionmaker[Session],
    first_run_id: UUID,
    second_run_id: UUID,
) -> list[UUID]:
    same_time = datetime(2026, 7, 29, 11, 0, tzinfo=UTC)
    report_ids = [UUID(int=101), UUID(int=102), UUID(int=103)]
    with session_factory.begin() as session:
        artifacts = [
            _artifact(run_id, value=value)
            for run_id, values in (
                (first_run_id, range(1001, 1007)),
                (second_run_id, range(1007, 1010)),
            )
            for value in values
        ]
        session.add_all(artifacts)
        session.flush()
        session.add_all(
            [
                Report(
                    id=report_ids[1],
                    audit_run_id=first_run_id,
                    version=2,
                    summary_json={"version": 2},
                    html_artifact_id=artifacts[3].id,
                    json_artifact_id=artifacts[4].id,
                    sarif_artifact_id=artifacts[5].id,
                    generated_at=same_time,
                ),
                Report(
                    id=report_ids[0],
                    audit_run_id=first_run_id,
                    version=1,
                    summary_json={"version": 1},
                    html_artifact_id=artifacts[0].id,
                    json_artifact_id=artifacts[1].id,
                    sarif_artifact_id=artifacts[2].id,
                    generated_at=same_time,
                ),
                Report(
                    id=report_ids[2],
                    audit_run_id=second_run_id,
                    version=1,
                    summary_json={"version": 1},
                    html_artifact_id=artifacts[6].id,
                    json_artifact_id=artifacts[7].id,
                    sarif_artifact_id=artifacts[8].id,
                    generated_at=same_time + timedelta(hours=1),
                ),
            ]
        )
    return report_ids


def test_audit_task_list_is_stable_paginated_and_frontend_complete(
    admin_client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    run_id, _ = _seed_runs(session_factory)
    expected_ids = _seed_tasks(session_factory, run_id)

    all_tasks = admin_client.get(
        f"/api/v1/audit-runs/{run_id}/tasks",
        params={"limit": 500},
    )
    page = admin_client.get(
        f"/api/v1/audit-runs/{run_id}/tasks",
        params={"limit": 2, "offset": 1},
    )

    assert all_tasks.status_code == 200, all_tasks.text
    assert all_tasks.json()["meta"] == {"limit": 500, "offset": 0, "total": 3}
    assert [item["id"] for item in all_tasks.json()["items"]] == [
        str(item) for item in expected_ids
    ]
    assert page.status_code == 200, page.text
    assert page.json()["meta"] == {"limit": 2, "offset": 1, "total": 3}
    assert [item["id"] for item in page.json()["items"]] == [
        str(item) for item in expected_ids[1:]
    ]
    assert set(all_tasks.json()["items"][0]) >= {
        "id",
        "audit_run_id",
        "type",
        "status",
        "worker_name",
        "attempt",
        "max_attempts",
        "error_code",
        "started_at",
        "finished_at",
        "output_artifact_ids",
    }


def test_audit_task_list_validates_run_and_page_boundaries(
    admin_client: TestClient,
) -> None:
    missing_id = UUID(int=0)

    missing = admin_client.get(f"/api/v1/audit-runs/{missing_id}/tasks")
    too_large = admin_client.get(
        f"/api/v1/audit-runs/{missing_id}/tasks",
        params={"limit": 501},
    )

    assert missing.status_code == 404
    assert missing.json()["error_code"] == "audit_run_not_found"
    assert too_large.status_code == 422


def test_report_list_filters_and_uses_stable_descending_order(
    admin_client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    first_run_id, second_run_id = _seed_runs(session_factory)
    report_ids = _seed_reports(session_factory, first_run_id, second_run_id)

    page = admin_client.get(
        "/api/v1/reports",
        params={"limit": 2, "offset": 1},
    )
    filtered = admin_client.get(
        "/api/v1/reports",
        params={"audit_run_id": first_run_id, "limit": 1, "offset": 1},
    )

    assert page.status_code == 200, page.text
    assert page.json()["meta"] == {"limit": 2, "offset": 1, "total": 3}
    assert [item["id"] for item in page.json()["items"]] == [
        str(report_ids[0]),
        str(report_ids[1]),
    ]
    assert filtered.status_code == 200, filtered.text
    assert filtered.json()["meta"] == {"limit": 1, "offset": 1, "total": 2}
    assert [item["id"] for item in filtered.json()["items"]] == [
        str(report_ids[1])
    ]
    assert filtered.json()["items"][0]["audit_run_id"] == str(first_run_id)
    assert admin_client.get("/api/v1/reports", params={"limit": 101}).status_code == 422


@pytest.mark.parametrize("role", list(UserRole))
def test_task_and_report_lists_are_readable_by_every_authenticated_role(
    client: TestClient,
    session_factory: sessionmaker[Session],
    role: UserRole,
) -> None:
    run_id, _ = _seed_runs(session_factory)
    create_account(session_factory, f"listing-{role.value}", role)
    login(client, f"listing-{role.value}")

    tasks = client.get(f"/api/v1/audit-runs/{run_id}/tasks")
    reports = client.get("/api/v1/reports")

    assert tasks.status_code == 200, tasks.text
    assert reports.status_code == 200, reports.text


@pytest.mark.parametrize(
    "path",
    [
        f"/api/v1/audit-runs/{UUID(int=0)}/tasks",
        "/api/v1/reports",
    ],
)
def test_task_and_report_lists_require_login(
    client: TestClient,
    path: str,
) -> None:
    response = client.get(path)

    assert response.status_code == 401
    assert response.json()["error_code"] == "authentication_required"
