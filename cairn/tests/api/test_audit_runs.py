from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditRunStatus,
    BuildSystem,
    SnapshotStatus,
)
from cairn.server.errors import InvalidStateError
from cairn.server.persistence.models import Artifact, AuditRun, SourceSnapshot
from cairn.server.services.audit_runs import AuditRunService


def create_repository(
    client: TestClient,
    name: str,
    *,
    source_type: str = "git",
) -> dict[str, object]:
    payload: dict[str, object] = {"name": name, "source_type": source_type}
    if source_type == "git":
        payload["remote_url"] = f"https://example.invalid/{name}.git"
    response = client.post("/api/v1/repositories", json=payload)
    assert response.status_code == 201
    return response.json()


def create_policy(client: TestClient, name: str = "run-policy") -> dict[str, object]:
    response = client.post("/api/v1/audit-policies", json={"name": name})
    assert response.status_code == 201
    return response.json()


def create_git_run(
    client: TestClient,
    repository_id: str,
    policy_id: str,
    *,
    ref: str = "main",
) -> dict[str, object]:
    response = client.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": repository_id,
            "policy_id": policy_id,
            "source_request": {"type": "git_ref", "ref": ref},
        },
    )
    assert response.status_code == 201
    return response.json()


def create_ready_snapshot(
    session_factory: sessionmaker[Session],
    repository_id: str,
    policy_id: str,
    *,
    suffix: str = "a",
) -> SourceSnapshot:
    with session_factory.begin() as session:
        producer_run = AuditRun(
            repository_id=UUID(repository_id),
            source_request={"type": "git_ref", "ref": "snapshot-source"},
            policy_id=UUID(policy_id),
            policy_version=1,
            status=AuditRunStatus.CREATED.value,
            progress=0,
            warning_count=0,
            created_by="system",
        )
        session.add(producer_run)
        session.flush()
        artifact = Artifact(
            audit_run_id=producer_run.id,
            kind=ArtifactKind.SOURCE_SNAPSHOT.value,
            storage_key=f"snapshots/{suffix}",
            sha256=suffix * 64,
            size_bytes=100,
            media_type="application/x-tar",
            access_level=ArtifactAccessLevel.NORMAL.value,
        )
        session.add(artifact)
        session.flush()
        snapshot = SourceSnapshot(
            repository_id=UUID(repository_id),
            commit_sha=suffix * 40,
            content_sha256=suffix * 64,
            branch_or_tag="main",
            artifact_id=artifact.id,
            file_count=2,
            total_bytes=100,
            java_file_count=1,
            java_version="21",
            build_system=BuildSystem.MAVEN.value,
            status=SnapshotStatus.READY.value,
        )
        session.add(snapshot)
        session.flush()
        snapshot_id = snapshot.id

    with session_factory() as session:
        return session.get(SourceSnapshot, snapshot_id)


def test_create_run_from_existing_ready_snapshot(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "snapshot-repo")
    policy = create_policy(client)
    snapshot = create_ready_snapshot(
        session_factory,
        repository["id"],
        policy["id"],
    )

    response = client.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": repository["id"],
            "policy_id": policy["id"],
            "source_request": {
                "type": "snapshot",
                "snapshot_id": str(snapshot.id),
            },
        },
    )

    assert response.status_code == 201
    assert response.json()["snapshot_id"] == str(snapshot.id)
    assert response.json()["status"] == "created"
    assert response.json()["policy_version"] == 1


def test_create_run_from_git_ref_has_no_snapshot(
    client: TestClient,
) -> None:
    repository = create_repository(client, "git-repo")
    policy = create_policy(client)

    run = create_git_run(client, repository["id"], policy["id"], ref="release")

    assert run["snapshot_id"] is None
    assert run["source_request"] == {"type": "git_ref", "ref": "release"}
    assert run["current_stage"] is None


def test_reject_snapshot_owned_by_another_repository(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    owner = create_repository(client, "owner")
    other = create_repository(client, "other")
    policy = create_policy(client)
    snapshot = create_ready_snapshot(session_factory, owner["id"], policy["id"])

    response = client.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": other["id"],
            "policy_id": policy["id"],
            "source_request": {
                "type": "snapshot",
                "snapshot_id": str(snapshot.id),
            },
        },
    )

    assert response.status_code == 409
    assert response.json()["error_code"] == "snapshot_repository_mismatch"


def test_list_filters_by_repository_and_status(client: TestClient) -> None:
    first_repository = create_repository(client, "first")
    second_repository = create_repository(client, "second")
    policy = create_policy(client)
    first_run = create_git_run(client, first_repository["id"], policy["id"])
    create_git_run(client, second_repository["id"], policy["id"])

    response = client.get(
        "/api/v1/audit-runs",
        params={
            "repository_id": first_repository["id"],
            "status": "created",
        },
    )

    assert response.status_code == 200
    assert response.json()["meta"]["total"] == 1
    assert response.json()["items"][0]["id"] == first_run["id"]


def test_cancel_running_run_and_make_repeated_cancel_idempotent(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "cancel")
    policy = create_policy(client)
    run = create_git_run(client, repository["id"], policy["id"])
    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(run["id"]))
        stored.status = AuditRunStatus.STATIC_SCANNING.value

    response = client.post(f"/api/v1/audit-runs/{run['id']}/cancel")
    assert response.status_code == 200
    assert response.json()["status"] == "cancelling"

    repeated = client.post(f"/api/v1/audit-runs/{run['id']}/cancel")
    assert repeated.status_code == 200
    assert repeated.json()["status"] == "cancelling"

    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(run["id"]))
        stored.status = AuditRunStatus.CANCELLED.value
    cancelled = client.post(f"/api/v1/audit-runs/{run['id']}/cancel")
    assert cancelled.status_code == 200
    assert cancelled.json()["status"] == "cancelled"


def test_public_api_rejects_direct_status_updates(client: TestClient) -> None:
    repository = create_repository(client, "no-status-write")
    policy = create_policy(client)
    run = create_git_run(client, repository["id"], policy["id"])

    response = client.patch(
        f"/api/v1/audit-runs/{run['id']}",
        json={"status": "completed"},
    )

    assert response.status_code == 405


def test_internal_preprocessing_transition_requires_ready_snapshot(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "transition")
    policy = create_policy(client)
    run = create_git_run(client, repository["id"], policy["id"])

    early_snapshot = create_ready_snapshot(
        session_factory,
        repository["id"],
        policy["id"],
        suffix="d",
    )
    with session_factory() as session:
        service = AuditRunService(session)
        with pytest.raises(InvalidStateError) as captured:
            service.transition(
                UUID(run["id"]),
                AuditRunStatus.PREPROCESSING,
                snapshot_id=early_snapshot.id,
            )
        assert captured.value.error_code == "audit_run_invalid_transition"
        assert service.get(UUID(run["id"])).snapshot_id is None

    with session_factory() as session:
        service = AuditRunService(session)
        service.transition(UUID(run["id"]), AuditRunStatus.INGESTING)
        with pytest.raises(InvalidStateError) as captured:
            service.transition(UUID(run["id"]), AuditRunStatus.PREPROCESSING)
        assert captured.value.error_code == "snapshot_required"

    snapshot = create_ready_snapshot(
        session_factory,
        repository["id"],
        policy["id"],
        suffix="c",
    )
    with session_factory() as session:
        transitioned = AuditRunService(session).transition(
            UUID(run["id"]),
            AuditRunStatus.PREPROCESSING,
            snapshot_id=snapshot.id,
        )
        assert transitioned.snapshot_id == snapshot.id
        assert transitioned.current_stage == "preprocessing"
