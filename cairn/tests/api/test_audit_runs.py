from uuid import UUID

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditFactKind,
    AuditIntentStatus,
    AuditLogAction,
    AuditRunStatus,
    AuditTaskStatus,
    AuditTaskType,
    BuildSystem,
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    RuntimeVerificationStatus,
    SnapshotStatus,
)
from cairn.server.errors import InvalidStateError
from cairn.server.persistence.models import (
    Artifact,
    AuditFact,
    AuditIntent,
    AuditIntentSource,
    AuditLogEntry,
    AuditRun,
    AuditRunStageEvent,
    AuditTask,
    Evidence,
    Finding,
    SourceSnapshot,
)
from cairn.server.services.audit_runs import AuditRunService


@pytest.fixture(autouse=True)
def _admin_session(admin_client: TestClient) -> None:
    """Run this file's tests as an authenticated admin.

    These tests predate §9.8 authentication and cover repository, run, finding
    and policy behaviour rather than authorisation; the role matrix is checked
    on its own in test_rbac_matrix.py.
    """


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


@pytest.mark.parametrize(
    "settled_status",
    [
        AuditRunStatus.FAILED,
        AuditRunStatus.CANCELLED,
        AuditRunStatus.HUMAN_REVIEW,
        AuditRunStatus.COMPLETED,
        AuditRunStatus.COMPLETED_WITH_WARNINGS,
    ],
)
def test_admin_can_delete_a_settled_audit_run_and_keeps_an_audit_log(
    client: TestClient,
    session_factory: sessionmaker[Session],
    settled_status: AuditRunStatus,
) -> None:
    repository = create_repository(client, f"delete-{settled_status.value}")
    policy = create_policy(client, f"delete-{settled_status.value}-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(run["id"]))
        assert stored is not None
        stored.status = settled_status.value

    response = client.delete(f"/api/v1/audit-runs/{run['id']}")

    assert response.status_code == 204
    assert client.get(f"/api/v1/audit-runs/{run['id']}").status_code == 404
    with session_factory() as session:
        entry = session.scalar(
            select(AuditLogEntry)
            .where(
                AuditLogEntry.action == AuditLogAction.AUDIT_RUN_DELETED.value,
                AuditLogEntry.target_id == run["id"],
            )
            .order_by(AuditLogEntry.created_at.desc())
        )
        assert entry is not None
        assert entry.detail["status"] == settled_status.value


def test_active_audit_run_must_be_cancelled_before_deletion(
    client: TestClient,
) -> None:
    repository = create_repository(client, "delete-active")
    policy = create_policy(client, "delete-active-policy")
    run = create_git_run(client, repository["id"], policy["id"])

    response = client.delete(f"/api/v1/audit-runs/{run['id']}")

    assert response.status_code == 409
    assert response.json()["error_code"] == "audit_run_not_deletable"
    assert client.get(f"/api/v1/audit-runs/{run['id']}").status_code == 200


def test_delete_orders_populated_run_records_before_their_producing_task(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "delete-populated")
    policy = create_policy(client, "delete-populated-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    run_id = UUID(run["id"])

    with session_factory.begin() as session:
        stored = session.get(AuditRun, run_id)
        assert stored is not None
        stored.status = AuditRunStatus.HUMAN_REVIEW.value
        task = AuditTask(
            audit_run_id=run_id,
            type=AuditTaskType.SAST.value,
            scope_key="deterministic:semgrep",
            scope={"tool": "semgrep"},
            required_capabilities=[],
            status=AuditTaskStatus.SUCCEEDED.value,
            attempt=1,
            max_attempts=3,
            timeout_seconds=300,
            input_artifact_ids=[],
            output_artifact_ids=[],
        )
        session.add(task)
        session.flush()
        artifact = Artifact(
            audit_run_id=run_id,
            kind=ArtifactKind.SCAN_RESULT.value,
            storage_key="sha256/aa/" + "a" * 64,
            sha256="a" * 64,
            size_bytes=128,
            media_type="application/x-tar",
            access_level=ArtifactAccessLevel.NORMAL.value,
            produced_by_task_id=task.id,
        )
        finding = Finding(
            audit_run_id=run_id,
            fingerprint="b" * 64,
            title="Populated deletion fixture",
            description="A run-owned finding with task-backed evidence.",
            category="authorization",
            cwe_id="CWE-862",
            severity=FindingSeverity.HIGH.value,
            confidence=FindingConfidence.HIGH.value,
            status=FindingStatus.CANDIDATE.value,
            attack_preconditions="An unauthenticated request reaches the endpoint.",
            impact="Authorization may be bypassed.",
            remediation="Require an explicit authorization policy.",
            runtime_verification=RuntimeVerificationStatus.UNVERIFIED.value,
            discovered_by="semgrep",
        )
        session.add_all([artifact, finding])
        session.flush()
        evidence = Evidence(
            finding_id=finding.id,
            type=EvidenceType.TOOL_RESULT.value,
            artifact_id=artifact.id,
            summary="Semgrep result",
            sha256=artifact.sha256,
            produced_by_task_id=task.id,
        )
        fact = AuditFact(
            audit_run_id=run_id,
            kind=AuditFactKind.ARCHITECTURE.value,
            structured_payload={"framework": "spring"},
            evidence_ids=[],
            created_by_task_id=task.id,
        )
        intent = AuditIntent(
            audit_run_id=run_id,
            category="authorization",
            scope={"module": "."},
            required_capabilities=[],
            status=AuditIntentStatus.PENDING.value,
            created_by_task_id=task.id,
        )
        session.add_all([evidence, fact, intent])
        session.flush()
        session.add(
            AuditIntentSource(
                audit_intent_id=intent.id,
                audit_fact_id=fact.id,
            )
        )
        task_id = task.id
        artifact_id = artifact.id
        finding_id = finding.id
        evidence_id = evidence.id
        fact_id = fact.id
        intent_id = intent.id

    response = client.delete(f"/api/v1/audit-runs/{run['id']}")

    assert response.status_code == 204
    with session_factory() as session:
        assert session.get(AuditRun, run_id) is None
        assert session.get(AuditTask, task_id) is None
        assert session.get(Artifact, artifact_id) is None
        assert session.get(Finding, finding_id) is None
        assert session.get(Evidence, evidence_id) is None
        assert session.get(AuditFact, fact_id) is None
        assert session.get(AuditIntent, intent_id) is None


def test_run_creation_and_audit_log_roll_back_together(
    client: TestClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = create_repository(client, "atomic-create")
    policy = create_policy(client, "atomic-create-policy")

    def fail_audit(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("audit log unavailable")

    monkeypatch.setattr(AuditLogService, "record", fail_audit)
    with pytest.raises(RuntimeError, match="audit log unavailable"):
        create_git_run(client, repository["id"], policy["id"])

    with session_factory() as session:
        runs = session.scalars(
            select(AuditRun).where(
                AuditRun.repository_id == UUID(str(repository["id"]))
            )
        ).all()
        assert runs == []


def test_run_cancellation_and_audit_log_roll_back_together(
    client: TestClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = create_repository(client, "atomic-cancel")
    policy = create_policy(client, "atomic-cancel-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(str(run["id"])))
        assert stored is not None
        stored.status = AuditRunStatus.STATIC_SCANNING.value

    def fail_audit(*args, **kwargs):  # noqa: ANN002, ANN003
        raise RuntimeError("audit log unavailable")

    monkeypatch.setattr(AuditLogService, "record", fail_audit)
    with pytest.raises(RuntimeError, match="audit log unavailable"):
        client.post(f"/api/v1/audit-runs/{run['id']}/cancel")

    with session_factory() as session:
        stored = session.get(AuditRun, UUID(str(run["id"])))
        assert stored is not None
        assert stored.status == AuditRunStatus.STATIC_SCANNING.value


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


def test_stage_entries_are_recorded_and_closed_by_the_next_entry(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    """Stage timing used to be reconstructed from the tasks a stage owns.

    `ingesting` owns none, so it had no duration at all. Recording the entry
    gives it one, and the entry that follows closes it.
    """

    repository = create_repository(client, "stage-events")
    policy = create_policy(client, "stage-events-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    snapshot = create_ready_snapshot(
        session_factory,
        repository["id"],
        policy["id"],
        suffix="e",
    )

    with session_factory() as session:
        service = AuditRunService(session)
        service.transition(UUID(run["id"]), AuditRunStatus.INGESTING)
        service.transition(
            UUID(run["id"]),
            AuditRunStatus.PREPROCESSING,
            snapshot_id=snapshot.id,
        )

    response = client.get(f"/api/v1/audit-runs/{run['id']}/stages")
    assert response.status_code == 200
    stages = response.json()

    assert [entry["stage"] for entry in stages] == ["ingesting", "preprocessing"]
    # The first stage is closed by the second one's entry.
    assert stages[0]["exited_at"] == stages[1]["entered_at"]
    # The current stage stays open while the run is live.
    assert stages[1]["exited_at"] is None


def test_the_last_stage_is_closed_by_the_run_completing(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "stage-events-terminal")
    policy = create_policy(client, "stage-events-terminal-policy")
    run = create_git_run(client, repository["id"], policy["id"])

    with session_factory() as session:
        service = AuditRunService(session)
        service.transition(UUID(run["id"]), AuditRunStatus.INGESTING)
        completed = service.transition(UUID(run["id"]), AuditRunStatus.FAILED)

    stages = client.get(f"/api/v1/audit-runs/{run['id']}/stages").json()

    assert len(stages) == 1
    assert stages[0]["stage"] == "ingesting"
    assert stages[0]["exited_at"] is not None
    assert completed.current_stage == "ingesting"


def test_deleting_a_run_removes_its_stage_entries(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_repository(client, "stage-events-delete")
    policy = create_policy(client, "stage-events-delete-policy")
    run = create_git_run(client, repository["id"], policy["id"])

    with session_factory() as session:
        AuditRunService(session).transition(UUID(run["id"]), AuditRunStatus.INGESTING)
    with session_factory() as session:
        AuditRunService(session).transition(UUID(run["id"]), AuditRunStatus.CANCELLING)
    with session_factory() as session:
        AuditRunService(session).transition(UUID(run["id"]), AuditRunStatus.CANCELLED)

    assert client.delete(f"/api/v1/audit-runs/{run['id']}").status_code == 204

    with session_factory() as session:
        remaining = session.scalars(
            select(AuditRunStageEvent).where(
                AuditRunStageEvent.audit_run_id == UUID(run["id"])
            )
        ).all()
    assert remaining == []


def test_failed_run_with_a_stale_running_task_can_still_be_deleted(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    """A terminal run is not executing, so an active-looking task is stale.

    Refusing on it locked the run out of deletion permanently: nothing settles
    the row once the run is terminal.
    """

    repository = create_repository(client, "stale-task-delete")
    policy = create_policy(client, "stale-task-delete-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(run["id"]))
        stored.status = AuditRunStatus.FAILED.value
        stored.failure_code = "ANALYSIS_INTERNAL_FAILURE"
        session.add(
            AuditTask(
                audit_run_id=UUID(run["id"]),
                type=AuditTaskType.INVENTORY.value,
                scope_key="deterministic:inventory",
                scope={},
                required_capabilities=["deterministic:inventory"],
                status=AuditTaskStatus.RUNNING.value,
                worker_name="deterministic-orchestrator",
                attempt=3,
                max_attempts=3,
                timeout_seconds=900,
            )
        )

    assert client.delete(f"/api/v1/audit-runs/{run['id']}").status_code == 204


def test_review_run_with_a_queued_task_is_still_refused(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    """`human_review` is the one deletable status that can owe real work.

    A queued reverify task there is waiting for the orchestrator to claim it, so
    the guard has to keep applying.
    """

    repository = create_repository(client, "review-task-delete")
    policy = create_policy(client, "review-task-delete-policy")
    run = create_git_run(client, repository["id"], policy["id"])
    with session_factory.begin() as session:
        stored = session.get(AuditRun, UUID(run["id"]))
        stored.status = AuditRunStatus.HUMAN_REVIEW.value
        session.add(
            AuditTask(
                audit_run_id=UUID(run["id"]),
                type=AuditTaskType.INDEPENDENT_VERIFY.value,
                scope_key="reverify:finding-1",
                scope={},
                required_capabilities=["verify:independent"],
                status=AuditTaskStatus.QUEUED.value,
                attempt=0,
                max_attempts=3,
                timeout_seconds=900,
            )
        )

    response = client.delete(f"/api/v1/audit-runs/{run['id']}")

    assert response.status_code == 409
    assert response.json()["error_code"] == "audit_run_has_active_tasks"
