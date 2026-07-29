"""The operator audit log (§9.8): what gets recorded, and what must not."""

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.auth.audit_log import AuditLogService
from cairn.server.domain.enums import ArtifactAccessLevel, ArtifactKind, UserRole
from cairn.server.persistence.models import Artifact, Repository
from cairn.server.persistence.models.identity import AuditLogEntry

from .conftest import TEST_PASSWORD, create_account, login


def _actions(session_factory: sessionmaker[Session]) -> list[str]:
    session = session_factory()
    try:
        return [
            entry.action
            for entry in session.scalars(
                select(AuditLogEntry).order_by(AuditLogEntry.created_at)
            )
        ]
    finally:
        session.close()


def _entry(session_factory: sessionmaker[Session], action: str) -> AuditLogEntry:
    session = session_factory()
    try:
        return session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == action)
        ).one()
    finally:
        session.close()


@pytest.fixture
def admin(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> TestClient:
    create_account(session_factory, "log-admin", UserRole.ADMIN)
    login(client, "log-admin")
    return client


def test_repository_lifecycle_is_audited(
    admin: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    created = admin.post(
        "/api/v1/repositories",
        json={"name": "audited", "source_type": "zip"},
    )
    assert created.status_code == 201
    repository_id = created.json()["id"]
    assert admin.delete(f"/api/v1/repositories/{repository_id}").status_code == 204

    actions = _actions(session_factory)
    assert "repository_created" in actions
    assert "repository_deleted" in actions
    entry = _entry(session_factory, "repository_created")
    assert entry.target_type == "repository"
    assert entry.target_id == repository_id
    assert entry.actor_username == "log-admin"
    assert entry.request_id


def test_business_write_rolls_back_when_audit_write_fails(
    admin: TestClient,
    session_factory: sessionmaker[Session],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_audit_write(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
        del args, kwargs
        raise RuntimeError("audit store unavailable")

    monkeypatch.setattr(AuditLogService, "record", fail_audit_write)

    with pytest.raises(RuntimeError, match="audit store unavailable"):
        admin.post(
            "/api/v1/repositories",
            json={"name": "must-roll-back", "source_type": "zip"},
        )

    with session_factory() as session:
        assert session.scalar(
            select(Repository).where(Repository.name == "must-roll-back")
        ) is None


def test_policy_and_run_actions_are_audited(
    admin: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = admin.post(
        "/api/v1/repositories",
        json={"name": "run-audited", "source_type": "zip"},
    ).json()
    policy = admin.post("/api/v1/audit-policies", json={"name": "audited"}).json()
    run = admin.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": repository["id"],
            "policy_id": policy["id"],
            "source_request": {"type": "upload", "upload_id": repository["id"]},
        },
    )

    actions = _actions(session_factory)
    assert "policy_created" in actions
    # The run creation above fails on a missing upload; the point is that the
    # successful policy write is logged and the failed run write is not.
    assert run.status_code == 404
    assert "audit_run_created" not in actions


def test_credential_audit_never_contains_the_secret(
    admin: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    token = "ghp_supersecrettokenvalue0123456789"
    response = admin.post(
        "/api/v1/git-credentials",
        json={"type": "https_token", "token": token},
    )
    assert response.status_code == 201

    entry = _entry(session_factory, "credential_created")
    assert entry.target_id == response.json()["reference"]
    assert token not in str(entry.detail)
    assert entry.detail == {"kind": "https_token"}


def test_password_change_audit_never_contains_the_password(
    admin: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    response = admin.post(
        "/api/v1/auth/password",
        json={
            "current_password": TEST_PASSWORD,
            "new_password": "another-long-passphrase",
        },
    )
    assert response.status_code == 204

    entry = _entry(session_factory, "user_password_changed")
    assert "another-long-passphrase" not in str(entry.detail)
    assert entry.detail == {"self_service": True}


def test_sensitive_artifact_download_is_refused_for_viewer_and_logged(
    client: TestClient,
    session_factory: sessionmaker[Session],
    tmp_path,
) -> None:
    session = session_factory()
    try:
        artifact = Artifact(
            kind=ArtifactKind.RUNTIME_LOG.value,
            storage_key="sha256/deadbeef",
            sha256="0" * 64,
            size_bytes=1,
            media_type="text/plain",
            access_level=ArtifactAccessLevel.SENSITIVE.value,
        )
        session.add(artifact)
        session.commit()
        artifact_id = str(artifact.id)
    finally:
        session.close()

    create_account(session_factory, "viewer-user", UserRole.VIEWER)
    login(client, "viewer-user")
    response = client.get(f"/api/v1/artifacts/{artifact_id}")

    assert response.status_code == 403
    assert response.json()["error_code"] == "artifact_access_forbidden"
    entry = _entry(session_factory, "artifact_downloaded")
    assert entry.outcome == "denied"
    assert entry.actor_username == "viewer-user"


def test_audit_log_is_readable_only_by_admin(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "log-reader", UserRole.REVIEWER)
    login(client, "log-reader")

    assert client.get("/api/v1/audit-logs").status_code == 403


def test_audit_log_listing_filters_and_paginates(
    admin: TestClient,
) -> None:
    admin.post("/api/v1/repositories", json={"name": "log-a", "source_type": "zip"})
    admin.post("/api/v1/repositories", json={"name": "log-b", "source_type": "zip"})

    response = admin.get(
        "/api/v1/audit-logs",
        params={"action": "repository_created", "limit": 1},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["meta"]["total"] == 2
    assert len(body["items"]) == 1
    assert body["items"][0]["action"] == "repository_created"


def test_audit_log_has_no_write_endpoint(admin: TestClient) -> None:
    """§9.8's log is only useful if the people it records cannot edit it."""

    for method in ("post", "put", "patch", "delete"):
        response = admin.request(method, "/api/v1/audit-logs", json={})
        assert response.status_code == 405, method
