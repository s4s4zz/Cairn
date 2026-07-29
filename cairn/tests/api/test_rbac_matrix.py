"""The §9.8 role matrix, checked endpoint by endpoint.

One table, four roles: whenever an endpoint is added, this file is where its
authorisation is stated, and a route that forgets its role dependency shows up
as a viewer being allowed to write.
"""

from collections.abc import Callable

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import UserRole
from cairn.server.persistence.models.identity import AuditLogEntry

from .conftest import create_account, login


ALL_ROLES = (UserRole.ADMIN, UserRole.AUDITOR, UserRole.REVIEWER, UserRole.VIEWER)

# (method, path, body, roles that may call it). Paths that need a live resource
# are exercised with a random UUID: authorisation is decided before the handler
# looks anything up, so an allowed role gets 404 and a refused one gets 403 —
# which is exactly the distinction under test.
MISSING_ID = "00000000-0000-0000-0000-000000000000"
MATRIX: tuple[tuple[str, str, dict | None, frozenset[UserRole]], ...] = (
    ("get", "/api/v1/repositories", None, frozenset(ALL_ROLES)),
    (
        "post",
        "/api/v1/repositories",
        {"name": "rbac-demo", "source_type": "zip"},
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "delete",
        f"/api/v1/repositories/{MISSING_ID}",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    ("get", "/api/v1/audit-policies", None, frozenset(ALL_ROLES)),
    (
        "post",
        "/api/v1/audit-policies",
        {"name": "rbac-policy"},
        frozenset({UserRole.ADMIN}),
    ),
    (
        "post",
        "/api/v1/git-credentials",
        {"reference": "rbac", "kind": "https_token", "token": "x" * 20},
        frozenset({UserRole.ADMIN}),
    ),
    ("get", "/api/v1/audit-runs", None, frozenset(ALL_ROLES)),
    (
        "post",
        "/api/v1/audit-runs",
        {
            "repository_id": MISSING_ID,
            "policy_id": MISSING_ID,
            "source_request": {"type": "git_ref", "ref": "main"},
        },
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "post",
        f"/api/v1/audit-runs/{MISSING_ID}/cancel",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "post",
        f"/api/v1/audit-runs/{MISSING_ID}/retry",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "delete",
        f"/api/v1/audit-runs/{MISSING_ID}",
        None,
        frozenset({UserRole.ADMIN}),
    ),
    (
        "get",
        f"/api/v1/audit-runs/{MISSING_ID}/coverage",
        None,
        frozenset(ALL_ROLES),
    ),
    (
        "get",
        f"/api/v1/audit-runs/{MISSING_ID}/tasks",
        None,
        frozenset(ALL_ROLES),
    ),
    (
        "get",
        f"/api/v1/audit-runs/{MISSING_ID}/events",
        None,
        frozenset(ALL_ROLES),
    ),
    (
        "post",
        f"/api/v1/audit-runs/{MISSING_ID}/reports",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    ("get", "/api/v1/findings", None, frozenset(ALL_ROLES)),
    ("get", f"/api/v1/findings/{MISSING_ID}", None, frozenset(ALL_ROLES)),
    (
        "post",
        f"/api/v1/findings/{MISSING_ID}/review",
        {"verdict": "confirmed"},
        frozenset({UserRole.ADMIN, UserRole.REVIEWER}),
    ),
    (
        "post",
        f"/api/v1/findings/{MISSING_ID}/reverify",
        {"comment": "Recheck the evidence."},
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "get",
        f"/api/v1/snapshots/{MISSING_ID}",
        None,
        frozenset(ALL_ROLES),
    ),
    (
        "get",
        f"/api/v1/snapshots/{MISSING_ID}/source?path=Demo.java",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR, UserRole.REVIEWER}),
    ),
    (
        "get",
        f"/api/v1/artifacts/{MISSING_ID}",
        None,
        frozenset(ALL_ROLES),
    ),
    (
        "get",
        f"/api/v1/reports/{MISSING_ID}",
        None,
        frozenset(ALL_ROLES),
    ),
    ("get", "/api/v1/reports", None, frozenset(ALL_ROLES)),
    ("get", "/api/v1/users", None, frozenset({UserRole.ADMIN})),
    (
        "post",
        "/api/v1/users",
        {"username": "rbac-new", "password": "a-long-enough-pass", "role": "viewer"},
        frozenset({UserRole.ADMIN}),
    ),
    ("get", "/api/v1/audit-logs", None, frozenset({UserRole.ADMIN})),
    ("get", "/api/v1/model-provider", None, frozenset({UserRole.ADMIN})),
    (
        "put",
        "/api/v1/model-provider",
        {
            "provider": "openai",
            "base_url": "https://api.openai.com",
            "model": "gpt-5",
            "api_key": "sk-rbac-placeholder",
        },
        frozenset({UserRole.ADMIN}),
    ),
    (
        "post",
        "/api/v1/model-provider/models",
        {
            "provider": "openai",
            "base_url": "https://api.openai.com",
            "api_key": "sk-rbac-placeholder",
        },
        frozenset({UserRole.ADMIN}),
    ),
    (
        "post",
        "/api/v1/uploads?source_type=zip",
        None,
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "post",
        f"/api/v1/repositories/{MISSING_ID}/snapshots",
        {"type": "git", "ref": "main"},
        frozenset({UserRole.ADMIN, UserRole.AUDITOR}),
    ),
    (
        "get",
        f"/api/v1/repositories/{MISSING_ID}/snapshots",
        None,
        frozenset(ALL_ROLES),
    ),
)


@pytest.mark.parametrize(("method", "path", "body", "allowed"), MATRIX)
@pytest.mark.parametrize("role", ALL_ROLES)
def test_role_matrix(
    client: TestClient,
    session_factory: sessionmaker[Session],
    method: str,
    path: str,
    body: dict | None,
    allowed: frozenset[UserRole],
    role: UserRole,
) -> None:
    create_account(session_factory, f"matrix-{role.value}", role)
    login(client, f"matrix-{role.value}")

    response = client.request(method, path, json=body)

    if role in allowed:
        assert response.status_code != 403, (path, role, response.text)
    else:
        assert response.status_code == 403, (path, role, response.text)
        assert response.json()["error_code"] == "insufficient_role"


def test_denied_write_is_recorded_in_the_audit_log(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "curious-viewer", UserRole.VIEWER)
    login(client, "curious-viewer")

    response = client.post(
        "/api/v1/repositories",
        json={"name": "not-allowed", "source_type": "zip"},
    )

    assert response.status_code == 403
    session = session_factory()
    try:
        entry = session.scalars(
            select(AuditLogEntry).where(AuditLogEntry.action == "access_denied")
        ).one()
        assert entry.actor_username == "curious-viewer"
        assert entry.actor_role == "viewer"
        assert entry.target_id == "/api/v1/repositories"
        assert entry.detail["method"] == "POST"
        assert entry.http_status == 403
    finally:
        session.close()


def test_last_active_admin_cannot_be_demoted(
    client: TestClient,
    session_factory: sessionmaker[Session],
    login_as: Callable[[UserRole], TestClient],
) -> None:
    admin = create_account(session_factory, "only-admin", UserRole.ADMIN)
    login(client, "only-admin")

    demote = client.patch(f"/api/v1/users/{admin.id}", json={"role": "viewer"})
    disable = client.patch(f"/api/v1/users/{admin.id}", json={"is_active": False})

    assert demote.status_code == 409
    assert demote.json()["error_code"] == "last_admin_protected"
    assert disable.status_code == 409


def test_admin_can_demote_when_another_admin_remains(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "admin-a", UserRole.ADMIN)
    second = create_account(session_factory, "admin-b", UserRole.ADMIN)
    login(client, "admin-a")

    response = client.patch(f"/api/v1/users/{second.id}", json={"role": "viewer"})

    assert response.status_code == 200
    assert response.json()["role"] == "viewer"


def test_role_change_revokes_the_target_users_sessions(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    create_account(session_factory, "admin-c", UserRole.ADMIN)
    target = create_account(session_factory, "demoted", UserRole.AUDITOR)

    # A second client so the demoted user holds a live session of their own.
    other = TestClient(client.app)
    login(other, "demoted")
    assert other.get("/api/v1/repositories").status_code == 200

    login(client, "admin-c")
    updated = client.patch(f"/api/v1/users/{target.id}", json={"role": "viewer"})
    assert updated.status_code == 200

    assert other.get("/api/v1/repositories").status_code == 401
