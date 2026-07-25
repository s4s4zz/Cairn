from uuid import UUID

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import AuditRunStatus
from cairn.server.persistence.models import AuditRun


def create_git_repository(client: TestClient, name: str = "demo") -> dict[str, object]:
    response = client.post(
        "/api/v1/repositories",
        json={
            "name": name,
            "source_type": "git",
            "remote_url": f"https://example.invalid/{name}.git",
            "default_branch": "main",
        },
    )
    assert response.status_code == 201
    return response.json()


def create_policy(client: TestClient) -> dict[str, object]:
    response = client.post(
        "/api/v1/audit-policies",
        json={"name": "repository-test-policy"},
    )
    assert response.status_code == 201
    return response.json()


def test_create_and_list_git_repository(client: TestClient) -> None:
    created = create_git_repository(client)

    assert UUID(created["id"])
    assert created["created_by"] == "system"
    assert created["source_type"] == "git"

    response = client.get("/api/v1/repositories")
    assert response.status_code == 200
    assert response.json()["meta"] == {"limit": 50, "offset": 0, "total": 1}
    assert [item["id"] for item in response.json()["items"]] == [created["id"]]


def test_duplicate_repository_name_returns_409(client: TestClient) -> None:
    create_git_repository(client)

    response = client.post(
        "/api/v1/repositories",
        json={
            "name": "demo",
            "source_type": "git",
            "remote_url": "https://example.invalid/other.git",
        },
    )

    assert response.status_code == 409
    assert response.json()["error_code"] == "repository_name_conflict"


def test_git_repository_requires_https_or_ssh_url(client: TestClient) -> None:
    response = client.post(
        "/api/v1/repositories",
        json={
            "name": "unsafe",
            "source_type": "git",
            "remote_url": "file:///srv/repository",
        },
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "invalid_request"


def test_zip_repository_rejects_remote_url(client: TestClient) -> None:
    response = client.post(
        "/api/v1/repositories",
        json={
            "name": "upload",
            "source_type": "zip",
            "remote_url": "https://example.invalid/demo.git",
        },
    )

    assert response.status_code == 422


def test_delete_repository_with_runs_returns_409(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    repository = create_git_repository(client)
    policy = create_policy(client)
    with session_factory.begin() as session:
        session.add(
            AuditRun(
                repository_id=UUID(repository["id"]),
                source_request={"type": "git_ref", "ref": "main"},
                policy_id=UUID(policy["id"]),
                policy_version=policy["version"],
                status=AuditRunStatus.CREATED.value,
                progress=0,
                warning_count=0,
                created_by="system",
            )
        )

    response = client.delete(f"/api/v1/repositories/{repository['id']}")

    assert response.status_code == 409
    assert response.json()["error_code"] == "repository_has_audit_runs"


def test_delete_empty_repository(client: TestClient) -> None:
    repository = create_git_repository(client)

    response = client.delete(f"/api/v1/repositories/{repository['id']}")

    assert response.status_code == 204
    assert client.get(f"/api/v1/repositories/{repository['id']}").status_code == 404
