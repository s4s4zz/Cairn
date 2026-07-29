from fastapi.testclient import TestClient
import pytest

from cairn.server.schemas.policies import SUPPORTED_SCANNERS


@pytest.fixture(autouse=True)
def _admin_session(admin_client: TestClient) -> None:
    """Run this file's tests as an authenticated admin.

    These tests predate §9.8 authentication and cover repository, run, finding
    and policy behaviour rather than authorisation; the role matrix is checked
    on its own in test_rbac_matrix.py.
    """


def create_policy(
    client: TestClient,
    *,
    name: str = "comprehensive",
    include_paths: list[str] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {"name": name}
    if include_paths is not None:
        payload["include_paths"] = include_paths
    response = client.post("/api/v1/audit-policies", json=payload)
    assert response.status_code == 201
    return response.json()


def test_policy_defaults_are_comprehensive(client: TestClient) -> None:
    policy = create_policy(client)

    assert policy["version"] == 1
    assert policy["active"] is True
    assert policy["dynamic_verification"] == "required"
    assert set(policy["enabled_scanners"]) == SUPPORTED_SCANNERS


def test_new_policy_version_preserves_old_payload_and_has_single_active_version(
    client: TestClient,
) -> None:
    first = create_policy(client, include_paths=["src/**"])
    second = create_policy(client, include_paths=["app/**"])

    assert second["version"] == 2
    response = client.get("/api/v1/audit-policies", params={"name": "comprehensive"})
    assert response.status_code == 200
    versions = {item["version"]: item for item in response.json()["items"]}
    assert versions[1]["include_paths"] == ["src/**"]
    assert versions[1]["active"] is False
    assert versions[2]["include_paths"] == ["app/**"]
    assert versions[2]["active"] is True
    assert sum(item["active"] for item in versions.values()) == 1

    first_response = client.get(f"/api/v1/audit-policies/{first['id']}")
    assert first_response.json()["include_paths"] == ["src/**"]


def test_inactive_version_does_not_deactivate_current_version(client: TestClient) -> None:
    first = create_policy(client)
    response = client.post(
        "/api/v1/audit-policies",
        json={"name": "comprehensive", "active": False},
    )

    assert response.status_code == 201
    assert response.json()["version"] == 2
    assert response.json()["active"] is False
    current = client.get(f"/api/v1/audit-policies/{first['id']}").json()
    assert current["active"] is True


def test_policy_rejects_unknown_scanner(client: TestClient) -> None:
    response = client.post(
        "/api/v1/audit-policies",
        json={"name": "bad", "enabled_scanners": ["made-up-scanner"]},
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "invalid_request"


def test_policy_list_filters_active_versions(client: TestClient) -> None:
    create_policy(client)
    create_policy(client)

    response = client.get("/api/v1/audit-policies", params={"active": True})

    assert response.status_code == 200
    assert response.json()["meta"]["total"] == 1
    assert response.json()["items"][0]["version"] == 2
