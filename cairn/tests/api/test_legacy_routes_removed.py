from collections.abc import Mapping, Sequence

from fastapi.testclient import TestClient
import pytest


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("get", "/projects"),
        ("post", "/projects"),
        ("get", "/projects/proj_001"),
        ("put", "/projects/proj_001/status"),
        ("get", "/projects/proj_001/intents"),
        ("post", "/projects/proj_001/intents"),
        ("get", "/projects/proj_001/hints"),
        ("post", "/projects/proj_001/hints"),
        ("get", "/projects/proj_001/export"),
        ("get", "/settings"),
        ("put", "/settings"),
        ("get", "/api/v1/projects"),
    ],
)
def test_legacy_routes_return_404(
    client: TestClient,
    method: str,
    path: str,
) -> None:
    response = client.request(method, path, json={})
    assert response.status_code == 404


def _property_names(value: object) -> set[str]:
    names: set[str] = set()
    if isinstance(value, Mapping):
        properties = value.get("properties")
        if isinstance(properties, Mapping):
            names.update(str(name) for name in properties)
        for child in value.values():
            names.update(_property_names(child))
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        for child in value:
            names.update(_property_names(child))
    return names


def test_openapi_exposes_only_audit_domain_contracts(client: TestClient) -> None:
    document = client.get("/openapi.json").json()
    paths = set(document["paths"])
    assert paths == {
        "/",
        "/health/live",
        "/health/ready",
        "/api/v1/auth/login",
        "/api/v1/auth/logout",
        "/api/v1/auth/me",
        "/api/v1/auth/password",
        "/api/v1/users",
        "/api/v1/users/{user_id}",
        "/api/v1/users/{user_id}/password",
        "/api/v1/audit-logs",
        "/api/v1/model-provider",
        "/api/v1/model-provider/models",
        "/api/v1/repositories",
        "/api/v1/repositories/{repository_id}",
        "/api/v1/git-credentials",
        "/api/v1/git-credentials/{reference}",
        "/api/v1/uploads",
        "/api/v1/repositories/{repository_id}/snapshots",
        "/api/v1/snapshots/{snapshot_id}",
        "/api/v1/snapshots/{snapshot_id}/source",
        "/api/v1/artifacts/{artifact_id}",
        "/api/v1/reports",
        "/api/v1/reports/{report_id}",
        "/api/v1/audit-policies",
        "/api/v1/audit-policies/{policy_id}",
        "/api/v1/audit-runs",
        "/api/v1/audit-runs/{run_id}",
        "/api/v1/audit-runs/{run_id}/tasks",
        "/api/v1/audit-runs/{run_id}/coverage",
        "/api/v1/audit-runs/{run_id}/events",
        "/api/v1/audit-runs/{run_id}/cancel",
        "/api/v1/audit-runs/{run_id}/retry",
        "/api/v1/audit-runs/{run_id}/reports",
        "/api/v1/findings",
        "/api/v1/findings/{finding_id}",
        "/api/v1/findings/{finding_id}/review",
        "/api/v1/findings/{finding_id}/reverify",
    }

    schema_names = set(document["components"]["schemas"])
    assert not schema_names & {"Project", "Fact", "Intent", "Hint"}
    assert not _property_names(document) & {"origin", "goal", "bootstrap_enabled"}


def test_root_and_health_describe_audit_service(client: TestClient) -> None:
    root = client.get("/")
    assert root.status_code == 200
    assert root.json()["service"] == "Cairn Java Audit"
    assert root.json()["api_prefix"] == "/api/v1"
    assert root.json()["docs"] == "/docs"

    assert client.get("/health/live").json() == {"status": "ok"}
    assert client.get("/health/ready").json() == {
        "status": "ready",
        "database": "reachable",
    }
