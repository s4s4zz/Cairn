from collections.abc import Generator
from uuid import UUID

from fastapi.testclient import TestClient
import pytest

from cairn.sandbox.app import create_sandbox_app
from cairn.sandbox.backend import BackendContainerStatus, BackendState
from cairn.sandbox.contracts import SandboxCreateRequest
from cairn.sandbox.manager import SandboxManager
from .test_manager import FakeBackend


@pytest.fixture
def sandbox_client(
    sandbox_settings,  # noqa: ANN001
) -> Generator[tuple[TestClient, SandboxManager, FakeBackend], None, None]:
    backend = FakeBackend()
    manager = SandboxManager(sandbox_settings, backend)
    app = create_sandbox_app(sandbox_settings, manager=manager)
    with TestClient(app) as client:
        yield client, manager, backend


def authorization() -> dict[str, str]:
    return {"Authorization": f"Bearer {'t' * 48}"}


def test_health_is_uncredentialed_but_internal_api_requires_token(
    sandbox_client,  # noqa: ANN001
) -> None:
    client, _manager, _backend = sandbox_client

    assert client.get("/health/live").status_code == 200
    response = client.get(
        "/internal/v1/sandboxes/00000000-0000-0000-0000-000000000001"
    )

    assert response.status_code == 401
    assert response.json()["error_code"] == "SANDBOX_UNAUTHORIZED"


def test_readiness_fails_when_backend_becomes_unavailable(
    sandbox_client,  # noqa: ANN001
) -> None:
    client, _manager, backend = sandbox_client
    backend.readiness_error = "SANDBOX_BACKEND_UNAVAILABLE"

    response = client.get("/health/ready")

    assert response.status_code == 503
    assert response.json()["error_code"] == "SANDBOX_BACKEND_UNAVAILABLE"


def test_internal_lifecycle_and_artifact_download(
    sandbox_client,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    client, manager, backend = sandbox_client
    request = SandboxCreateRequest(
        template="analysis",
        snapshot=snapshot_artifact,
    )

    created_response = client.post(
        "/internal/v1/sandboxes",
        headers=authorization(),
        json=request.model_dump(mode="json"),
    )
    assert created_response.status_code == 201
    sandbox_id = created_response.json()["id"]

    started = client.post(
        f"/internal/v1/sandboxes/{sandbox_id}/start",
        headers=authorization(),
    )
    assert started.json()["status"] == "running"

    record = manager.state_store.get(UUID(started.json()["id"]))
    output = manager.work_root / sandbox_id / "output"
    (output / "result.txt").write_text("sandbox evidence")
    backend.states[record.id] = BackendState(
        status=BackendContainerStatus.EXITED,
        exit_code=0,
    )
    waited = client.post(
        f"/internal/v1/sandboxes/{sandbox_id}/wait",
        headers=authorization(),
        json={"timeout_seconds": 1},
    )

    assert waited.status_code == 200
    body = waited.json()
    assert body["status"] == "succeeded"
    assert body["resources_destroyed"] is True
    digest = body["artifacts"][0]["sha256"]

    artifact = client.get(
        f"/internal/v1/sandbox-artifacts/{digest}",
        headers=authorization(),
    )
    assert artifact.status_code == 200
    assert artifact.headers["etag"] == f'"{digest}"'
    assert len(artifact.content) > 0


def test_internal_create_rejects_image_override(
    sandbox_client,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    client, _manager, _backend = sandbox_client
    response = client.post(
        "/internal/v1/sandboxes",
        headers=authorization(),
        json={
            "template": "analysis",
            "snapshot": snapshot_artifact.model_dump(mode="json"),
            "image": "attacker/image",
        },
    )

    assert response.status_code == 422
    assert response.json()["error_code"] == "invalid_request"


def test_internal_create_echoes_server_owned_operation_profile(
    sandbox_client,  # noqa: ANN001
    snapshot_artifact,  # noqa: ANN001
) -> None:
    client, _manager, _backend = sandbox_client
    request = SandboxCreateRequest(
        template="analysis",
        operation="semgrep",
        snapshot=snapshot_artifact,
    )

    response = client.post(
        "/internal/v1/sandboxes",
        headers=authorization(),
        json=request.model_dump(mode="json"),
    )

    assert response.status_code == 201
    assert response.json()["template"] == "analysis"
    assert response.json()["operation"] == "semgrep"


def test_manager_does_not_publish_openapi(
    sandbox_client,  # noqa: ANN001
) -> None:
    client, _manager, _backend = sandbox_client

    assert client.get("/openapi.json").status_code == 404
