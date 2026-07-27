from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4

import pytest
import requests

from cairn.orchestrator.client import HttpSandboxClient
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.errors import OrchestratorError
from cairn.sandbox.contracts import SandboxCreateRequest, SnapshotArtifact


class FakeResponse:
    def __init__(self, status_code: int, payload: object) -> None:
        self.status_code = status_code
        self.payload = payload

    def json(self) -> object:
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = list(responses)
        self.headers: dict[str, str] = {}
        self.calls: list[dict[str, object]] = []
        self.closed = False

    def request(self, method: str, url: str, **kwargs) -> FakeResponse:  # noqa: ANN003
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response

    def close(self) -> None:
        self.closed = True


def settings(tmp_path: Path) -> OrchestratorSettings:
    token = tmp_path / "sandbox-token"
    token.write_text("s" * 48 + "\n")
    return OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_api_url="http://sandbox-manager.test:8001/",
        sandbox_auth_token_file=token,
    )


def snapshot() -> SnapshotArtifact:
    digest = "a" * 64
    return SnapshotArtifact(
        storage_key=f"sha256/{digest[:2]}/{digest}",
        sha256=digest,
        size_bytes=1024,
    )


def record_payload(
    request: SandboxCreateRequest,
    *,
    sandbox_id: UUID | None = None,
) -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "id": str(sandbox_id or uuid4()),
        "task_id": str(request.task_id) if request.task_id else None,
        "template": request.template.value,
        "operation": request.operation.value,
        "snapshot": request.snapshot.model_dump(mode="json"),
        "limits": {
            "cpu_millis": 1000,
            "memory_bytes": 512 * 1024 * 1024,
            "pids": 128,
            "disk_bytes": 1024 * 1024 * 1024,
            "output_bytes": 256 * 1024 * 1024,
            "tmpfs_bytes": 64 * 1024 * 1024,
            "timeout_seconds": 900,
        },
        "status": "created",
        "created_at": now.isoformat(),
        "deadline_at": (now + timedelta(seconds=60)).isoformat(),
        "started_at": None,
        "finished_at": None,
        "exit_code": None,
        "failure_code": None,
        "artifacts": [],
        "resources_destroyed": False,
    }


def test_http_client_sends_only_the_closed_create_contract(tmp_path: Path) -> None:
    task_id = uuid4()
    request = SandboxCreateRequest(
        template="analysis",
        operation="semgrep",
        snapshot=snapshot(),
        task_id=task_id,
    )
    fake_session = FakeSession([FakeResponse(201, record_payload(request))])
    client = HttpSandboxClient(settings(tmp_path), session=fake_session)  # type: ignore[arg-type]

    record = client.create(request)

    assert record.operation.value == "semgrep"
    assert fake_session.headers == {
        "Authorization": f"Bearer {'s' * 48}",
        "Accept": "application/json",
    }
    assert fake_session.calls == [
        {
            "method": "POST",
            "url": "http://sandbox-manager.test:8001/internal/v1/sandboxes",
            "json": request.model_dump(mode="json"),
            "timeout": 15,
        }
    ]
    assert set(fake_session.calls[0]["json"]) == {
        "template",
        "operation",
        "snapshot",
        "task_id",
        "limits",
        "semantic",
    }
    # The point of this assertion is what is *absent*: nothing the caller sends
    # can choose an image, a command, an environment mapping, mounts,
    # capabilities, devices, ports or a network. `semantic` is a typed block
    # carrying a grant and a review scope, and it is null for every template
    # but `semantic`.
    assert fake_session.calls[0]["json"]["semantic"] is None
    client.close()
    assert fake_session.closed is True


@pytest.mark.parametrize(
    ("status_code", "payload", "expected_code", "retryable"),
    [
        (
            503,
            {"error_code": "SANDBOX_BACKEND_UNAVAILABLE"},
            "SANDBOX_BACKEND_UNAVAILABLE",
            True,
        ),
        (400, {"error_code": "untrusted_detail"}, "SANDBOX_API_REJECTED", False),
        (429, ValueError("not json"), "SANDBOX_API_REJECTED", True),
    ],
)
def test_http_client_maps_rejections_to_stable_errors(
    tmp_path: Path,
    status_code: int,
    payload: object,
    expected_code: str,
    retryable: bool,
) -> None:
    fake_session = FakeSession([FakeResponse(status_code, payload)])
    client = HttpSandboxClient(settings(tmp_path), session=fake_session)  # type: ignore[arg-type]

    with pytest.raises(OrchestratorError) as captured:
        client.get(uuid4())

    assert captured.value.error_code == expected_code
    assert captured.value.retryable is retryable


def test_http_client_rejects_invalid_success_and_wraps_transport_errors(
    tmp_path: Path,
) -> None:
    fake_session = FakeSession(
        [
            FakeResponse(200, {"status": "not-a-record"}),
            requests.ConnectionError("internal address must not leak"),
        ]
    )
    client = HttpSandboxClient(settings(tmp_path), session=fake_session)  # type: ignore[arg-type]

    with pytest.raises(OrchestratorError) as invalid:
        client.get(uuid4())
    with pytest.raises(OrchestratorError) as unavailable:
        client.get(uuid4())

    assert invalid.value.error_code == "SANDBOX_RESPONSE_INVALID"
    assert invalid.value.retryable is True
    assert unavailable.value.error_code == "SANDBOX_API_UNAVAILABLE"
    assert unavailable.value.retryable is True
    assert "internal address" not in unavailable.value.message
