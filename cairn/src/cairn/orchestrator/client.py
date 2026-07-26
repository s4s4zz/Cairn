from __future__ import annotations

from collections.abc import Callable
from typing import Protocol
from uuid import UUID

import requests

from cairn.sandbox.config import read_auth_token
from cairn.sandbox.contracts import (
    ACTIVE_SANDBOX_STATUSES,
    SandboxCreateRequest,
    SandboxRecord,
)
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.errors import OrchestratorError


class SandboxBackend(Protocol):
    def create(self, request: SandboxCreateRequest) -> SandboxRecord: ...

    def start(self, sandbox_id: UUID) -> SandboxRecord: ...

    def get(self, sandbox_id: UUID) -> SandboxRecord: ...

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord: ...

    def cancel(self, sandbox_id: UUID) -> SandboxRecord: ...

    def collect(self, sandbox_id: UUID) -> SandboxRecord: ...

    def destroy(self, sandbox_id: UUID) -> SandboxRecord: ...


class HttpSandboxClient:
    def __init__(
        self,
        settings: OrchestratorSettings,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.base_url = settings.sandbox_api_url
        self.wait_seconds = settings.orchestrator_wait_seconds
        token = read_auth_token(settings.sandbox_auth_token_file).decode("ascii")
        self.session = session or requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
            }
        )

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        return self._request(
            "POST",
            "/internal/v1/sandboxes",
            json=request.model_dump(mode="json"),
        )

    def start(self, sandbox_id: UUID) -> SandboxRecord:
        return self._request(
            "POST",
            f"/internal/v1/sandboxes/{sandbox_id}/start",
        )

    def get(self, sandbox_id: UUID) -> SandboxRecord:
        return self._request(
            "GET",
            f"/internal/v1/sandboxes/{sandbox_id}",
        )

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        return self._request(
            "POST",
            f"/internal/v1/sandboxes/{sandbox_id}/wait",
            json={"timeout_seconds": timeout_seconds},
            timeout=max(timeout_seconds + 5, 10),
        )

    def cancel(self, sandbox_id: UUID) -> SandboxRecord:
        return self._request(
            "POST",
            f"/internal/v1/sandboxes/{sandbox_id}/cancel",
        )

    def collect(self, sandbox_id: UUID) -> SandboxRecord:
        return self._request(
            "POST",
            f"/internal/v1/sandboxes/{sandbox_id}/artifacts",
        )

    def destroy(self, sandbox_id: UUID) -> SandboxRecord:
        return self._request(
            "DELETE",
            f"/internal/v1/sandboxes/{sandbox_id}",
        )

    def wait_until_terminal(
        self,
        sandbox_id: UUID,
        *,
        should_cancel: Callable[[], bool] | None = None,
    ) -> SandboxRecord:
        while True:
            if should_cancel is not None and should_cancel():
                return self.cancel(sandbox_id)
            record = self.wait(sandbox_id, self.wait_seconds)
            if record.status not in ACTIVE_SANDBOX_STATUSES:
                return record

    def close(self) -> None:
        self.session.close()

    def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, object] | None = None,
        timeout: float = 15,
    ) -> SandboxRecord:
        try:
            response = self.session.request(
                method,
                f"{self.base_url}{path}",
                json=json,
                timeout=timeout,
            )
        except requests.RequestException as exc:
            raise OrchestratorError(
                "SANDBOX_API_UNAVAILABLE",
                "Sandbox Manager request failed",
                retryable=True,
            ) from exc
        if not 200 <= response.status_code < 300:
            error_code = "SANDBOX_API_REJECTED"
            try:
                payload = response.json()
                supplied = payload.get("error_code")
                if isinstance(supplied, str) and supplied.startswith("SANDBOX_"):
                    error_code = supplied
            except (ValueError, AttributeError):
                pass
            raise OrchestratorError(
                error_code,
                "Sandbox Manager rejected the request",
                retryable=response.status_code >= 500 or response.status_code == 429,
            )
        try:
            return SandboxRecord.model_validate(response.json())
        except (ValueError, TypeError) as exc:
            raise OrchestratorError(
                "SANDBOX_RESPONSE_INVALID",
                "Sandbox Manager returned an invalid response",
                retryable=True,
            ) from exc
