from __future__ import annotations

from contextlib import asynccontextmanager
from uuid import UUID

from fastapi import Depends, FastAPI, status
from fastapi.responses import FileResponse

from cairn import __version__
from cairn.sandbox.auth import require_internal_auth
from cairn.sandbox.config import (
    SandboxSettings,
    get_sandbox_settings,
    read_auth_token,
)
from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxRecord,
    SandboxWaitRequest,
)
from cairn.sandbox.docker_backend import RootlessDockerBackend
from cairn.sandbox.manager import SandboxManager, SandboxReaper
from cairn.server.errors import register_error_handlers


def create_sandbox_app(
    settings: SandboxSettings | None = None,
    *,
    manager: SandboxManager | None = None,
) -> FastAPI:
    settings = settings or get_sandbox_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        auth_token = read_auth_token(settings.auth_token_file)
        owned_manager = manager is None
        active_manager = manager or SandboxManager(
            settings,
            RootlessDockerBackend(settings),
        )
        application.state.auth_token = auth_token
        application.state.sandbox_manager = active_manager
        reaper: SandboxReaper | None = None
        try:
            active_manager.validate_ready()
            active_manager.reconcile()
            reaper = SandboxReaper(
                active_manager,
                settings.reap_interval_seconds,
            )
            reaper.start()
            yield
        finally:
            if reaper is not None:
                reaper.stop()
            if owned_manager:
                active_manager.close()

    application = FastAPI(
        title="Cairn Sandbox Manager",
        description="Restricted internal execution service",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    register_error_handlers(application)

    @application.get("/health/live", tags=["health"])
    def live() -> dict[str, str]:
        return {"status": "ok"}

    @application.get("/health/ready", tags=["health"])
    def ready() -> dict[str, str]:
        application.state.sandbox_manager.validate_ready()
        return {"status": "ready"}

    internal_dependencies = [Depends(require_internal_auth)]

    @application.post(
        "/internal/v1/sandboxes",
        response_model=SandboxRecord,
        status_code=status.HTTP_201_CREATED,
        dependencies=internal_dependencies,
    )
    def create_sandbox(request: SandboxCreateRequest) -> SandboxRecord:
        return application.state.sandbox_manager.create(request)

    @application.get(
        "/internal/v1/sandboxes/{sandbox_id}",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def get_sandbox(sandbox_id: UUID) -> SandboxRecord:
        return application.state.sandbox_manager.get(sandbox_id)

    @application.post(
        "/internal/v1/sandboxes/{sandbox_id}/start",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def start_sandbox(sandbox_id: UUID) -> SandboxRecord:
        return application.state.sandbox_manager.start(sandbox_id)

    @application.post(
        "/internal/v1/sandboxes/{sandbox_id}/wait",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def wait_for_sandbox(
        sandbox_id: UUID,
        request: SandboxWaitRequest,
    ) -> SandboxRecord:
        return application.state.sandbox_manager.wait(
            sandbox_id,
            request.timeout_seconds,
        )

    @application.post(
        "/internal/v1/sandboxes/{sandbox_id}/cancel",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def cancel_sandbox(sandbox_id: UUID) -> SandboxRecord:
        return application.state.sandbox_manager.cancel(sandbox_id)

    @application.post(
        "/internal/v1/sandboxes/{sandbox_id}/artifacts",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def collect_sandbox_artifacts(sandbox_id: UUID) -> SandboxRecord:
        return application.state.sandbox_manager.collect_artifacts(sandbox_id)

    @application.delete(
        "/internal/v1/sandboxes/{sandbox_id}",
        response_model=SandboxRecord,
        dependencies=internal_dependencies,
    )
    def destroy_sandbox(sandbox_id: UUID) -> SandboxRecord:
        return application.state.sandbox_manager.destroy(sandbox_id)

    @application.get(
        "/internal/v1/sandbox-artifacts/{sha256}",
        dependencies=internal_dependencies,
        response_class=FileResponse,
    )
    def download_sandbox_artifact(sha256: str) -> FileResponse:
        path = application.state.sandbox_manager.resolve_artifact(sha256)
        return FileResponse(
            path,
            media_type="application/x-tar",
            filename=f"{sha256}.tar",
            headers={"ETag": f'"{sha256}"'},
        )

    return application
