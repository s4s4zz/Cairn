from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse

from cairn import __version__
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.config import ServerSettings, get_settings
from cairn.server.errors import register_error_handlers
from cairn.server.persistence.session import configure_engine, dispose_engine
from cairn.server.routers import (
    artifacts,
    audit_logs,
    audit_runs,
    auth,
    credentials,
    findings,
    health,
    model_settings,
    policies,
    repositories,
    snapshots,
    uploads,
    users,
)

_WORKBENCH_INDEX_HEADERS = {"Cache-Control": "no-cache, no-store, must-revalidate"}
_WORKBENCH_ASSET_HEADERS = {
    "Cache-Control": "public, max-age=31536000, immutable",
}


def _is_reserved_path(path: str, api_prefix: str) -> bool:
    """Keep SPA fallback responses away from service and API namespaces."""

    normalized = f"/{path.lstrip('/')}"
    reserved = (
        "/api",
        api_prefix.rstrip("/"),
        "/docs",
        "/redoc",
        "/openapi.json",
        "/health",
    )
    return any(
        prefix and (normalized == prefix or normalized.startswith(f"{prefix}/"))
        for prefix in reserved
    )


def _register_service_root(application: FastAPI, settings: ServerSettings) -> None:
    static_root = settings.static_root.resolve()
    index = static_root / "index.html"

    if not index.is_file():
        @application.get("/", tags=["service"])
        def service_descriptor() -> dict[str, str]:
            return {
                "service": "Cairn Java Audit",
                "version": __version__,
                "api_prefix": settings.api_prefix,
                "docs": "/docs",
            }

        return

    @application.get("/", include_in_schema=False, response_class=FileResponse)
    def workbench_index() -> FileResponse:
        return FileResponse(
            index,
            media_type="text/html",
            headers=_WORKBENCH_INDEX_HEADERS,
        )

    @application.get(
        "/{frontend_path:path}",
        include_in_schema=False,
        response_class=FileResponse,
    )
    def workbench_asset_or_route(frontend_path: str) -> FileResponse:
        if _is_reserved_path(frontend_path, settings.api_prefix):
            raise HTTPException(status_code=404)

        candidate = (static_root / frontend_path).resolve()
        try:
            candidate.relative_to(static_root)
        except ValueError as exc:
            raise HTTPException(status_code=404) from exc
        if candidate.is_file():
            headers = (
                _WORKBENCH_ASSET_HEADERS
                if frontend_path.startswith("assets/")
                else _WORKBENCH_INDEX_HEADERS
            )
            return FileResponse(candidate, headers=headers)

        # Vite client-side routes have no suffix. A missing .js/.css/map file
        # must stay a 404 instead of receiving HTML with a successful status.
        if Path(frontend_path).suffix:
            raise HTTPException(status_code=404)
        return FileResponse(
            index,
            media_type="text/html",
            headers=_WORKBENCH_INDEX_HEADERS,
        )


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        settings.ingestion_work_root.mkdir(parents=True, exist_ok=True)
        _app.state.artifact_store = LocalArtifactStore(settings.artifact_root)
        configure_engine(settings.database_url, sql_echo=settings.sql_echo)
        try:
            yield
        finally:
            dispose_engine()

    application = FastAPI(
        title="Cairn Java Audit",
        description="Single-tenant Java source code audit platform",
        version=__version__,
        lifespan=lifespan,
    )
    application.state.settings = settings
    register_error_handlers(application)
    application.include_router(health.router)
    for audit_router in (
        auth.router,
        users.router,
        audit_logs.router,
        repositories.router,
        credentials.router,
        model_settings.router,
        uploads.router,
        snapshots.router,
        artifacts.router,
        policies.router,
        audit_runs.router,
        findings.router,
    ):
        application.include_router(audit_router, prefix=settings.api_prefix)

    _register_service_root(application, settings)

    return application


app = create_app()
