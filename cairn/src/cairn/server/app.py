from contextlib import asynccontextmanager

from fastapi import FastAPI

from cairn import __version__
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.config import ServerSettings, get_settings
from cairn.server.errors import register_error_handlers
from cairn.server.persistence.session import configure_engine, dispose_engine
from cairn.server.routers import (
    artifacts,
    audit_runs,
    credentials,
    findings,
    health,
    policies,
    repositories,
    snapshots,
    uploads,
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
        repositories.router,
        credentials.router,
        uploads.router,
        snapshots.router,
        artifacts.router,
        policies.router,
        audit_runs.router,
        findings.router,
    ):
        application.include_router(audit_router, prefix=settings.api_prefix)

    @application.get("/", tags=["service"])
    def service_descriptor() -> dict[str, str]:
        return {
            "service": "Cairn Java Audit",
            "version": __version__,
            "api_prefix": settings.api_prefix,
            "docs": "/docs",
        }

    return application


app = create_app()
