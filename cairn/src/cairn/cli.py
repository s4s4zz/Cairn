import click
from pydantic import ValidationError
import time
import uvicorn

from cairn.orchestrator.config import OrchestratorSettings
from cairn.sandbox.config import SandboxSettings
from cairn.server.config import ServerSettings


@click.group()
def main() -> None:
    """Cairn - single-tenant Java source code audit platform."""


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option(
    "--port",
    default=8000,
    show_default=True,
    type=click.IntRange(1, 65535),
    help="Bind port",
)
@click.option(
    "--log-level",
    default="info",
    show_default=True,
    type=click.Choice(
        ["critical", "error", "warning", "info", "debug", "trace"],
        case_sensitive=False,
    ),
    help="Uvicorn log level",
)
@click.option(
    "--access-log/--no-access-log",
    default=True,
    show_default=True,
    help="Enable Uvicorn access log",
)
def serve(
    host: str,
    port: int,
    log_level: str,
    access_log: bool,
) -> None:
    """Start the Java audit API server."""
    try:
        settings = ServerSettings()
    except ValidationError as exc:
        raise click.ClickException(
            "CAIRN_DATABASE_URL must be configured before starting the server"
        ) from exc

    from cairn.server.app import create_app

    uvicorn.run(
        create_app(settings),
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command("sandbox-serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option(
    "--port",
    default=8001,
    show_default=True,
    type=click.IntRange(1, 65535),
    help="Bind port",
)
@click.option(
    "--log-level",
    default="info",
    show_default=True,
    type=click.Choice(
        ["critical", "error", "warning", "info", "debug", "trace"],
        case_sensitive=False,
    ),
    help="Uvicorn log level",
)
@click.option(
    "--access-log/--no-access-log",
    default=False,
    show_default=True,
    help="Enable Uvicorn access log",
)
def sandbox_serve(
    host: str,
    port: int,
    log_level: str,
    access_log: bool,
) -> None:
    """Start the restricted internal Sandbox Manager."""
    try:
        settings = SandboxSettings()
    except ValidationError as exc:
        raise click.ClickException(
            "CAIRN_SANDBOX_AUTH_TOKEN_FILE must be configured before "
            "starting Sandbox Manager"
        ) from exc

    from cairn.sandbox.app import create_sandbox_app

    uvicorn.run(
        create_sandbox_app(settings),
        host=host,
        port=port,
        log_level=log_level.lower(),
        access_log=access_log,
    )


@main.command()
@click.option(
    "--once",
    is_flag=True,
    help="Process at most one eligible AuditRun and exit",
)
def orchestrate(once: bool) -> None:
    """Run deterministic Java audit orchestration."""
    try:
        settings = OrchestratorSettings()
    except ValidationError as exc:
        raise click.ClickException(
            "CAIRN_DATABASE_URL and CAIRN_SANDBOX_AUTH_TOKEN_FILE must be "
            "configured before starting the Orchestrator"
        ) from exc
    try:
        _run_orchestrator(settings, once=once)
    except ValueError as exc:
        raise click.ClickException(str(exc)) from exc


def _run_orchestrator(
    settings: OrchestratorSettings,
    *,
    once: bool,
) -> None:
    from cairn.orchestrator.client import HttpSandboxClient
    from cairn.orchestrator.engine import DeterministicOrchestrator
    from cairn.server.artifacts.local import LocalArtifactStore
    from cairn.server.persistence.session import (
        configure_engine,
        dispose_engine,
        session_scope,
    )

    settings.ingestion_work_root.mkdir(parents=True, exist_ok=True)
    artifact_store = LocalArtifactStore(settings.artifact_root)
    configure_engine(settings.database_url, sql_echo=settings.sql_echo)
    sandbox = HttpSandboxClient(settings)
    try:
        while True:
            with session_scope() as session:
                DeterministicOrchestrator(
                    session,
                    settings,
                    artifact_store,
                    sandbox,
                ).process_next()
            if once:
                return
            time.sleep(settings.orchestrator_poll_interval_seconds)
    finally:
        sandbox.close()
        dispose_engine()
