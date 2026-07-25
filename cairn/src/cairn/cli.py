import click
from pydantic import ValidationError
import uvicorn

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
