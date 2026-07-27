import click
from pydantic import ValidationError
from pathlib import Path
import time
import uvicorn

from cairn.analysis.contracts import ToolStatus
from cairn.gateway.config import GatewaySettings
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


@main.command("gateway-serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option(
    "--port",
    default=8002,
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
def gateway_serve(
    host: str,
    port: int,
    log_level: str,
    access_log: bool,
) -> None:
    """Start the LLM Gateway egress proxy."""
    try:
        settings = GatewaySettings()
    except ValidationError as exc:
        raise click.ClickException(
            "CAIRN_LLM_API_KEY_FILE and CAIRN_LLM_GRANT_KEY_FILE must be "
            "configured before starting the LLM Gateway"
        ) from exc

    from cairn.gateway.app import create_gateway_app

    uvicorn.run(
        create_gateway_app(settings),
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


@main.command("semantic-smoke")
@click.option(
    "--source",
    required=True,
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    help="A Java source tree to review, mounted read-only in production",
)
@click.option(
    "--gateway-url",
    default="http://127.0.0.1:8002",
    show_default=True,
    help="Origin of a running LLM Gateway",
)
@click.option(
    "--grant-key-file",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="The Gateway's grant signing key, to mint a short-lived grant",
)
@click.option("--module", default=".", show_default=True, help="Scope module")
@click.option(
    "--attack-surface",
    default="HTTP endpoint",
    show_default=True,
    help="Scope attack surface",
)
@click.option(
    "--category",
    default="sql-injection",
    show_default=True,
    help="Scope audit category",
)
@click.option(
    "--max-turns",
    default=8,
    show_default=True,
    type=click.IntRange(2, 64),
    help="Turn ceiling for this one review",
)
def semantic_smoke(
    source: Path,
    gateway_url: str,
    grant_key_file: Path,
    module: str,
    attack_surface: str,
    category: str,
    max_turns: int,
) -> None:
    """Run one real semantic review through a running LLM Gateway.

    The one step the test suite cannot cover: it needs a live upstream model
    key, which exists only inside the Gateway. Everything else in the semantic
    stage is verified against a stub upstream, so this confirms the last hop
    and nothing more. Prints cache_read_input_tokens, which is how prompt-cache
    effectiveness gets confirmed against the real endpoint.
    """

    from datetime import UTC, datetime, timedelta

    from cairn.gateway.config import read_key_file
    from cairn.gateway.tokens import ModelGrant, mint_grant
    from cairn.semantic.broker import ToolBroker
    from cairn.semantic.client import DEFAULT_MODEL, SemanticModelClient
    from cairn.semantic.findings import ReviewScope
    from cairn.semantic.review import SemanticReviewer

    scope = ReviewScope(
        module=module,
        attack_surface=attack_surface,
        category=category,
    )
    grant = mint_grant(
        ModelGrant(
            audit_run_id="smoke",
            task_id="smoke",
            worker="semantic-smoke",
            model=DEFAULT_MODEL,
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
            max_requests=max_turns + 2,
            max_output_tokens=16_000 * (max_turns + 2),
        ),
        read_key_file(grant_key_file),
    )
    reviewer = SemanticReviewer(
        SemanticModelClient(base_url=gateway_url, grant_token=grant),
        ToolBroker(source),
        scope=scope,
        max_turns=max_turns,
    )
    result = reviewer.run()

    click.echo(f"scope       {result.scope_key}")
    click.echo(f"status      {result.status.value}")
    click.echo(f"reason      {result.reason_code or '-'}")
    click.echo(f"model       {result.model}")
    click.echo(f"findings    {len(result.findings)}")
    click.echo(f"rejections  {len(result.rejections)}")
    for rejection in result.rejections:
        click.echo(f"  [{rejection.ordinal}] {rejection.reason_code}: {rejection.detail}")
    for warning in result.warnings:
        click.echo(f"  warning {warning}")
    usage = result.usage
    click.echo(
        f"usage       requests={usage.requests} "
        f"in={usage.input_tokens} out={usage.output_tokens} "
        f"cache_read={usage.cache_read_input_tokens} "
        f"cache_write={usage.cache_creation_input_tokens}"
    )
    if usage.requests > 1 and usage.cache_read_input_tokens == 0:
        click.echo(
            "note        no cached prefix was read; the system prompt may have "
            "fallen below the model's minimum cacheable length"
        )
    if result.status is not ToolStatus.COMPLETED:
        raise click.ClickException(
            f"semantic review did not complete: {result.reason_code}"
        )
