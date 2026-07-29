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
            "CAIRN_LLM_GRANT_KEY_FILE plus either "
            "CAIRN_LLM_PROVIDER_CONFIG_FILE/CAIRN_LLM_CONFIG_KEY_FILE or the "
            "legacy CAIRN_LLM_API_KEY_FILE must be configured before starting "
            "the LLM Gateway"
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


@main.command("benchmarks")
@click.option(
    "--gold",
    "gold_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="closed-platform-gold-v1 manifest",
)
@click.option(
    "--audit-run",
    "audit_run_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, readable=True, path_type=Path),
    help="audit-run-export-v1 JSON",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, writable=True, path_type=Path),
    help="Write benchmark-result-v1 JSON here instead of stdout",
)
def benchmarks(
    gold_path: Path,
    audit_run_path: Path,
    output_path: Path | None,
) -> None:
    """Evaluate one AuditRun export against a closed-platform gold manifest."""

    from cairn.benchmarks.contracts import AuditRunExport, ClosedPlatformGoldManifest
    from cairn.benchmarks.runner import (
        BenchmarkInputError,
        evaluate_benchmark,
        load_contract,
        render_result,
    )

    try:
        gold = load_contract(gold_path, ClosedPlatformGoldManifest)
        audit_run = load_contract(audit_run_path, AuditRunExport)
        rendered = render_result(evaluate_benchmark(gold, audit_run))
        if output_path is None:
            click.echo(rendered, nl=False)
        else:
            output_path.write_text(rendered, encoding="utf-8")
    except BenchmarkInputError as exc:
        raise click.ClickException(str(exc)) from exc
    except OSError as exc:
        name = output_path.name if output_path is not None else "output"
        raise click.ClickException(f"cannot write benchmark result: {name}") from exc


def _user_session():
    """Open a database session for the account commands.

    Separate from the server process on purpose: creating the first admin has
    to work before anything is serving, and these commands are the only way an
    account is created — there is no bootstrap-from-environment path that would
    leave a password in a Compose file or a process listing.
    """

    from contextlib import contextmanager

    from cairn.server.config import ServerSettings
    from cairn.server.persistence.session import (
        configure_engine,
        dispose_engine,
        session_scope,
    )

    try:
        settings = ServerSettings()
    except ValidationError as exc:
        raise click.ClickException(
            "CAIRN_DATABASE_URL must be configured before managing accounts"
        ) from exc

    @contextmanager
    def scope():
        configure_engine(settings.database_url, sql_echo=settings.sql_echo)
        try:
            with session_scope() as session:
                yield settings, session
        finally:
            dispose_engine()

    return scope()


def _password_parameters(settings) -> object:
    from cairn.server.auth.passwords import Argon2Parameters

    return Argon2Parameters(
        memory_kib=settings.password_hash_memory_kib,
        iterations=settings.password_hash_iterations,
        lanes=settings.password_hash_lanes,
    )


def _record_cli_user_action(session, action, user, detail: dict[str, object]) -> None:
    from cairn.server.auth.audit_log import (
        SYSTEM_PRINCIPAL,
        AuditLogService,
    )

    AuditLogService(session).record(
        action,
        actor=SYSTEM_PRINCIPAL,
        target_type="user",
        target_id=user.id,
        detail={"source": "cli", **detail},
    )


@main.command("create-user")
@click.option("--username", required=True, help="Login name")
@click.option(
    "--role",
    required=True,
    type=click.Choice(["admin", "auditor", "reviewer", "viewer"]),
    help="Role from §9.8",
)
def create_user(username: str, role: str) -> None:
    """Create a local account, prompting for the password.

    The password is read from the terminal and never accepted as an option: a
    command-line password lands in the shell history and in `ps` output for
    every other user on the host.
    """

    from cairn.server.domain.enums import AuditLogAction, UserRole
    from cairn.server.errors import DomainError
    from cairn.server.services.users import UserService

    password = click.prompt(
        "Password",
        hide_input=True,
        confirmation_prompt=True,
    )
    with _user_session() as (settings, session):
        try:
            user = UserService(
                session,
                password_parameters=_password_parameters(settings),
            ).create(username, password, UserRole(role))
        except DomainError as exc:
            raise click.ClickException(f"{exc.error_code}: {exc.message}") from exc
        _record_cli_user_action(
            session,
            AuditLogAction.USER_CREATED,
            user,
            {"username": user.username, "role": user.role},
        )
        click.echo(f"created {user.username} ({user.role}) id={user.id}")


@main.command("list-users")
def list_users() -> None:
    """List local accounts."""

    from cairn.server.services.users import UserFilters, UserService

    with _user_session() as (_settings, session):
        users, total = UserService(session).list(UserFilters(limit=100))
        for user in users:
            state = "active" if user.is_active else "disabled"
            last_login = user.last_login_at.isoformat() if user.last_login_at else "-"
            click.echo(f"{user.username:<24} {user.role:<9} {state:<9} {last_login}")
        click.echo(f"total {total}")


@main.command("set-password")
@click.option("--username", required=True, help="Login name")
def set_password(username: str) -> None:
    """Reset an account's password and revoke its open sessions."""

    from datetime import timedelta

    from cairn.server.auth.sessions import SessionService
    from cairn.server.domain.enums import AuditLogAction
    from cairn.server.errors import DomainError, NotFoundError
    from cairn.server.services.users import UserService

    password = click.prompt(
        "Password",
        hide_input=True,
        confirmation_prompt=True,
    )
    with _user_session() as (settings, session):
        service = UserService(
            session,
            password_parameters=_password_parameters(settings),
        )
        user = service.by_username(username)
        if user is None:
            raise click.ClickException(str(NotFoundError("user", username).message))
        try:
            service.set_password(user, password)
        except DomainError as exc:
            raise click.ClickException(f"{exc.error_code}: {exc.message}") from exc
        revoked = SessionService(
            session,
            ttl=timedelta(minutes=settings.session_ttl_minutes),
        ).revoke_all_for_user(user.id)
        _record_cli_user_action(
            session,
            AuditLogAction.USER_PASSWORD_CHANGED,
            user,
            {"self_service": False},
        )
        click.echo(f"password updated for {user.username}; {revoked} session(s) revoked")


@main.command("set-role")
@click.option("--username", required=True, help="Login name")
@click.option(
    "--role",
    type=click.Choice(["admin", "auditor", "reviewer", "viewer"]),
    default=None,
    help="New role",
)
@click.option(
    "--active/--inactive",
    "is_active",
    default=None,
    help="Enable or disable the account",
)
def set_role(username: str, role: str | None, is_active: bool | None) -> None:
    """Change an account's role or activation."""

    from datetime import timedelta

    from cairn.server.auth.sessions import SessionService
    from cairn.server.domain.enums import AuditLogAction, UserRole
    from cairn.server.errors import DomainError, NotFoundError
    from cairn.server.services.users import UserService

    if role is None and is_active is None:
        raise click.ClickException("nothing to change: pass --role or --active/--inactive")
    with _user_session() as (settings, session):
        service = UserService(session)
        user = service.by_username(username)
        if user is None:
            raise click.ClickException(str(NotFoundError("user", username).message))
        try:
            service.update(
                user,
                role=UserRole(role) if role else None,
                is_active=is_active,
            )
        except DomainError as exc:
            raise click.ClickException(f"{exc.error_code}: {exc.message}") from exc
        SessionService(
            session,
            ttl=timedelta(minutes=settings.session_ttl_minutes),
        ).revoke_all_for_user(user.id)
        _record_cli_user_action(
            session,
            AuditLogAction.USER_UPDATED,
            user,
            {"role": user.role, "is_active": user.is_active},
        )
        state = "active" if user.is_active else "disabled"
        click.echo(f"{user.username} is now {user.role} ({state})")


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
