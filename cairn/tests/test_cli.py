from click.testing import CliRunner

from cairn.cli import main


def test_help_exposes_control_sandbox_and_orchestrator_services() -> None:
    result = CliRunner().invoke(main, ["--help"])

    assert result.exit_code == 0
    assert "serve" in result.output
    assert "sandbox-serve" in result.output
    assert "orchestrate" in result.output
    assert "dispatch" not in result.output
    assert "Java source code audit" in result.output


def test_serve_help_has_no_sqlite_path_option() -> None:
    result = CliRunner().invoke(main, ["serve", "--help"])

    assert result.exit_code == 0
    assert "--db-path" not in result.output
    assert "--host" in result.output
    assert "--port" in result.output


def test_serve_requires_database_url(monkeypatch) -> None:
    monkeypatch.delenv("CAIRN_DATABASE_URL", raising=False)

    result = CliRunner().invoke(main, ["serve"])

    assert result.exit_code == 1
    assert "CAIRN_DATABASE_URL" in result.output


def test_sandbox_serve_requires_auth_token_file(monkeypatch) -> None:
    monkeypatch.delenv("CAIRN_SANDBOX_AUTH_TOKEN_FILE", raising=False)

    result = CliRunner().invoke(main, ["sandbox-serve"])

    assert result.exit_code == 1
    assert "CAIRN_SANDBOX_AUTH_TOKEN_FILE" in result.output


def test_orchestrate_requires_database_and_sandbox_token(monkeypatch) -> None:
    monkeypatch.delenv("CAIRN_DATABASE_URL", raising=False)
    monkeypatch.delenv("CAIRN_SANDBOX_AUTH_TOKEN_FILE", raising=False)

    result = CliRunner().invoke(main, ["orchestrate", "--once"])

    assert result.exit_code == 1
    assert "CAIRN_DATABASE_URL" in result.output
    assert "CAIRN_SANDBOX_AUTH_TOKEN_FILE" in result.output


def test_orchestrate_once_builds_settings_and_runs_worker(
    monkeypatch,
    tmp_path,
) -> None:  # noqa: ANN001
    token_file = tmp_path / "token"
    token_file.write_text("s" * 40)
    monkeypatch.setenv(
        "CAIRN_DATABASE_URL",
        "postgresql+psycopg://cairn:secret@127.0.0.1/cairn",
    )
    monkeypatch.setenv("CAIRN_SANDBOX_AUTH_TOKEN_FILE", str(token_file))
    captured: dict[str, object] = {}

    def fake_run(settings, *, once: bool) -> None:  # noqa: ANN001
        captured["settings"] = settings
        captured["once"] = once

    monkeypatch.setattr("cairn.cli._run_orchestrator", fake_run)

    result = CliRunner().invoke(main, ["orchestrate", "--once"])

    assert result.exit_code == 0, result.output
    assert captured["once"] is True
    assert captured["settings"].sandbox_auth_token_file == token_file


def test_serve_builds_audit_app_and_invokes_uvicorn(monkeypatch) -> None:
    monkeypatch.setenv(
        "CAIRN_DATABASE_URL",
        "postgresql+psycopg://cairn:secret@127.0.0.1/cairn",
    )
    captured: dict[str, object] = {}

    def fake_run(app, **kwargs) -> None:  # noqa: ANN001
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("cairn.cli.uvicorn.run", fake_run)

    result = CliRunner().invoke(
        main,
        [
            "serve",
            "--host",
            "127.0.0.1",
            "--port",
            "9000",
            "--log-level",
            "warning",
            "--no-access-log",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["app"].title == "Cairn Java Audit"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9000
    assert captured["log_level"] == "warning"
    assert captured["access_log"] is False


def test_sandbox_serve_builds_internal_app_and_invokes_uvicorn(
    monkeypatch,
    tmp_path,
) -> None:  # noqa: ANN001
    token_file = tmp_path / "token"
    token_file.write_text("s" * 40)
    monkeypatch.setenv("CAIRN_SANDBOX_AUTH_TOKEN_FILE", str(token_file))
    captured: dict[str, object] = {}

    def fake_run(app, **kwargs) -> None:  # noqa: ANN001
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr("cairn.cli.uvicorn.run", fake_run)

    result = CliRunner().invoke(
        main,
        [
            "sandbox-serve",
            "--host",
            "127.0.0.1",
            "--port",
            "9001",
            "--log-level",
            "warning",
            "--no-access-log",
        ],
    )

    assert result.exit_code == 0, result.output
    assert captured["app"].title == "Cairn Sandbox Manager"
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 9001
    assert captured["log_level"] == "warning"
    assert captured["access_log"] is False
