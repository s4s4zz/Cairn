from __future__ import annotations

from click.testing import CliRunner
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from cairn.cli import main
from cairn.server.persistence import models  # noqa: F401
from cairn.server.persistence.base import Base
from cairn.server.persistence.models.identity import AuditLogEntry, User


def test_cli_account_mutations_are_audited_without_passwords(
    monkeypatch,
    tmp_path,
) -> None:  # noqa: ANN001
    database_url = f"sqlite+pysqlite:///{tmp_path / 'cli-users.db'}"
    engine = create_engine(database_url)
    Base.metadata.create_all(engine)
    engine.dispose()
    monkeypatch.setenv("CAIRN_DATABASE_URL", database_url)
    monkeypatch.setenv("CAIRN_PASSWORD_HASH_MEMORY_KIB", "64")
    monkeypatch.setenv("CAIRN_PASSWORD_HASH_ITERATIONS", "1")
    monkeypatch.setenv("CAIRN_PASSWORD_HASH_LANES", "1")
    runner = CliRunner()

    created = runner.invoke(
        main,
        ["create-user", "--username", "cli-user", "--role", "viewer"],
        input="initial-long-password\ninitial-long-password\n",
    )
    password = runner.invoke(
        main,
        ["set-password", "--username", "cli-user"],
        input="replacement-password\nreplacement-password\n",
    )
    role = runner.invoke(
        main,
        ["set-role", "--username", "cli-user", "--role", "reviewer"],
    )

    assert created.exit_code == 0, created.output
    assert password.exit_code == 0, password.output
    assert role.exit_code == 0, role.output
    with Session(create_engine(database_url)) as session:
        user = session.scalar(select(User).where(User.username == "cli-user"))
        assert user is not None
        assert user.role == "reviewer"
        entries = list(
            session.scalars(
                select(AuditLogEntry).order_by(AuditLogEntry.created_at)
            )
        )
    assert [entry.action for entry in entries] == [
        "user_created",
        "user_password_changed",
        "user_updated",
    ]
    assert all(entry.actor_username == "system" for entry in entries)
    assert all(entry.detail["source"] == "cli" for entry in entries)
    serialized = " ".join(str(entry.detail) for entry in entries)
    assert "initial-long-password" not in serialized
    assert "replacement-password" not in serialized
