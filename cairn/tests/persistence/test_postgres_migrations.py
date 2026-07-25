from io import StringIO
import os
from pathlib import Path

from alembic import command
from alembic.config import Config
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import make_url


def migration_config(database_url: str, *, output_buffer: StringIO | None = None) -> Config:
    project_dir = Path(__file__).resolve().parents[2]
    config = Config(project_dir / "alembic.ini", output_buffer=output_buffer)
    config.set_main_option("sqlalchemy.url", database_url)
    return config


def test_initial_migration_renders_ordered_postgresql_ddl() -> None:
    output = StringIO()
    config = migration_config(
        "postgresql+psycopg://cairn:cairn@127.0.0.1:55432/cairn_test",
        output_buffer=output,
    )

    command.upgrade(config, "head", sql=True)

    ddl = output.getvalue()
    assert ddl.index("CREATE TABLE repositories") < ddl.index("CREATE TABLE audit_runs")
    assert ddl.index("CREATE TABLE audit_tasks") < ddl.index("CREATE TABLE artifacts")
    assert ddl.index("CREATE TABLE artifacts") < ddl.index("CREATE TABLE source_snapshots")
    assert (
        "ALTER TABLE audit_runs ADD CONSTRAINT "
        "fk_audit_runs_snapshot_id_source_snapshots" in ddl
    )
    assert "INSERT INTO audit_policies" in ddl
    assert "'comprehensive'" in ddl


@pytest.mark.postgres
def test_initial_migration_upgrades_and_downgrades() -> None:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL is not configured")
    assert make_url(database_url).get_backend_name() == "postgresql"

    config = migration_config(database_url)

    command.upgrade(config, "head")
    engine = create_engine(database_url)
    try:
        inspector = inspect(engine)
        assert {
            "repositories",
            "source_snapshots",
            "audit_policies",
            "audit_runs",
            "audit_tasks",
            "artifacts",
            "findings",
            "finding_locations",
            "evidence",
            "verifications",
            "audit_coverage",
            "human_reviews",
            "reports",
            "audit_facts",
            "audit_intents",
            "audit_intent_sources",
        } <= set(inspector.get_table_names())
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("select count(*) from alembic_version")
                ).scalar_one()
                == 1
            )
    finally:
        engine.dispose()

    command.downgrade(config, "base")
    engine = create_engine(database_url)
    try:
        assert "audit_runs" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()

    command.upgrade(config, "head")
