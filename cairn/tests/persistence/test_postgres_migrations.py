from io import StringIO
import os
from pathlib import Path
from uuid import UUID

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
    assert "CREATE TRIGGER trg_source_snapshots_ready_immutable" in ddl
    assert "CREATE TABLE encrypted_secrets" in ddl
    assert "CREATE TABLE source_uploads" in ddl
    assert "source_upload" in ddl
    assert "ADD COLUMN scope_key VARCHAR(128)" in ddl
    assert "ADD COLUMN sandbox_id UUID" in ddl
    assert "uq_audit_tasks_run_scope_key" in ddl
    assert "uq_audit_tasks_sandbox_id" in ddl
    assert "uq_artifacts_task_sha_kind" in ddl
    assert "CREATE TABLE users" in ddl
    assert "CREATE TABLE user_sessions" in ddl
    assert "CREATE TABLE audit_log_entries" in ddl
    assert "ADD COLUMN jvm_artifact_count INTEGER DEFAULT 0 NOT NULL" in ddl
    assert "ADD COLUMN input_kind VARCHAR(16) DEFAULT 'source' NOT NULL" in ddl
    assert "'binary_upload'" in ddl
    assert "input_kind IN ('source', 'bytecode', 'hybrid')" in ddl
    assert "jvm_artifact_count >= 0" in ddl
    assert "ADD COLUMN origin_kind VARCHAR(16) DEFAULT 'source' NOT NULL" in ddl
    assert "ADD COLUMN bytecode_offset INTEGER" in ddl
    assert "ADD COLUMN decompiled_artifact_id UUID" in ddl
    assert "origin_kind IN ('source', 'bytecode', 'config', 'decompiled')" in ddl
    assert "fk_finding_locations_decompiled_artifact_id_artifacts" in ddl
    assert ddl.index("CREATE TABLE users") < ddl.index("CREATE TABLE user_sessions")
    assert ddl.index("CREATE TABLE users") < ddl.index(
        "CREATE TABLE audit_log_entries"
    )
    assert "CREATE INDEX ix_user_sessions_user_id" in ddl
    assert "CREATE INDEX ix_audit_log_entries_created_at" in ddl
    assert "CREATE INDEX ix_audit_log_entries_action" in ddl
    assert "CREATE INDEX ix_audit_log_entries_target" in ddl


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
        assert "audit_runs" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
    command.downgrade(config, "base")
    engine = create_engine(database_url)
    try:
        assert "audit_runs" not in inspect(engine).get_table_names()
    finally:
        engine.dispose()
    command.upgrade(config, "head")


@pytest.mark.postgres
def test_cp1_cp2_migrations_backfill_v1_rows_and_refuse_lossy_downgrade() -> None:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if database_url is None:
        pytest.skip("TEST_DATABASE_URL is not configured")
    assert make_url(database_url).get_backend_name() == "postgresql"

    config = migration_config(database_url)
    command.downgrade(config, "base")
    command.upgrade(config, "20260728_0007")
    engine = create_engine(database_url)
    repository_id = UUID("00000000-0000-0000-0000-000000000701")
    artifact_id = UUID("00000000-0000-0000-0000-000000000702")
    snapshot_id = UUID("00000000-0000-0000-0000-000000000703")
    run_id = UUID("00000000-0000-0000-0000-000000000704")
    finding_id = UUID("00000000-0000-0000-0000-000000000705")
    source_location_id = UUID("00000000-0000-0000-0000-000000000706")
    binary_location_id = UUID("00000000-0000-0000-0000-000000000707")
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO repositories "
                    "(id, name, source_type, created_by, created_at, updated_at) "
                    "VALUES (:id, 'migration-v1', 'zip', 'fixture', now(), now())"
                ),
                {"id": repository_id},
            )
            connection.execute(
                text(
                    "INSERT INTO artifacts "
                    "(id, audit_run_id, kind, storage_key, sha256, size_bytes, "
                    "media_type, access_level, produced_by_task_id, created_at) "
                    "VALUES (:id, NULL, 'source_snapshot', :storage_key, :sha, 1, "
                    "'application/x-tar', 'sensitive', NULL, now())"
                ),
                {
                    "id": artifact_id,
                    "storage_key": f"sha256/{'a' * 2}/{'a' * 64}",
                    "sha": "a" * 64,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO source_snapshots "
                    "(id, repository_id, content_sha256, artifact_id, file_count, "
                    "total_bytes, java_file_count, build_system, status, created_at) "
                    "VALUES (:id, :repository_id, :sha, :artifact_id, 1, 1, 1, "
                    "'unknown', 'ready', now())"
                ),
                {
                    "id": snapshot_id,
                    "repository_id": repository_id,
                    "artifact_id": artifact_id,
                    "sha": "b" * 64,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO audit_runs "
                    "(id, repository_id, source_request, snapshot_id, policy_id, "
                    "policy_version, status, current_stage, progress, warning_count, "
                    "created_by, created_at) VALUES "
                    "(:id, :repository_id, '{}'::json, :snapshot_id, "
                    "'00000000-0000-0000-0000-000000000001', 1, 'human_review', "
                    "'human_review', 90, 0, 'fixture', now())"
                ),
                {
                    "id": run_id,
                    "repository_id": repository_id,
                    "snapshot_id": snapshot_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO findings "
                    "(id, audit_run_id, fingerprint, title, description, category, "
                    "cwe_id, severity, confidence, status, attack_preconditions, "
                    "impact, remediation, runtime_verification, discovered_by, "
                    "first_seen_at, updated_at) VALUES "
                    "(:id, :run_id, :fingerprint, 'V1 finding', 'description', "
                    "'injection', 'CWE-89', 'high', 'high', 'candidate', "
                    "'precondition', 'impact', 'remediation', 'unverified', "
                    "'fixture', now(), now())"
                ),
                {"id": finding_id, "run_id": run_id, "fingerprint": "c" * 64},
            )
            connection.execute(
                text(
                    "INSERT INTO finding_locations "
                    "(id, finding_id, role, file_path, start_line, end_line, symbol, "
                    "code_snippet, snapshot_sha, ordinal) VALUES "
                    "(:id, :finding_id, 'sink', 'src/V1.java', 7, 7, 'V1.run', "
                    "'sink();', :sha, 0)"
                ),
                {
                    "id": source_location_id,
                    "finding_id": finding_id,
                    "sha": "b" * 64,
                },
            )

        command.upgrade(config, "20260729_0008")
        with engine.connect() as connection:
            assert connection.execute(
                text(
                    "SELECT input_kind, jvm_artifact_count FROM source_snapshots "
                    "WHERE id = :id"
                ),
                {"id": snapshot_id},
            ).one() == ("source", 0)

        command.upgrade(config, "20260729_0009")
        with engine.connect() as connection:
            source_row = connection.execute(
                text(
                    "SELECT origin_kind, file_path, start_line, end_line, "
                    "code_snippet, container_path, entry_path, bytecode_offset "
                    "FROM finding_locations WHERE id = :id"
                ),
                {"id": source_location_id},
            ).one()
            assert source_row == (
                "source",
                "src/V1.java",
                7,
                7,
                "sink();",
                None,
                None,
                None,
            )

        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO finding_locations "
                    "(id, finding_id, role, origin_kind, file_path, start_line, "
                    "end_line, symbol, code_snippet, container_path, entry_path, "
                    "class_name, method_name, method_descriptor, bytecode_offset, "
                    "snapshot_sha, ordinal) VALUES "
                    "(:id, :finding_id, 'sink', 'bytecode', NULL, NULL, NULL, "
                    "'fixture.BinaryAction.lookup', NULL, 'sample.war', "
                    "'WEB-INF/classes/fixture/BinaryAction.class', "
                    "'fixture.BinaryAction', 'lookup', '()V', 7, :sha, 1)"
                ),
                {
                    "id": binary_location_id,
                    "finding_id": finding_id,
                    "sha": "b" * 64,
                },
            )

        with pytest.raises(
            RuntimeError,
            match="cannot downgrade CodeLocationV2 while binary locations exist",
        ):
            command.downgrade(config, "20260729_0008")
        with engine.connect() as connection:
            assert connection.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one() == "20260729_0009"

        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM finding_locations WHERE id = :id"),
                {"id": binary_location_id},
            )
        command.downgrade(config, "20260729_0008")
        assert "origin_kind" not in {
            column["name"]
            for column in inspect(engine).get_columns("finding_locations")
        }
    finally:
        engine.dispose()
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
            "encrypted_secrets",
            "source_uploads",
            "users",
            "user_sessions",
            "audit_log_entries",
        } <= set(inspector.get_table_names())
        artifact_columns = {
            column["name"]: column for column in inspector.get_columns("artifacts")
        }
        assert artifact_columns["audit_run_id"]["nullable"] is True
        artifact_uniques = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints("artifacts")
        }
        assert "uq_artifacts_storage_key" not in artifact_uniques
        assert "uq_artifacts_task_sha_kind" in artifact_uniques
        task_columns = {
            column["name"]: column
            for column in inspector.get_columns("audit_tasks")
        }
        assert task_columns["scope_key"]["nullable"] is False
        assert task_columns["sandbox_id"]["nullable"] is True
        snapshot_columns = {
            column["name"]: column
            for column in inspector.get_columns("source_snapshots")
        }
        assert snapshot_columns["input_kind"]["nullable"] is False
        assert snapshot_columns["jvm_artifact_count"]["nullable"] is False
        location_columns = {
            column["name"]: column
            for column in inspector.get_columns("finding_locations")
        }
        assert location_columns["origin_kind"]["nullable"] is False
        assert location_columns["file_path"]["nullable"] is True
        assert location_columns["start_line"]["nullable"] is True
        assert location_columns["end_line"]["nullable"] is True
        assert location_columns["code_snippet"]["nullable"] is True
        assert {
            "container_path",
            "entry_path",
            "class_name",
            "method_name",
            "method_descriptor",
            "bytecode_offset",
            "decompiled_artifact_id",
            "decompiled_start_line",
            "decompiled_end_line",
        } <= set(location_columns)
        task_uniques = {
            constraint["name"]
            for constraint in inspector.get_unique_constraints("audit_tasks")
        }
        assert {
            "uq_audit_tasks_run_scope_key",
            "uq_audit_tasks_sandbox_id",
        } <= task_uniques
        with engine.connect() as connection:
            assert (
                connection.execute(
                    text("select count(*) from alembic_version")
                ).scalar_one()
                == 1
            )
            assert (
                connection.execute(
                    text(
                        "select count(*) from pg_trigger "
                        "where tgname = 'trg_source_snapshots_ready_immutable'"
                    )
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
