"""Create the Java audit domain foundation schema.

Revision ID: 20260725_0001
Revises: none
Create Date: 2026-07-25
"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa



revision: str = "20260725_0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None




def _create_snapshot_foreign_key() -> None:
    name = op.f("fk_audit_runs_snapshot_id_source_snapshots")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("audit_runs") as batch_op:
            batch_op.create_foreign_key(
                name,
                "source_snapshots",
                ["snapshot_id"],
                ["id"],
                ondelete="RESTRICT",
            )
        return
    op.create_foreign_key(
        name,
        "audit_runs",
        "source_snapshots",
        ["snapshot_id"],
        ["id"],
        ondelete="RESTRICT",
    )


def _drop_snapshot_foreign_key() -> None:
    name = op.f("fk_audit_runs_snapshot_id_source_snapshots")
    if op.get_bind().dialect.name == "sqlite":
        with op.batch_alter_table("audit_runs") as batch_op:
            batch_op.drop_constraint(name, type_="foreignkey")
        return
    op.drop_constraint(name, "audit_runs", type_="foreignkey")


def _create_snapshot_immutability_guard() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE FUNCTION cairn_reject_ready_source_snapshot_update()
                RETURNS trigger AS $$
                BEGIN
                    IF OLD.status = 'ready' THEN
                        RAISE EXCEPTION 'ready source snapshots are immutable'
                            USING ERRCODE = 'check_violation';
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_source_snapshots_ready_immutable
                BEFORE UPDATE ON source_snapshots
                FOR EACH ROW
                EXECUTE FUNCTION cairn_reject_ready_source_snapshot_update()
                """
            )
        )
        return
    if op.get_bind().dialect.name == "sqlite":
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_source_snapshots_ready_immutable
                BEFORE UPDATE ON source_snapshots
                WHEN OLD.status = 'ready'
                BEGIN
                    SELECT RAISE(ABORT, 'ready source snapshots are immutable');
                END
                """
            )
        )


def _drop_snapshot_immutability_guard() -> None:
    if op.get_bind().dialect.name == "postgresql":
        op.execute(
            sa.text(
                "DROP TRIGGER IF EXISTS "
                "trg_source_snapshots_ready_immutable ON source_snapshots"
            )
        )
        op.execute(
            sa.text(
                "DROP FUNCTION IF EXISTS "
                "cairn_reject_ready_source_snapshot_update()"
            )
        )
        return
    if op.get_bind().dialect.name == "sqlite":
        op.execute(
            sa.text("DROP TRIGGER IF EXISTS trg_source_snapshots_ready_immutable")
        )


def upgrade() -> None:
    """Create the complete Java audit domain schema."""
    op.create_table('repositories',
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('source_type', sa.String(length=32), nullable=False),
    sa.Column('remote_url', sa.Text(), nullable=True),
    sa.Column('credential_ref', sa.String(length=255), nullable=True),
    sa.Column('default_branch', sa.String(length=255), nullable=True),
    sa.Column('created_by', sa.String(length=255), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("source_type IN ('git', 'zip', 'local_upload')", name=op.f('ck_repositories_source_type_values')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_repositories')),
    sa.UniqueConstraint('name', name='name_unique')
    )
    op.create_index('ix_repositories_name', 'repositories', ['name'], unique=False)
    op.create_table('audit_policies',
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('include_paths', sa.JSON(), nullable=False),
    sa.Column('exclude_paths', sa.JSON(), nullable=False),
    sa.Column('enabled_scanners', sa.JSON(), nullable=False),
    sa.Column('dynamic_verification', sa.String(length=16), nullable=False),
    sa.Column('severity_thresholds', sa.JSON(), nullable=False),
    sa.Column('resource_budget', sa.JSON(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("dynamic_verification IN ('required', 'preferred', 'disabled')", name=op.f('ck_audit_policies_dynamic_verification_values')),
    sa.CheckConstraint('version > 0', name=op.f('ck_audit_policies_version_positive')),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_policies')),
    sa.UniqueConstraint('name', 'version', name='name_version_unique')
    )
    op.create_index('ix_audit_policies_name', 'audit_policies', ['name'], unique=False)
    op.create_index('uq_audit_policies_active_name', 'audit_policies', ['name'], unique=True, postgresql_where=sa.text('active'), sqlite_where=sa.text('active = 1'))
    op.execute(
        sa.text(
            """
            INSERT INTO audit_policies (
                id, name, version, include_paths, exclude_paths,
                enabled_scanners, dynamic_verification,
                severity_thresholds, resource_budget, active, created_at
            ) VALUES (
                '00000000-0000-0000-0000-000000000001',
                'comprehensive',
                1,
                '["**"]',
                '[]',
                '["codeql", "config-rules", "dependency-check", "findsecbugs", "gitleaks", "semgrep", "trivy"]',
                'required',
                '{}',
                '{}',
                true,
                '2026-07-25T00:00:00+00:00'
            )
            """
        )
    )
    op.create_table('audit_runs',
    sa.Column('repository_id', sa.Uuid(), nullable=False),
    sa.Column('source_request', sa.JSON(), nullable=False),
    sa.Column('snapshot_id', sa.Uuid(), nullable=True),
    sa.Column('policy_id', sa.Uuid(), nullable=False),
    sa.Column('policy_version', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('current_stage', sa.String(length=32), nullable=True),
    sa.Column('progress', sa.Numeric(precision=5, scale=2), nullable=False),
    sa.Column('warning_count', sa.Integer(), nullable=False),
    sa.Column('failure_code', sa.String(length=128), nullable=True),
    sa.Column('failure_reason', sa.Text(), nullable=True),
    sa.Column('created_by', sa.String(length=255), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("current_stage IN ('ingesting', 'preprocessing', 'static_scanning', 'semantic_auditing', 'dynamic_verifying', 'machine_review', 'human_review', 'reporting')", name=op.f('ck_audit_runs_current_stage_values')),
    sa.CheckConstraint("status IN ('created', 'ingesting', 'preprocessing', 'static_scanning', 'semantic_auditing', 'dynamic_verifying', 'machine_review', 'human_review', 'reporting', 'completed', 'completed_with_warnings', 'cancelling', 'cancelled', 'failed')", name=op.f('ck_audit_runs_status_values')),
    sa.CheckConstraint('policy_version > 0', name=op.f('ck_audit_runs_policy_version_positive')),
    sa.CheckConstraint('progress >= 0 AND progress <= 100', name=op.f('ck_audit_runs_progress_percentage')),
    sa.CheckConstraint('warning_count >= 0', name=op.f('ck_audit_runs_warning_count_nonnegative')),
    sa.ForeignKeyConstraint(['policy_id'], ['audit_policies.id'], name=op.f('fk_audit_runs_policy_id_audit_policies'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], name=op.f('fk_audit_runs_repository_id_repositories'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_runs'))
    )
    op.create_index('ix_audit_runs_repository_id', 'audit_runs', ['repository_id'], unique=False)
    op.create_index('ix_audit_runs_status', 'audit_runs', ['status'], unique=False)
    op.create_table('audit_tasks',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('parent_task_id', sa.Uuid(), nullable=True),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('required_capabilities', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('worker_name', sa.String(length=255), nullable=True),
    sa.Column('attempt', sa.Integer(), nullable=False),
    sa.Column('max_attempts', sa.Integer(), nullable=False),
    sa.Column('timeout_seconds', sa.Integer(), nullable=False),
    sa.Column('input_artifact_ids', sa.JSON(), nullable=False),
    sa.Column('output_artifact_ids', sa.JSON(), nullable=False),
    sa.Column('error_code', sa.String(length=128), nullable=True),
    sa.Column('error_detail', sa.Text(), nullable=True),
    sa.Column('lease_expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("status IN ('queued', 'claimed', 'running', 'succeeded', 'failed', 'cancelled', 'skipped')", name=op.f('ck_audit_tasks_status_values')),
    sa.CheckConstraint("type IN ('inventory', 'build', 'sast', 'dependency_scan', 'secret_scan', 'config_scan', 'semantic_review', 'dynamic_verify', 'independent_verify', 'coverage_check', 'report')", name=op.f('ck_audit_tasks_type_values')),
    sa.CheckConstraint('attempt >= 0', name=op.f('ck_audit_tasks_attempt_nonnegative')),
    sa.CheckConstraint('max_attempts > 0', name=op.f('ck_audit_tasks_max_attempts_positive')),
    sa.CheckConstraint('timeout_seconds > 0', name=op.f('ck_audit_tasks_timeout_seconds_positive')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_audit_tasks_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['parent_task_id'], ['audit_tasks.id'], name=op.f('fk_audit_tasks_parent_task_id_audit_tasks'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_tasks'))
    )
    op.create_index('ix_audit_tasks_run_status', 'audit_tasks', ['audit_run_id', 'status'], unique=False)
    op.create_index('ix_audit_tasks_status_lease', 'audit_tasks', ['status', 'lease_expires_at'], unique=False)
    op.create_table('artifacts',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('storage_key', sa.String(length=1024), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=False),
    sa.Column('size_bytes', sa.BigInteger(), nullable=False),
    sa.Column('media_type', sa.String(length=255), nullable=False),
    sa.Column('access_level', sa.String(length=16), nullable=False),
    sa.Column('produced_by_task_id', sa.Uuid(), nullable=True),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("access_level IN ('normal', 'sensitive')", name=op.f('ck_artifacts_access_level_values')),
    sa.CheckConstraint("kind IN ('source_snapshot', 'scan_result', 'build_log', 'runtime_log', 'poc', 'report', 'other')", name=op.f('ck_artifacts_kind_values')),
    sa.CheckConstraint('size_bytes >= 0', name=op.f('ck_artifacts_size_bytes_nonnegative')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_artifacts_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['produced_by_task_id'], ['audit_tasks.id'], name=op.f('fk_artifacts_produced_by_task_id_audit_tasks'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_artifacts')),
    sa.UniqueConstraint('storage_key', name=op.f('uq_artifacts_storage_key'))
    )
    op.create_index('ix_artifacts_sha256', 'artifacts', ['sha256'], unique=False)
    op.create_table('source_snapshots',
    sa.Column('repository_id', sa.Uuid(), nullable=False),
    sa.Column('commit_sha', sa.String(length=128), nullable=True),
    sa.Column('content_sha256', sa.String(length=64), nullable=False),
    sa.Column('branch_or_tag', sa.String(length=255), nullable=True),
    sa.Column('artifact_id', sa.Uuid(), nullable=False),
    sa.Column('file_count', sa.Integer(), nullable=False),
    sa.Column('total_bytes', sa.Integer(), nullable=False),
    sa.Column('java_file_count', sa.Integer(), nullable=False),
    sa.Column('java_version', sa.String(length=64), nullable=True),
    sa.Column('build_system', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('failure_code', sa.String(length=128), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("build_system IN ('maven', 'gradle', 'mixed', 'unknown')", name=op.f('ck_source_snapshots_build_system_values')),
    sa.CheckConstraint("status IN ('creating', 'ready', 'rejected', 'failed')", name=op.f('ck_source_snapshots_status_values')),
    sa.CheckConstraint('file_count >= 0', name=op.f('ck_source_snapshots_file_count_nonnegative')),
    sa.CheckConstraint('java_file_count >= 0', name=op.f('ck_source_snapshots_java_file_count_nonnegative')),
    sa.CheckConstraint('total_bytes >= 0', name=op.f('ck_source_snapshots_total_bytes_nonnegative')),
    sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], name=op.f('fk_source_snapshots_artifact_id_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['repository_id'], ['repositories.id'], name=op.f('fk_source_snapshots_repository_id_repositories'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_source_snapshots')),
    sa.UniqueConstraint('artifact_id', name=op.f('uq_source_snapshots_artifact_id'))
    )
    op.create_index('ix_source_snapshots_content_sha256', 'source_snapshots', ['content_sha256'], unique=False)
    op.create_index(op.f('ix_source_snapshots_repository_id'), 'source_snapshots', ['repository_id'], unique=False)
    _create_snapshot_foreign_key()
    _create_snapshot_immutability_guard()
    op.create_table('audit_coverage',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('modules_total', sa.Integer(), nullable=False),
    sa.Column('modules_analyzed', sa.Integer(), nullable=False),
    sa.Column('java_files_total', sa.Integer(), nullable=False),
    sa.Column('java_files_analyzed', sa.Integer(), nullable=False),
    sa.Column('entrypoints_total', sa.Integer(), nullable=False),
    sa.Column('entrypoints_analyzed', sa.Integer(), nullable=False),
    sa.Column('sensitive_sinks_total', sa.Integer(), nullable=False),
    sa.Column('sensitive_sinks_analyzed', sa.Integer(), nullable=False),
    sa.Column('build_status', sa.String(length=16), nullable=False),
    sa.Column('static_tools_completed', sa.JSON(), nullable=False),
    sa.Column('skipped_paths', sa.JSON(), nullable=False),
    sa.Column('unsupported_components', sa.JSON(), nullable=False),
    sa.Column('coverage_warnings', sa.JSON(), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("build_status IN ('success', 'partial', 'failed')", name=op.f('ck_audit_coverage_build_status_values')),
    sa.CheckConstraint('entrypoints_analyzed <= entrypoints_total', name=op.f('ck_audit_coverage_entrypoints_within_total')),
    sa.CheckConstraint('entrypoints_analyzed >= 0', name=op.f('ck_audit_coverage_entrypoints_analyzed_nonnegative')),
    sa.CheckConstraint('entrypoints_total >= 0', name=op.f('ck_audit_coverage_entrypoints_total_nonnegative')),
    sa.CheckConstraint('java_files_analyzed <= java_files_total', name=op.f('ck_audit_coverage_java_files_within_total')),
    sa.CheckConstraint('java_files_analyzed >= 0', name=op.f('ck_audit_coverage_java_files_analyzed_nonnegative')),
    sa.CheckConstraint('java_files_total >= 0', name=op.f('ck_audit_coverage_java_files_total_nonnegative')),
    sa.CheckConstraint('modules_analyzed <= modules_total', name=op.f('ck_audit_coverage_modules_within_total')),
    sa.CheckConstraint('modules_analyzed >= 0', name=op.f('ck_audit_coverage_modules_analyzed_nonnegative')),
    sa.CheckConstraint('modules_total >= 0', name=op.f('ck_audit_coverage_modules_total_nonnegative')),
    sa.CheckConstraint('sensitive_sinks_analyzed <= sensitive_sinks_total', name=op.f('ck_audit_coverage_sensitive_sinks_within_total')),
    sa.CheckConstraint('sensitive_sinks_analyzed >= 0', name=op.f('ck_audit_coverage_sensitive_sinks_analyzed_nonnegative')),
    sa.CheckConstraint('sensitive_sinks_total >= 0', name=op.f('ck_audit_coverage_sensitive_sinks_total_nonnegative')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_audit_coverage_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('audit_run_id', name=op.f('pk_audit_coverage'))
    )
    op.create_table('audit_facts',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=32), nullable=False),
    sa.Column('structured_payload', sa.JSON(), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
    sa.Column('created_by_task_id', sa.Uuid(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("kind IN ('architecture', 'entrypoint', 'trust_boundary', 'source', 'sink', 'candidate_finding', 'verification_result')", name=op.f('ck_audit_facts_kind_values')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_audit_facts_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['created_by_task_id'], ['audit_tasks.id'], name=op.f('fk_audit_facts_created_by_task_id_audit_tasks'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_facts'))
    )
    op.create_index(op.f('ix_audit_facts_audit_run_id'), 'audit_facts', ['audit_run_id'], unique=False)
    op.create_table('audit_intents',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('category', sa.String(length=255), nullable=False),
    sa.Column('scope', sa.JSON(), nullable=False),
    sa.Column('required_capabilities', sa.JSON(), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('created_by_task_id', sa.Uuid(), nullable=False),
    sa.Column('claimed_by_task_id', sa.Uuid(), nullable=True),
    sa.Column('concluded_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.CheckConstraint("status IN ('pending', 'claimed', 'concluded', 'cancelled')", name=op.f('ck_audit_intents_status_values')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_audit_intents_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['claimed_by_task_id'], ['audit_tasks.id'], name=op.f('fk_audit_intents_claimed_by_task_id_audit_tasks'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['created_by_task_id'], ['audit_tasks.id'], name=op.f('fk_audit_intents_created_by_task_id_audit_tasks'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_audit_intents'))
    )
    op.create_index(op.f('ix_audit_intents_audit_run_id'), 'audit_intents', ['audit_run_id'], unique=False)
    op.create_table('findings',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('fingerprint', sa.String(length=64), nullable=False),
    sa.Column('title', sa.String(length=500), nullable=False),
    sa.Column('description', sa.Text(), nullable=False),
    sa.Column('category', sa.String(length=255), nullable=False),
    sa.Column('cwe_id', sa.String(length=32), nullable=False),
    sa.Column('owasp_category', sa.String(length=128), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('confidence', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=32), nullable=False),
    sa.Column('attack_preconditions', sa.Text(), nullable=False),
    sa.Column('impact', sa.Text(), nullable=False),
    sa.Column('remediation', sa.Text(), nullable=False),
    sa.Column('runtime_verification', sa.String(length=24), nullable=False),
    sa.Column('discovered_by', sa.String(length=255), nullable=False),
    sa.Column('first_seen_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("confidence IN ('confirmed', 'high', 'medium', 'low')", name=op.f('ck_findings_confidence_values')),
    sa.CheckConstraint("runtime_verification IN ('verified', 'unverified', 'not_applicable')", name=op.f('ck_findings_runtime_verification_values')),
    sa.CheckConstraint("severity IN ('critical', 'high', 'medium', 'low', 'info')", name=op.f('ck_findings_severity_values')),
    sa.CheckConstraint("status IN ('candidate', 'validating', 'machine_confirmed', 'awaiting_human_review', 'confirmed', 'rejected', 'accepted_risk')", name=op.f('ck_findings_status_values')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_findings_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_findings')),
    sa.UniqueConstraint('audit_run_id', 'fingerprint', name='run_fingerprint_unique')
    )
    op.create_index('ix_findings_fingerprint', 'findings', ['fingerprint'], unique=False)
    op.create_index('ix_findings_run_severity_status', 'findings', ['audit_run_id', 'severity', 'status'], unique=False)
    op.create_table('reports',
    sa.Column('audit_run_id', sa.Uuid(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('summary_json', sa.JSON(), nullable=False),
    sa.Column('html_artifact_id', sa.Uuid(), nullable=False),
    sa.Column('json_artifact_id', sa.Uuid(), nullable=False),
    sa.Column('sarif_artifact_id', sa.Uuid(), nullable=False),
    sa.Column('generated_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint('version > 0', name=op.f('ck_reports_version_positive')),
    sa.ForeignKeyConstraint(['audit_run_id'], ['audit_runs.id'], name=op.f('fk_reports_audit_run_id_audit_runs'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['html_artifact_id'], ['artifacts.id'], name=op.f('fk_reports_html_artifact_id_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['json_artifact_id'], ['artifacts.id'], name=op.f('fk_reports_json_artifact_id_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['sarif_artifact_id'], ['artifacts.id'], name=op.f('fk_reports_sarif_artifact_id_artifacts'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_reports')),
    sa.UniqueConstraint('audit_run_id', 'version', name='run_version_unique')
    )
    op.create_index(op.f('ix_reports_audit_run_id'), 'reports', ['audit_run_id'], unique=False)
    op.create_table('audit_intent_sources',
    sa.Column('audit_intent_id', sa.Uuid(), nullable=False),
    sa.Column('audit_fact_id', sa.Uuid(), nullable=False),
    sa.ForeignKeyConstraint(['audit_fact_id'], ['audit_facts.id'], name=op.f('fk_audit_intent_sources_audit_fact_id_audit_facts'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['audit_intent_id'], ['audit_intents.id'], name=op.f('fk_audit_intent_sources_audit_intent_id_audit_intents'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('audit_intent_id', 'audit_fact_id', name=op.f('pk_audit_intent_sources'))
    )
    op.create_table('evidence',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('type', sa.String(length=32), nullable=False),
    sa.Column('artifact_id', sa.Uuid(), nullable=True),
    sa.Column('summary', sa.Text(), nullable=False),
    sa.Column('sha256', sa.String(length=64), nullable=True),
    sa.Column('produced_by_task_id', sa.Uuid(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("type IN ('code_snippet', 'call_trace', 'tool_result', 'build_log', 'unit_test', 'poc_output', 'http_exchange', 'runtime_log')", name=op.f('ck_evidence_type_values')),
    sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], name=op.f('fk_evidence_artifact_id_artifacts'), ondelete='RESTRICT'),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_evidence_finding_id_findings'), ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['produced_by_task_id'], ['audit_tasks.id'], name=op.f('fk_evidence_produced_by_task_id_audit_tasks'), ondelete='RESTRICT'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_evidence'))
    )
    op.create_index(op.f('ix_evidence_finding_id'), 'evidence', ['finding_id'], unique=False)
    op.create_table('finding_locations',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('role', sa.String(length=16), nullable=False),
    sa.Column('file_path', sa.Text(), nullable=False),
    sa.Column('start_line', sa.Integer(), nullable=False),
    sa.Column('end_line', sa.Integer(), nullable=False),
    sa.Column('symbol', sa.Text(), nullable=True),
    sa.Column('code_snippet', sa.Text(), nullable=False),
    sa.Column('snapshot_sha', sa.String(length=128), nullable=False),
    sa.Column('ordinal', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("role IN ('entrypoint', 'source', 'propagation', 'sink', 'related')", name=op.f('ck_finding_locations_role_values')),
    sa.CheckConstraint('end_line >= start_line', name=op.f('ck_finding_locations_line_range_valid')),
    sa.CheckConstraint('ordinal >= 0', name=op.f('ck_finding_locations_ordinal_nonnegative')),
    sa.CheckConstraint('start_line > 0', name=op.f('ck_finding_locations_start_line_positive')),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_finding_locations_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_finding_locations')),
    sa.UniqueConstraint('finding_id', 'ordinal', name='finding_ordinal_unique')
    )
    op.create_index(op.f('ix_finding_locations_finding_id'), 'finding_locations', ['finding_id'], unique=False)
    op.create_table('human_reviews',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('original_severity', sa.String(length=16), nullable=False),
    sa.Column('final_severity', sa.String(length=16), nullable=False),
    sa.Column('reviewer_id', sa.String(length=255), nullable=False),
    sa.Column('comment', sa.Text(), nullable=False),
    sa.Column('reviewed_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("final_severity IN ('critical', 'high', 'medium', 'low', 'info')", name=op.f('ck_human_reviews_final_severity_values')),
    sa.CheckConstraint("original_severity IN ('critical', 'high', 'medium', 'low', 'info')", name=op.f('ck_human_reviews_original_severity_values')),
    sa.CheckConstraint("verdict IN ('confirmed', 'rejected', 'accepted_risk', 'reverify')", name=op.f('ck_human_reviews_verdict_values')),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_human_reviews_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_human_reviews'))
    )
    op.create_index(op.f('ix_human_reviews_finding_id'), 'human_reviews', ['finding_id'], unique=False)
    op.create_table('verifications',
    sa.Column('finding_id', sa.Uuid(), nullable=False),
    sa.Column('method', sa.String(length=32), nullable=False),
    sa.Column('verdict', sa.String(length=16), nullable=False),
    sa.Column('verifier', sa.String(length=255), nullable=False),
    sa.Column('evidence_ids', sa.JSON(), nullable=False),
    sa.Column('reasoning', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.CheckConstraint("method IN ('static_corroboration', 'independent_agent', 'build_test', 'dynamic_poc')", name=op.f('ck_verifications_method_values')),
    sa.CheckConstraint("verdict IN ('confirmed', 'rejected', 'inconclusive')", name=op.f('ck_verifications_verdict_values')),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], name=op.f('fk_verifications_finding_id_findings'), ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id', name=op.f('pk_verifications'))
    )
    op.create_index(op.f('ix_verifications_finding_id'), 'verifications', ['finding_id'], unique=False)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Remove the Java audit domain schema."""
    _drop_snapshot_immutability_guard()
    _drop_snapshot_foreign_key()
    op.drop_table('verifications')
    op.drop_table('human_reviews')
    op.drop_table('finding_locations')
    op.drop_table('evidence')
    op.drop_table('audit_intent_sources')
    op.drop_table('reports')
    op.drop_table('findings')
    op.drop_table('audit_intents')
    op.drop_table('audit_facts')
    op.drop_table('audit_coverage')
    op.drop_table('source_snapshots')
    op.drop_table('artifacts')
    op.drop_table('audit_tasks')
    op.drop_table('audit_runs')
    op.drop_table('audit_policies')
    op.drop_table('repositories')
