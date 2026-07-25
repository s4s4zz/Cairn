from datetime import datetime
from uuid import UUID

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditRunStatus,
    BuildSystem,
    DynamicVerificationMode,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
    RuntimeVerificationStatus,
    SnapshotStatus,
    SourceType,
)
from cairn.server.persistence import models  # noqa: F401
from cairn.server.persistence.base import Base
from cairn.server.persistence.models import (
    Artifact,
    AuditPolicy,
    AuditRun,
    Finding,
    Repository,
    SnapshotImmutableError,
    SourceSnapshot,
)
from cairn.server.persistence.session import (
    configure_engine,
    dispose_engine,
    session_scope,
)


EXPECTED_TABLES = {
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
}


def test_metadata_contains_complete_audit_domain() -> None:
    assert set(Base.metadata.tables) == EXPECTED_TABLES


def test_model_columns_match_core_contract() -> None:
    assert set(Base.metadata.tables["repositories"].columns.keys()) == {
        "id",
        "name",
        "source_type",
        "remote_url",
        "credential_ref",
        "default_branch",
        "created_by",
        "created_at",
        "updated_at",
    }
    assert {
        "repository_id",
        "source_request",
        "snapshot_id",
        "policy_id",
        "policy_version",
        "status",
        "current_stage",
        "progress",
        "warning_count",
        "failure_code",
        "failure_reason",
        "created_by",
        "created_at",
        "started_at",
        "completed_at",
    } <= set(Base.metadata.tables["audit_runs"].columns.keys())


def test_run_owned_foreign_keys_cascade_and_snapshot_reference_is_restricted() -> None:
    finding_run_fk = next(
        iter(Base.metadata.tables["findings"].c.audit_run_id.foreign_keys)
    )
    snapshot_fk = next(
        iter(Base.metadata.tables["audit_runs"].c.snapshot_id.foreign_keys)
    )

    assert finding_run_fk.ondelete == "CASCADE"
    assert snapshot_fk.ondelete == "RESTRICT"


def test_models_generate_uuid_and_aware_timestamps() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = Repository(
            name="demo",
            source_type=SourceType.GIT.value,
            remote_url="https://example.invalid/demo.git",
            created_by="system",
        )
        session.add(repository)
        session.flush()

        assert isinstance(repository.id, UUID)
        assert isinstance(repository.created_at, datetime)
        assert repository.created_at.tzinfo is not None
        assert repository.updated_at.tzinfo is not None


def test_finding_fingerprint_is_unique_within_a_run() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = Repository(
            name="demo",
            source_type=SourceType.ZIP.value,
            created_by="system",
        )
        policy = AuditPolicy(
            name="comprehensive",
            version=1,
            include_paths=["**"],
            exclude_paths=[],
            enabled_scanners=["semgrep"],
            dynamic_verification=DynamicVerificationMode.REQUIRED.value,
            severity_thresholds={},
            resource_budget={},
            active=True,
        )
        session.add_all([repository, policy])
        session.flush()
        audit_run = AuditRun(
            repository_id=repository.id,
            source_request={"type": "upload", "upload_id": "upload-1"},
            policy_id=policy.id,
            policy_version=policy.version,
            status=AuditRunStatus.CREATED.value,
            progress=0,
            warning_count=0,
            created_by="system",
        )
        session.add(audit_run)
        session.flush()

        common = {
            "audit_run_id": audit_run.id,
            "fingerprint": "a" * 64,
            "title": "SQL injection",
            "description": "Untrusted input reaches a SQL sink.",
            "category": "injection",
            "cwe_id": "CWE-89",
            "severity": FindingSeverity.HIGH.value,
            "confidence": FindingConfidence.HIGH.value,
            "status": FindingStatus.CANDIDATE.value,
            "attack_preconditions": "Attacker controls the query parameter.",
            "impact": "Database confidentiality and integrity loss.",
            "remediation": "Use parameterized queries.",
            "runtime_verification": RuntimeVerificationStatus.UNVERIFIED.value,
            "discovered_by": "semgrep",
        }
        session.add(Finding(**common))
        session.flush()
        session.add(Finding(**common))

        with pytest.raises(IntegrityError):
            session.flush()


def test_ready_source_snapshot_is_immutable() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine, expire_on_commit=False) as session:
        repository = Repository(
            name="immutable-snapshot",
            source_type=SourceType.GIT.value,
            remote_url="https://example.invalid/immutable.git",
            created_by="system",
        )
        policy = AuditPolicy(
            name="snapshot-policy",
            version=1,
            include_paths=["**"],
            exclude_paths=[],
            enabled_scanners=["semgrep"],
            dynamic_verification=DynamicVerificationMode.REQUIRED.value,
            severity_thresholds={},
            resource_budget={},
            active=True,
        )
        session.add_all([repository, policy])
        session.flush()
        audit_run = AuditRun(
            repository_id=repository.id,
            source_request={"type": "git_ref", "ref": "main"},
            policy_id=policy.id,
            policy_version=1,
            status=AuditRunStatus.CREATED.value,
            progress=0,
            warning_count=0,
            created_by="system",
        )
        session.add(audit_run)
        session.flush()
        artifact = Artifact(
            audit_run_id=audit_run.id,
            kind=ArtifactKind.SOURCE_SNAPSHOT.value,
            storage_key="snapshots/immutable",
            sha256="e" * 64,
            size_bytes=10,
            media_type="application/x-tar",
            access_level=ArtifactAccessLevel.NORMAL.value,
        )
        session.add(artifact)
        session.flush()
        snapshot = SourceSnapshot(
            repository_id=repository.id,
            content_sha256="e" * 64,
            artifact_id=artifact.id,
            file_count=1,
            total_bytes=10,
            java_file_count=1,
            build_system=BuildSystem.MAVEN.value,
            status=SnapshotStatus.READY.value,
        )
        session.add(snapshot)
        session.commit()

        snapshot.java_version = "21"
        with pytest.raises(SnapshotImmutableError):
            session.commit()


def test_session_scope_commits_rolls_back_and_reconfiguration_isolated() -> None:
    database_url = "sqlite+pysqlite:///:memory:"
    configure_engine(database_url)
    try:
        with session_scope() as session:
            Base.metadata.create_all(session.get_bind())
            session.add(
                Repository(
                    name="committed",
                    source_type=SourceType.LOCAL_UPLOAD.value,
                    created_by="system",
                )
            )

        with pytest.raises(RuntimeError):
            with session_scope() as session:
                session.add(
                    Repository(
                        name="rolled-back",
                        source_type=SourceType.LOCAL_UPLOAD.value,
                        created_by="system",
                    )
                )
                raise RuntimeError("abort transaction")

        with session_scope() as session:
            names = set(session.scalars(select(Repository.name)))
            assert names == {"committed"}

        configure_engine(database_url)
        with session_scope() as session:
            Base.metadata.create_all(session.get_bind())
            assert list(session.scalars(select(Repository.name))) == []
    finally:
        dispose_engine()
