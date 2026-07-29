from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from cairn.server.domain.enums import (
    AuditRunStatus,
    DynamicVerificationMode,
    FindingConfidence,
    FindingSeverity,
    SourceType,
)
from cairn.server.persistence.base import Base
from cairn.server.persistence.models import (
    AuditPolicy,
    AuditRun,
    FindingLocation,
    Repository,
)
from cairn.server.schemas.findings import (
    CandidateFindingCommand,
    FindingLocationResponse,
)
from cairn.server.services.findings import FindingService


def test_service_persists_bytecode_location_without_source_lines() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        repository = Repository(
            name="binary-demo",
            source_type=SourceType.BINARY_UPLOAD.value,
            created_by="system",
        )
        policy = AuditPolicy(
            name="binary-policy",
            version=1,
            include_paths=["**"],
            exclude_paths=[],
            enabled_scanners=[],
            dynamic_verification=DynamicVerificationMode.DISABLED.value,
            severity_thresholds={},
            resource_budget={},
            active=True,
        )
        session.add_all([repository, policy])
        session.flush()
        audit_run = AuditRun(
            repository_id=repository.id,
            source_request={"type": "binary_upload", "upload_id": "upload-1"},
            policy_id=policy.id,
            policy_version=policy.version,
            status=AuditRunStatus.CREATED.value,
            progress=0,
            warning_count=0,
            created_by="system",
        )
        session.add(audit_run)
        session.commit()

        command = CandidateFindingCommand.model_validate(
            {
                "audit_run_id": audit_run.id,
                "fingerprint": "a" * 64,
                "title": "Bytecode sink",
                "description": "Request data reaches Statement.execute.",
                "category": "injection",
                "cwe_id": "CWE-89",
                "severity": FindingSeverity.HIGH,
                "confidence": FindingConfidence.HIGH,
                "attack_preconditions": "Attacker controls a request parameter.",
                "impact": "Database confidentiality and integrity loss.",
                "remediation": "Use parameterized queries.",
                "discovered_by": "asm-index",
                "locations": [
                    {
                        "role": "sink",
                        "origin_kind": "bytecode",
                        "container_path": "sample.war",
                        "entry_path": "WEB-INF/lib/app.jar!/demo/Action.class",
                        "class_name": "demo.Action",
                        "method_name": "execute",
                        "method_descriptor": "(Ljava/lang/String;)V",
                        "bytecode_offset": 18,
                        "snapshot_sha": "b" * 64,
                        "ordinal": 0,
                    }
                ],
            }
        )
        FindingService(session).create_candidate(command)

    with Session(engine) as session:
        location = session.scalar(select(FindingLocation))

        assert location is not None
        assert location.origin_kind == "bytecode"
        assert location.file_path is None
        assert location.start_line is None
        assert location.end_line is None
        assert location.code_snippet is None
        assert location.container_path == "sample.war"
        assert location.entry_path.endswith("demo/Action.class")
        assert location.method_descriptor == "(Ljava/lang/String;)V"
        assert location.bytecode_offset == 18

        response = FindingLocationResponse.model_validate(location)
        assert response.origin_kind.value == "bytecode"
        assert response.file_path is None
        assert response.source_path is None
        assert response.start_line is None
        assert response.bytecode_offset == 18
