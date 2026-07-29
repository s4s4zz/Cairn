from uuid import UUID

from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest
from sqlalchemy.orm import Session, sessionmaker

from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditTaskStatus,
    AuditTaskType,
    EvidenceType,
    FindingConfidence,
    FindingSeverity,
    LocationRole,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.errors import ConflictError
from cairn.server.persistence.models import (
    Artifact,
    AuditTask,
    Evidence,
    Verification,
)
from cairn.server.schemas.findings import CandidateFindingCommand
from cairn.server.services.findings import FindingService


@pytest.fixture(autouse=True)
def _admin_session(admin_client: TestClient) -> None:
    """Run this file's tests as an authenticated admin.

    These tests predate §9.8 authentication and cover repository, run, finding
    and policy behaviour rather than authorisation; the role matrix is checked
    on its own in test_rbac_matrix.py.
    """


def create_run(client: TestClient) -> dict[str, object]:
    repository_response = client.post(
        "/api/v1/repositories",
        json={
            "name": "finding-repository",
            "source_type": "git",
            "remote_url": "https://example.invalid/finding-repository.git",
        },
    )
    assert repository_response.status_code == 201
    policy_response = client.post(
        "/api/v1/audit-policies",
        json={"name": "finding-policy"},
    )
    assert policy_response.status_code == 201
    response = client.post(
        "/api/v1/audit-runs",
        json={
            "repository_id": repository_response.json()["id"],
            "policy_id": policy_response.json()["id"],
            "source_request": {"type": "git_ref", "ref": "main"},
        },
    )
    assert response.status_code == 201
    return response.json()


def probe_task(audit_run_id: UUID) -> AuditTask:
    """The task an evidence row is attributed to. Unflushed; the caller adds it."""

    return AuditTask(
        audit_run_id=audit_run_id,
        type=AuditTaskType.DYNAMIC_VERIFY.value,
        scope={"module": "app"},
        required_capabilities=["dynamic:probe"],
        status=AuditTaskStatus.SUCCEEDED.value,
        attempt=1,
        max_attempts=1,
        timeout_seconds=300,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )


def stored_artifact(audit_run_id: UUID) -> Artifact:
    return Artifact(
        audit_run_id=audit_run_id,
        kind=ArtifactKind.SCAN_RESULT.value,
        storage_key="tool-results/semgrep.json",
        sha256="e" * 64,
        size_bytes=64,
        media_type="application/json",
        access_level=ArtifactAccessLevel.NORMAL.value,
    )


def candidate_payload(
    run_id: str,
    *,
    fingerprint_character: str = "a",
    severity: FindingSeverity = FindingSeverity.HIGH,
    cwe_id: str = "CWE-89",
) -> dict[str, object]:
    return {
        "audit_run_id": run_id,
        "fingerprint": fingerprint_character * 64,
        "title": "SQL injection",
        "description": "Untrusted input reaches a SQL sink.",
        "category": "injection",
        "cwe_id": cwe_id,
        "severity": severity,
        "confidence": FindingConfidence.HIGH,
        "attack_preconditions": "Attacker controls a request parameter.",
        "impact": "Database confidentiality and integrity loss.",
        "remediation": "Use parameterized queries.",
        "discovered_by": "semgrep",
        "locations": [
            {
                "role": LocationRole.SINK,
                "file_path": "src/main/java/Demo.java",
                "start_line": 42,
                "end_line": 42,
                "symbol": "Demo.query",
                "code_snippet": "statement.execute(input);",
                "snapshot_sha": "b" * 64,
                "ordinal": 0,
            }
        ],
    }


def test_internal_service_creates_candidate_with_location(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    run = create_run(client)
    command = CandidateFindingCommand.model_validate(candidate_payload(run["id"]))

    with session_factory() as session:
        finding = FindingService(session).create_candidate(command)

        assert finding.status == "candidate"
        assert finding.runtime_verification == "unverified"
        assert finding.confidence == "high"
        assert len(finding.locations) == 1
        assert finding.locations[0].file_path == "src/main/java/Demo.java"


@pytest.mark.parametrize(
    "missing_field",
    ["cwe_id", "attack_preconditions", "impact", "remediation", "locations"],
)
def test_candidate_contract_rejects_missing_required_evidence_fields(
    missing_field: str,
) -> None:
    payload = candidate_payload(str(UUID(int=1)))
    payload.pop(missing_field)

    with pytest.raises(ValidationError):
        CandidateFindingCommand.model_validate(payload)


def test_duplicate_fingerprint_returns_conflict_without_merging(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    run = create_run(client)
    command = CandidateFindingCommand.model_validate(candidate_payload(run["id"]))

    with session_factory() as session:
        service = FindingService(session)
        first = service.create_candidate(command)
        with pytest.raises(ConflictError) as captured:
            service.create_candidate(command)

        assert captured.value.error_code == "finding_fingerprint_conflict"
        assert service.get(first.id).title == "SQL injection"


def test_list_filters_by_run_cwe_severity_and_status(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    run = create_run(client)
    with session_factory() as session:
        service = FindingService(session)
        first = service.create_candidate(
            CandidateFindingCommand.model_validate(candidate_payload(run["id"]))
        )
        service.create_candidate(
            CandidateFindingCommand.model_validate(
                candidate_payload(
                    run["id"],
                    fingerprint_character="c",
                    severity=FindingSeverity.LOW,
                    cwe_id="CWE-22",
                )
            )
        )

    response = client.get(
        "/api/v1/findings",
        params={
            "audit_run_id": run["id"],
            "cwe_id": "CWE-89",
            "severity": "high",
            "status": "candidate",
        },
    )

    assert response.status_code == 200
    assert response.json()["meta"]["total"] == 1
    assert response.json()["items"][0]["id"] == str(first.id)


def test_detail_returns_locations_evidence_and_verifications(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    run = create_run(client)
    with session_factory() as session:
        task = AuditTask(
            audit_run_id=UUID(run["id"]),
            type=AuditTaskType.SAST.value,
            scope={"module": "app"},
            required_capabilities=["semgrep"],
            status=AuditTaskStatus.SUCCEEDED.value,
            attempt=1,
            max_attempts=1,
            timeout_seconds=300,
            input_artifact_ids=[],
            output_artifact_ids=[],
        )
        session.add(task)
        session.commit()
        finding = FindingService(session).create_candidate(
            CandidateFindingCommand.model_validate(candidate_payload(run["id"]))
        )
        evidence = Evidence(
            finding_id=finding.id,
            type=EvidenceType.TOOL_RESULT.value,
            summary="Semgrep matched a tainted SQL execution path.",
            sha256="d" * 64,
            produced_by_task_id=task.id,
        )
        session.add(evidence)
        session.flush()
        session.add(
            Verification(
                finding_id=finding.id,
                method=VerificationMethod.STATIC_CORROBORATION.value,
                verdict=VerificationVerdict.CONFIRMED.value,
                verifier="codeql-worker",
                evidence_ids=[str(evidence.id)],
                reasoning="A second data-flow engine found the same path.",
            )
        )
        session.commit()
        finding_id = finding.id

    response = client.get(f"/api/v1/findings/{finding_id}")

    assert response.status_code == 200
    detail = response.json()
    assert len(detail["locations"]) == 1
    assert detail["evidence"][0]["type"] == "tool_result"
    assert detail["verifications"][0]["verdict"] == "confirmed"
    assert detail["verifications"][0]["evidence_ids"] == [
        detail["evidence"][0]["id"]
    ]


def test_artifact_less_evidence_of_one_type_is_kept_row_per_observation(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    """§7.7 wants both halves of a probe kept, and neither names an Artifact.

    Deduplicating them on ``(type, artifact_id)`` matched on ``(http_exchange,
    None)`` and silently discarded the attack request — the half that carries
    the finding — leaving a reviewer with the baseline alone.
    """

    run = create_run(client)
    with session_factory() as session:
        task = probe_task(UUID(run["id"]))
        session.add(task)
        session.commit()
        service = FindingService(session)
        finding = service.create_candidate(
            CandidateFindingCommand.model_validate(candidate_payload(run["id"]))
        )

        baseline = service.record_evidence(
            finding,
            evidence_type=EvidenceType.HTTP_EXCHANGE,
            summary="基线请求：GET http://app/orders?q=1 -> 200，耗时 12 毫秒",
            produced_by_task_id=task.id,
        )
        payload = service.record_evidence(
            finding,
            evidence_type=EvidenceType.HTTP_EXCHANGE,
            summary="攻击请求：GET http://app/orders?q=1' OR '1'='1 -> 500，耗时 31 毫秒",
            produced_by_task_id=task.id,
        )

        assert baseline is not payload
        assert [item.summary for item in finding.evidence] == [
            baseline.summary,
            payload.summary,
        ]


def test_evidence_naming_the_same_artifact_is_recorded_once(
    client: TestClient,
    session_factory: sessionmaker[Session],
) -> None:
    """An Artifact is content-addressed, so a second row citing it adds nothing.

    This is what the deduplication is for: a stage resumed after a crash
    re-records the artifacts it already attached.
    """

    run = create_run(client)
    with session_factory() as session:
        task = probe_task(UUID(run["id"]))
        artifact = stored_artifact(UUID(run["id"]))
        session.add_all([task, artifact])
        session.commit()
        service = FindingService(session)
        finding = service.create_candidate(
            CandidateFindingCommand.model_validate(candidate_payload(run["id"]))
        )
        artifact_id = artifact.id

        first = service.record_evidence(
            finding,
            evidence_type=EvidenceType.TOOL_RESULT,
            summary="该候选归一化前的工具原始输出（semgrep）。",
            produced_by_task_id=task.id,
            artifact_id=artifact_id,
        )
        again = service.record_evidence(
            finding,
            evidence_type=EvidenceType.TOOL_RESULT,
            summary="重跑该阶段时再次记录的同一份产物。",
            produced_by_task_id=task.id,
            artifact_id=artifact_id,
        )

        assert again is first
        assert len(finding.evidence) == 1
        assert first.summary == "该候选归一化前的工具原始输出（semgrep）。"


def test_public_finding_creation_is_not_exposed(client: TestClient) -> None:
    run = create_run(client)

    response = client.post(
        "/api/v1/findings",
        json=candidate_payload(run["id"]),
    )

    assert response.status_code == 405
