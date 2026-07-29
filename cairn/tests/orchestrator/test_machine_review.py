"""The Finding Pipeline, dynamic stage and machine review inside the Orchestrator.

Everything runs against a fake Sandbox: the property under test is what the
Orchestrator does with a verdict — promote candidates, record verifications,
apply §7.8, gate the human queue — not whether a container starts.

The acceptance criteria of §13.6 are asserted directly here:

* a timeout or missing environment yields `inconclusive`, never `rejected`;
* the original discoverer cannot perform the independent review;
* critical and high findings cannot enter the human queue before machine review.
"""

from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
import json
from pathlib import Path
import tarfile
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.engine import DeterministicOrchestrator
from cairn.sandbox.contracts import (
    SandboxArtifact,
    SandboxCreateRequest,
    SandboxOperation,
    SandboxRecord,
    SandboxStatus,
    SandboxTemplateName,
)
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    AuditFactKind,
    AuditIntentStatus,
    AuditRunStatus,
    AuditTaskStatus,
    AuditTaskType,
    BuildStatus,
    FindingConfidence,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.errors import InvalidStateError
from cairn.server.persistence.models import (
    AuditCoverage,
    AuditFact,
    AuditIntent,
    AuditRun,
    AuditTask,
    Finding,
    Verification,
)
from cairn.server.schemas.findings import FindingReverifyRequest
from cairn.server.services.findings import FindingService
from cairn.verify.contracts import VERIFY_CONTRACT, VERIFY_TOOL_NAME

from .test_engine import FakeSandbox, create_run
from .test_semantic_stage import GRANT_KEY

CONTROLLER = "web/src/main/java/dev/cairn/UserController.java"
REPOSITORY_JAVA = "core/src/main/java/dev/cairn/UserRepository.java"


# --- fixtures -----------------------------------------------------------------


def candidate_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "rule_id": "sql-injection-in-user-lookup",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "severity": "high",
        "confidence": "medium",
        "message": "A path variable reaches a concatenated SQL statement.",
        "locations": [
            {
                "path": REPOSITORY_JAVA,
                "start_line": 7,
                "end_line": 7,
                "start_column": None,
                "end_column": None,
                "symbol": "UserRepository.find",
                "role": "sink",
            }
        ],
        "sink": "java.sql.Statement.execute",
        "fingerprint": "a" * 64,
        "root_cause_key": "b" * 64,
        "discovered_by": ["semgrep"],
        "source_rules": ["java.lang.security.audit.sqli"],
        "call_chain": [
            {
                "path": CONTROLLER,
                "start_line": 12,
                "end_line": 12,
                "symbol": "UserController.user",
                "role": "entrypoint",
                "note": None,
            },
            {
                "path": REPOSITORY_JAVA,
                "start_line": 7,
                "end_line": 7,
                "symbol": "UserRepository.find",
                "role": "sink",
                "note": None,
            },
        ],
        "controllability": "the `name` path variable is concatenated unchanged",
        "existing_defenses": [],
        "attack_preconditions": "any caller with the ADMIN role",
        "impact": "arbitrary read of the users table",
        "recommended_verification": "request /users/' OR '1'='1",
        "severity_conflict": [],
    }
    payload.update(overrides)
    return payload


def verify_result(
    root_cause_key: str,
    *,
    verdict: str = "confirmed",
    status: str = "completed",
    reason_code: str | None = None,
    defeating_control: str | None = None,
    chain_steps: int = 2,
) -> dict[str, object]:
    chain = [
        {
            "path": CONTROLLER,
            "start_line": 12,
            "end_line": 12,
            "symbol": "UserController.user",
            "role": "entrypoint",
            "note": None,
        },
        {
            "path": REPOSITORY_JAVA,
            "start_line": 7,
            "end_line": 7,
            "symbol": "UserRepository.find",
            "role": "sink",
            "note": None,
        },
    ][:chain_steps]
    payload: dict[str, object] = {
        "contract": VERIFY_CONTRACT,
        "status": status,
        "tool_name": VERIFY_TOOL_NAME,
        "model": "claude-opus-5",
        "root_cause_key": root_cause_key,
        "reason_code": reason_code,
        "verdict": None
        if status != "completed"
        else {
            "verdict": verdict,
            "reasoning": "I traced the path from the controller myself.",
            "reachability": "GET /users/{name} reaches the repository directly.",
            "call_chain": chain,
            "defeating_control": defeating_control,
        },
        "warnings": [],
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "requests": 1,
        },
    }
    return payload


class VerifySandbox(FakeSandbox):
    """Answers `independent-verify` operations from a queue."""

    def __init__(
        self,
        store: LocalArtifactStore,
        tmp_path: Path,
        results: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(store, tmp_path, {})
        self.results = list(results or [])
        self.verify_requests: list[SandboxCreateRequest] = []
        self.poc_requests: list[SandboxCreateRequest] = []
        # finding_id -> poc-result payload. Absent means "the author declined",
        # which is the default and keeps findings inconclusive.
        self.poc_results: dict[str, dict[str, object]] = {}

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        if request.operation is SandboxOperation.INDEPENDENT_VERIFY:
            self.verify_requests.append(request)
        elif request.operation is SandboxOperation.AUTHOR_POC:
            self.poc_requests.append(request)
        return super().create(request)

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        record = self.records[sandbox_id]
        if record.operation is SandboxOperation.AUTHOR_POC:
            return self._answer_poc(sandbox_id)
        if record.operation is not SandboxOperation.INDEPENDENT_VERIFY:
            return super().wait(sandbox_id, timeout_seconds)
        key = self.verify_requests[-1].semantic.candidate.root_cause_key
        payload = self.results.pop(0) if self.results else verify_result(key)
        archive_path = self.tmp_path / f"{sandbox_id}-verify.tar"
        encoded = json.dumps(payload).encode()
        with tarfile.open(archive_path, mode="w") as archive:
            info = tarfile.TarInfo("verify-result.json")
            info.size = len(encoded)
            archive.addfile(info, BytesIO(encoded))
        stored = self.store.put_file(archive_path)
        completed = record.model_copy(
            update={
                "status": SandboxStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "exit_code": 0,
                "artifacts": [
                    SandboxArtifact(
                        storage_key=stored.storage_key,
                        sha256=stored.sha256,
                        size_bytes=stored.size_bytes,
                        media_type="application/x-tar",
                    )
                ],
                "resources_destroyed": True,
            }
        )
        self.records[sandbox_id] = completed
        return completed

    def _answer_poc(self, sandbox_id: UUID) -> SandboxRecord:
        record = self.records[sandbox_id]
        finding_id = str(self.poc_requests[-1].semantic.poc.finding_id)
        payload = self.poc_results.get(finding_id) or {
            "contract": "cairn-poc-plan-v1",
            "status": "failed",
            "tool_name": "poc-author",
            "model": "claude-opus-5",
            "finding_id": finding_id,
            "reason_code": "POC_MODEL_REFUSED",
            "plan": None,
            "warnings": [],
        }
        archive_path = self.tmp_path / f"{sandbox_id}-poc.tar"
        encoded = json.dumps(payload).encode()
        with tarfile.open(archive_path, mode="w") as archive:
            info = tarfile.TarInfo("poc-result.json")
            info.size = len(encoded)
            archive.addfile(info, BytesIO(encoded))
        stored = self.store.put_file(archive_path)
        completed = record.model_copy(
            update={
                "status": SandboxStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "exit_code": 0,
                "artifacts": [
                    SandboxArtifact(
                        storage_key=stored.storage_key,
                        sha256=stored.sha256,
                        size_bytes=stored.size_bytes,
                        media_type="application/x-tar",
                    )
                ],
                "resources_destroyed": True,
            }
        )
        self.records[sandbox_id] = completed
        return completed


def settings_for(tmp_path: Path) -> OrchestratorSettings:
    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    grant_key_file = tmp_path / "grant.key"
    grant_key_file.write_bytes(GRANT_KEY)
    return OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
        llm_grant_key_file=grant_key_file,
    )


def parked_run(
    session: Session,
    store: LocalArtifactStore,
    tmp_path: Path,
    candidates: list[dict[str, object]],
) -> AuditRun:
    """A run sitting where the semantic stage leaves it, with candidate facts."""

    audit_run = create_run(session, store, tmp_path)
    audit_run.status = AuditRunStatus.DYNAMIC_VERIFYING.value
    audit_run.current_stage = AuditRunStatus.DYNAMIC_VERIFYING.value
    task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.SEMANTIC_REVIEW.value,
        scope_key="web:http-endpoint:sql-injection",
        scope={},
        required_capabilities=[],
        status=AuditTaskStatus.SUCCEEDED.value,
        attempt=1,
        max_attempts=3,
        timeout_seconds=60,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()
    session.add(
        AuditCoverage(
            audit_run_id=audit_run.id,
            modules_total=2,
            modules_analyzed=2,
            java_files_total=2,
            java_files_analyzed=2,
            entrypoints_total=1,
            entrypoints_analyzed=1,
            sensitive_sinks_total=1,
            sensitive_sinks_analyzed=1,
            build_status=BuildStatus.SUCCESS.value,
            static_tools_completed={},
            skipped_paths=[],
            unsupported_components=[],
            coverage_warnings=[],
        )
    )
    for candidate in candidates:
        session.add(
            AuditFact(
                audit_run_id=audit_run.id,
                kind=AuditFactKind.CANDIDATE_FINDING.value,
                structured_payload={"candidate": candidate, "raw_artifact_ids": []},
                evidence_ids=[],
                created_by_task_id=task.id,
            )
        )
    session.add(
        AuditIntent(
            audit_run_id=audit_run.id,
            category="sql-injection",
            scope={"module": "web"},
            required_capabilities=[],
            status=AuditIntentStatus.PENDING.value,
            created_by_task_id=task.id,
        )
    )
    session.commit()
    return audit_run


def drive(
    session: Session,
    tmp_path: Path,
    *,
    candidates: list[dict[str, object]] | None = None,
    verify_results: list[dict[str, object]] | None = None,
) -> tuple[AuditRun, VerifySandbox]:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(
        session,
        store,
        tmp_path,
        candidates if candidates is not None else [candidate_payload()],
    )
    sandbox = VerifySandbox(store, tmp_path, verify_results)
    orchestrator = DeterministicOrchestrator(
        session,
        settings_for(tmp_path),
        store,
        sandbox,
    )
    orchestrator.process_run(audit_run.id)
    session.commit()
    session.refresh(audit_run)
    return audit_run, sandbox


def findings_of(session: Session, audit_run: AuditRun) -> list[Finding]:
    return list(
        session.scalars(
            select(Finding).where(Finding.audit_run_id == audit_run.id)
        )
    )


def warnings_of(session: Session, audit_run: AuditRun) -> set[str]:
    coverage = session.get(AuditCoverage, audit_run.id)
    assert coverage is not None
    return {warning["reason_code"] for warning in coverage.coverage_warnings}


# --- the Finding Pipeline -----------------------------------------------------


def test_candidate_facts_become_formal_findings(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """The bridge §6.14 asks for, and the thing nothing before 6a did."""

    audit_run, _ = drive(db_session, tmp_path)

    findings = findings_of(db_session, audit_run)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.fingerprint == "a" * 64
    assert finding.cwe_id == "CWE-89"
    assert finding.owasp_category == "A03:2021 Injection"
    assert finding.remediation


def test_locations_carry_real_snippets_bound_to_the_snapshot(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]
    snapshot = audit_run.snapshot
    assert snapshot is not None

    assert [location.role for location in finding.locations] == ["entrypoint", "sink"]
    assert all(
        location.snapshot_sha == snapshot.content_sha256
        for location in finding.locations
    )
    assert "statement.execute" in finding.locations[1].code_snippet


def test_promotion_is_idempotent_across_a_resumed_run(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    before = len(findings_of(db_session, audit_run))

    # Re-enter the stage the way a restarted worker would.
    audit_run.status = AuditRunStatus.DYNAMIC_VERIFYING.value
    db_session.commit()
    store = LocalArtifactStore(tmp_path / "artifacts")
    DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        store,
        VerifySandbox(store, tmp_path, None),
    ).process_run(audit_run.id)

    assert len(findings_of(db_session, audit_run)) == before


def test_a_candidate_the_snapshot_cannot_substantiate_is_recorded_not_promoted(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(
        db_session,
        tmp_path,
        candidates=[
            candidate_payload(
                cwe_ids=[],
                fingerprint="c" * 64,
                root_cause_key="d" * 64,
            )
        ],
    )

    assert findings_of(db_session, audit_run) == []
    assert "PIPELINE_NO_CWE" in warnings_of(db_session, audit_run)


# --- the dynamic stage (§7.7) -------------------------------------------------


def test_a_missing_environment_yields_inconclusive_and_never_rejected(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]

    dynamic = [
        verification
        for verification in finding.verifications
        if verification.method == VerificationMethod.DYNAMIC_POC.value
    ]
    assert len(dynamic) == 1
    assert dynamic[0].verdict == VerificationVerdict.INCONCLUSIVE.value
    assert dynamic[0].verdict != VerificationVerdict.REJECTED.value
    assert "DYNAMIC_ENVIRONMENT_UNAVAILABLE" in warnings_of(db_session, audit_run)


def test_runtime_verification_is_unverified_not_verified(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """6a records the absence of runtime evidence; it never claims to have it."""

    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]

    assert finding.runtime_verification == RuntimeVerificationStatus.UNVERIFIED.value


def test_a_run_with_no_candidates_still_advances(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """A repository with nothing to report is a valid audit, not a failure."""

    audit_run, _ = drive(db_session, tmp_path, candidates=[])

    assert audit_run.status == AuditRunStatus.HUMAN_REVIEW.value
    assert findings_of(db_session, audit_run) == []


# --- machine review (§7.8) ----------------------------------------------------


def test_confirmation_plus_a_corroborating_tool_confirms_the_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(discovered_by=["codeql", "semgrep"])],
    )
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert finding.confidence == FindingConfidence.CONFIRMED.value
    assert finding.runtime_verification == RuntimeVerificationStatus.UNVERIFIED.value


def test_a_lone_confirmation_reaches_a_human_without_being_confirmed(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert finding.confidence != FindingConfidence.CONFIRMED.value
    assert "VERIFICATION_SINGLE_CONCLUSION" in warnings_of(db_session, audit_run)


def test_a_reasoned_rejection_still_reaches_human_disposition(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(
        db_session,
        tmp_path,
        verify_results=[
            verify_result(
                "b" * 64,
                verdict="rejected",
                chain_steps=0,
                defeating_control=f"{REPOSITORY_JAVA}:7 binds the value",
            )
        ],
    )
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert "VERIFICATION_CONFLICT" in warnings_of(db_session, audit_run)


def test_a_rejection_against_corroborating_tools_goes_to_a_human(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """A conflict is routed, not settled."""

    audit_run, _ = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(discovered_by=["codeql", "semgrep"])],
        verify_results=[
            verify_result(
                "b" * 64,
                verdict="rejected",
                chain_steps=0,
                defeating_control=f"{REPOSITORY_JAVA}:7 binds the value",
            )
        ],
    )
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert "VERIFICATION_CONFLICT" in warnings_of(db_session, audit_run)


def test_a_failed_review_becomes_inconclusive_and_never_deletes_the_candidate(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(
        db_session,
        tmp_path,
        verify_results=[
            verify_result(
                "b" * 64,
                status="failed",
                reason_code="VERIFY_MODEL_REFUSED",
            )
        ],
    )
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status != FindingStatus.REJECTED.value
    independent = [
        verification
        for verification in finding.verifications
        if verification.method == VerificationMethod.INDEPENDENT_AGENT.value
    ]
    assert independent[0].verdict == VerificationVerdict.INCONCLUSIVE.value
    assert "VERIFY_MODEL_REFUSED" in warnings_of(db_session, audit_run)


def test_medium_findings_settle_without_entering_the_human_queue(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """§7.9 does not force medium and below through human confirmation."""

    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(severity="medium")],
    )
    finding = findings_of(db_session, audit_run)[0]

    assert finding.status == FindingStatus.MACHINE_CONFIRMED.value
    assert sandbox.verify_requests == []


# --- independence (§6.10, §13.6) ---------------------------------------------


def test_the_verifier_is_never_one_of_the_discovering_tools(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]

    independent = [
        verification
        for verification in finding.verifications
        if verification.method == VerificationMethod.INDEPENDENT_AGENT.value
    ]
    assert independent
    assert independent[0].verifier == VERIFY_TOOL_NAME
    assert independent[0].verifier not in finding.discovered_by


def test_the_discovering_worker_cannot_review_its_own_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """§6.10, enforced in the service so no call site can arrange otherwise."""

    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]
    service = FindingService(db_session)

    with pytest.raises(InvalidStateError) as excinfo:
        service.record_verification(
            finding,
            method=VerificationMethod.INDEPENDENT_AGENT,
            verdict=VerificationVerdict.CONFIRMED,
            verifier="semgrep",
            reasoning="the discoverer confirming itself",
            discovered_by=["semgrep"],
        )

    assert excinfo.value.error_code == "verifier_not_independent"


def test_the_verify_task_is_not_the_task_that_produced_the_candidate(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)

    verify_tasks = list(
        db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.INDEPENDENT_VERIFY.value,
            )
        )
    )
    fact = db_session.scalar(
        select(AuditFact).where(
            AuditFact.audit_run_id == audit_run.id,
            AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
        )
    )
    assert verify_tasks and fact is not None
    assert verify_tasks[0].id != fact.created_by_task_id
    assert verify_tasks[0].worker_name.endswith(":independent-verifier")


@pytest.mark.parametrize("severity", ["critical", "high"])
def test_a_severe_finding_cannot_enter_the_human_queue_unreviewed(
    db_session: Session,
    tmp_path: Path,
    severity: str,
) -> None:
    """§13.6's acceptance criterion, asserted against the gate itself."""

    audit_run, _ = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(severity=severity)],
    )
    finding = findings_of(db_session, audit_run)[0]

    # Strip the machine review and try to walk it into the queue again.
    for verification in list(finding.verifications):
        if verification.method == VerificationMethod.INDEPENDENT_AGENT.value:
            db_session.delete(verification)
            finding.verifications.remove(verification)
    finding.status = FindingStatus.MACHINE_CONFIRMED.value
    db_session.flush()

    with pytest.raises(InvalidStateError) as excinfo:
        FindingService(db_session).enter_human_queue(finding)

    assert excinfo.value.error_code == "finding_machine_review_required"


def test_a_medium_finding_needs_no_machine_review_to_be_queued(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(severity="medium")],
    )
    finding = findings_of(db_session, audit_run)[0]

    FindingService(db_session).enter_human_queue(finding)

    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value


# --- the blind assignment on the wire -----------------------------------------


def test_the_request_sent_to_the_reviewer_carries_no_reasoning(
    db_session: Session,
    tmp_path: Path,
) -> None:
    _audit_run, sandbox = drive(db_session, tmp_path)

    assert sandbox.verify_requests
    payload = json.dumps(
        sandbox.verify_requests[0].semantic.candidate.model_dump(mode="json")
    )
    for leaked in (
        "concatenated unchanged",
        "arbitrary read of the users table",
        "any caller with the ADMIN role",
        "request /users/",
    ):
        assert leaked not in payload
    assert "call_chain" not in payload
    assert "controllability" not in payload


def test_the_reviewer_is_told_the_category_cwe_and_locations(
    db_session: Session,
    tmp_path: Path,
) -> None:
    _audit_run, sandbox = drive(db_session, tmp_path)
    candidate = sandbox.verify_requests[0].semantic.candidate

    assert candidate.category == "sql-injection"
    assert candidate.cwe_ids == ["CWE-89"]
    assert {location.path for location in candidate.locations} == {
        CONTROLLER,
        REPOSITORY_JAVA,
    }


# --- run progression ----------------------------------------------------------


def test_the_run_reaches_human_review(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)

    assert audit_run.status == AuditRunStatus.HUMAN_REVIEW.value
    assert audit_run.progress == 90


def test_the_intents_the_semantic_stage_opened_are_concluded(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)

    intents = list(
        db_session.scalars(
            select(AuditIntent).where(AuditIntent.audit_run_id == audit_run.id)
        )
    )
    assert intents
    assert all(
        intent.status == AuditIntentStatus.CONCLUDED.value for intent in intents
    )
    assert all(intent.concluded_at is not None for intent in intents)


@pytest.mark.parametrize(
    "status",
    [
        AuditRunStatus.SEMANTIC_AUDITING,
        AuditRunStatus.DYNAMIC_VERIFYING,
        AuditRunStatus.MACHINE_REVIEW,
    ],
)
def test_a_run_parked_mid_stage_is_picked_up_again(
    db_session: Session,
    tmp_path: Path,
    status: AuditRunStatus,
) -> None:
    """A worker that died mid-stage must not strand the run forever."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [candidate_payload()])
    audit_run.status = status.value
    audit_run.current_stage = status.value
    db_session.commit()

    claimed = DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        store,
        VerifySandbox(store, tmp_path, None),
    ).process_next()

    assert claimed == audit_run.id
    db_session.refresh(audit_run)
    assert audit_run.status == AuditRunStatus.HUMAN_REVIEW.value


def test_the_verify_task_is_created_once_per_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path)

    tasks = list(
        db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.INDEPENDENT_VERIFY.value,
            )
        )
    )
    assert len(tasks) == 1
    assert len(sandbox.verify_requests) == 1
    assert tasks[0].status == AuditTaskStatus.SUCCEEDED.value


def test_the_review_transcript_is_attached_as_evidence(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _ = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]

    assert finding.evidence
    independent = [
        verification
        for verification in finding.verifications
        if verification.method == VerificationMethod.INDEPENDENT_AGENT.value
    ]
    assert independent[0].evidence_ids


# --- human-requested reverification ------------------------------------------


def test_requested_independent_reverification_is_claimed_and_requeues_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]
    _finding, review, task = FindingService(db_session).request_reverification(
        finding.id,
        FindingReverifyRequest(
            method="independent_agent",
            comment="Rebuild the trace with fresh evidence.",
        ),
        reviewer_id=uuid4(),
    )
    db_session.commit()
    sandbox.results.append(
        verify_result(
            "b" * 64,
            verdict="rejected",
            chain_steps=0,
            defeating_control=f"{REPOSITORY_JAVA}:7 binds the value",
        )
    )

    claimed = DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        sandbox.store,
        sandbox,
    ).process_next()

    assert claimed == audit_run.id
    db_session.refresh(finding)
    db_session.refresh(task)
    assert audit_run.status == AuditRunStatus.HUMAN_REVIEW.value
    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert review.verdict == "reverify"
    assert task.status == AuditTaskStatus.SUCCEEDED.value
    assert task.attempt == 1
    assert task.worker_name is not None
    assert task.worker_name.endswith(":independent-verifier")
    independent = [
        item
        for item in finding.verifications
        if item.method == VerificationMethod.INDEPENDENT_AGENT.value
    ]
    assert len(independent) == 2
    assert independent[-1].verdict == VerificationVerdict.REJECTED.value
    assert len(sandbox.verify_requests) == 2


def test_unavailable_dynamic_reverification_is_terminal_and_requeues_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]
    _finding, _review, task = FindingService(db_session).request_reverification(
        finding.id,
        FindingReverifyRequest(
            method="dynamic_poc",
            comment="Try the runtime path again.",
        ),
        reviewer_id=uuid4(),
    )
    db_session.commit()

    claimed = DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        sandbox.store,
        sandbox,
    ).process_next()

    assert claimed == audit_run.id
    db_session.refresh(finding)
    db_session.refresh(task)
    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    assert task.status == AuditTaskStatus.SKIPPED.value
    assert task.attempt == 1
    assert task.worker_name is not None
    assert task.worker_name.endswith(":dynamic-verifier")
    assert task.error_code == "DYNAMIC_ENVIRONMENT_UNAVAILABLE"
    dynamic = [
        item
        for item in finding.verifications
        if item.method == VerificationMethod.DYNAMIC_POC.value
    ]
    assert len(dynamic) == 2
    assert dynamic[-1].verdict == VerificationVerdict.INCONCLUSIVE.value
    assert "DYNAMIC_ENVIRONMENT_UNAVAILABLE" in warnings_of(
        db_session,
        audit_run,
    )


def test_reverification_claim_is_durable_before_worker_execution(
    db_session: Session,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path)
    finding = findings_of(db_session, audit_run)[0]
    _finding, _review, task = FindingService(db_session).request_reverification(
        finding.id,
        FindingReverifyRequest(
            method="independent_agent",
            comment="Check that another worker cannot claim this task.",
        ),
        reviewer_id=uuid4(),
    )
    db_session.commit()
    observed_task_ids: list[UUID] = []

    def observe_claim(
        _orchestrator: DeterministicOrchestrator,
        *_args: object,
        task_override: AuditTask | None = None,
        **_kwargs: object,
    ) -> VerificationVerdict:
        assert task_override is not None
        with Session(db_session.get_bind()) as competing_session:
            persisted = competing_session.get(AuditTask, task.id)
            assert persisted is not None
            assert persisted.status == AuditTaskStatus.RUNNING.value
            assert persisted.attempt == 1
            assert persisted.worker_name is not None
            assert persisted.worker_name.endswith(":independent-verifier")
            competitor = DeterministicOrchestrator(
                competing_session,
                settings_for(tmp_path),
                sandbox.store,
                sandbox,
            )
            assert competitor.process_next() is None

        observed_task_ids.append(task_override.id)
        task_override.status = AuditTaskStatus.SUCCEEDED.value
        task_override.finished_at = datetime.now(UTC)
        return VerificationVerdict.INCONCLUSIVE

    monkeypatch.setattr(DeterministicOrchestrator, "_review_finding", observe_claim)

    claimed = DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        sandbox.store,
        sandbox,
    ).process_next()

    assert claimed == audit_run.id
    assert observed_task_ids == [task.id]
    db_session.refresh(task)
    assert task.status == AuditTaskStatus.SUCCEEDED.value
    assert task.attempt == 1
