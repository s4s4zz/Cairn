"""The dynamic verification stage inside the Orchestrator (§7.7, §7.8).

6a recorded an unconditional `inconclusive` here because no environment
existed. These tests are about what changes once one does: a real runtime
verdict reaches the §7.8 decision, and the paths that still cannot produce one
keep saying so.
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

from cairn.dynamic.contracts import DYNAMIC_CONTRACT, DYNAMIC_TOOL_NAME
from cairn.orchestrator.engine import DeterministicOrchestrator
from cairn.sandbox.contracts import (
    SandboxArtifact,
    SandboxCreateRequest,
    SandboxRecord,
    SandboxStatus,
    SandboxTemplateName,
)
from cairn.sandbox.services import ServiceKind
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    ArtifactKind,
    AuditFactKind,
    AuditRunStatus,
    AuditTaskType,
    EvidenceType,
    FindingConfidence,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.persistence.models import (
    Artifact,
    AuditFact,
    AuditRun,
    AuditTask,
    Finding,
)

from .test_machine_review import (
    CONTROLLER,
    REPOSITORY_JAVA,
    VerifySandbox,
    candidate_payload,
    findings_of,
    parked_run,
    settings_for,
    verify_result,
    warnings_of,
)

FINDING_PLACEHOLDER = "00000000-0000-0000-0000-000000000000"


def dynamic_result(
    finding_id: str,
    *,
    verdict: str = "confirmed",
    status: str = "completed",
    reason_code: str | None = None,
) -> dict[str, object]:
    exchange = {
        "method": "GET",
        "url": "http://127.0.0.1:8080/users/1",
        "request_body": None,
        "status_code": 200,
        "response_excerpt": "ok",
        "response_bytes": 2,
        "elapsed_ms": 12,
        "error": None,
    }
    outcome: dict[str, object] = {
        "finding_id": finding_id,
        "category": "sql-injection",
        "verdict": verdict,
        "reason_code": None,
        "detail": "The quoted payload changed the response where a literal did not.",
        "baseline": exchange,
        "payload": {**exchange, "url": "http://127.0.0.1:8080/users/1'%20OR%20'1'='1"},
        "nonce": None,
        "echo_observed": False,
    }
    return {
        "contract": DYNAMIC_CONTRACT,
        "status": status,
        "tool_name": DYNAMIC_TOOL_NAME,
        "reason_code": reason_code,
        "app_started": True,
        "app_exit_code": 143,
        "app_log_path": "runtime/application.log",
        "services_ready": ["postgres"],
        "outcomes": [outcome],
        "warnings": [],
    }


class DynamicSandbox(VerifySandbox):
    """Answers validation operations as well as blind reviews."""

    def __init__(
        self,
        store: LocalArtifactStore,
        tmp_path: Path,
        results: list[dict[str, object]] | None = None,
        dynamic_results: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(store, tmp_path, results)
        self.dynamic_results = list(dynamic_results or [])
        self.dynamic_requests: list[SandboxCreateRequest] = []

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        if request.template is SandboxTemplateName.VALIDATION:
            self.dynamic_requests.append(request)
        return super().create(request)

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        record = self.records[sandbox_id]
        if record.template is not SandboxTemplateName.VALIDATION:
            return super().wait(sandbox_id, timeout_seconds)
        payload = (
            self.dynamic_results.pop(0)
            if self.dynamic_results
            else dynamic_result(FINDING_PLACEHOLDER)
        )
        archive_path = self.tmp_path / f"{sandbox_id}-dynamic.tar"
        encoded = json.dumps(payload).encode()
        with tarfile.open(archive_path, mode="w") as archive:
            info = tarfile.TarInfo("dynamic-result.json")
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


def build_output(
    session: Session,
    store: LocalArtifactStore,
    tmp_path: Path,
    audit_run: AuditRun,
    *,
    runnable: bool = True,
) -> None:
    """Register a build task whose output carries a runnable artifact."""

    task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.BUILD.value,
        scope_key="deterministic:build",
        scope={},
        required_capabilities=[],
        status="succeeded",
        attempt=1,
        max_attempts=3,
        timeout_seconds=900,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()

    manifest = {
        "contract": "cairn-deterministic-result-v1",
        "operation": "build",
        "status": "completed",
        "tool_name": "cairn-java-build",
        "tool_version": "1.0.0",
        "reason_code": None,
        "warnings": [],
        "raw_result_paths": [],
        "inventory": None,
        "build": {
            "status": "success",
            "steps": [],
            "runnable_artifacts": (
                [
                    {
                        "module_path": "web",
                        "path": "artifacts/web_app.jar",
                        "build_system": "maven",
                        "size_bytes": 1024,
                    }
                ]
                if runnable
                else []
            ),
        },
        "candidates": [],
    }
    archive_path = tmp_path / f"build-{uuid4()}.tar"
    encoded = json.dumps(manifest).encode()
    with tarfile.open(archive_path, mode="w") as archive:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(encoded)
        archive.addfile(info, BytesIO(encoded))
    stored = store.put_file(archive_path)
    artifact = Artifact(
        audit_run_id=audit_run.id,
        kind=ArtifactKind.SCAN_RESULT.value,
        storage_key=stored.storage_key,
        sha256=stored.sha256,
        size_bytes=stored.size_bytes,
        media_type="application/x-tar",
        access_level="sensitive",
        produced_by_task_id=task.id,
    )
    session.add(artifact)
    session.flush()
    task.output_artifact_ids = [str(artifact.id)]
    session.commit()


def entrypoint_fact(session: Session, audit_run: AuditRun) -> None:
    """The index record a probe needs to address the endpoint."""

    task = session.scalar(
        select(AuditTask).where(AuditTask.audit_run_id == audit_run.id)
    )
    assert task is not None
    session.add(
        AuditFact(
            audit_run_id=audit_run.id,
            kind=AuditFactKind.ENTRYPOINT.value,
            structured_payload={
                "items": [
                    {
                        "path": CONTROLLER,
                        "line": 10,
                        "kind": "http-route",
                        "symbol": "UserController.user",
                        "route": "/users/{name}",
                        "annotations": ["GetMapping"],
                    }
                ]
            },
            evidence_ids=[],
            created_by_task_id=task.id,
        )
    )
    session.commit()


def drive(
    session: Session,
    tmp_path: Path,
    *,
    candidates=None,
    verify_results=None,
    dynamic_results=None,
    runnable: bool = True,
    with_entrypoint: bool = True,
) -> tuple[AuditRun, DynamicSandbox]:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(
        session,
        store,
        tmp_path,
        candidates if candidates is not None else [candidate_payload()],
    )
    build_output(session, store, tmp_path, audit_run, runnable=runnable)
    if with_entrypoint:
        entrypoint_fact(session, audit_run)
    sandbox = DynamicSandbox(store, tmp_path, verify_results, dynamic_results)
    DeterministicOrchestrator(
        session,
        settings_for(tmp_path),
        store,
        sandbox,
    ).process_run(audit_run.id)
    session.commit()
    session.refresh(audit_run)
    return audit_run, sandbox


def dynamic_verifications(finding: Finding) -> list:
    return [
        verification
        for verification in finding.verifications
        if verification.method == VerificationMethod.DYNAMIC_POC.value
    ]


# --- a real runtime verdict reaches the decision ------------------------------


def test_a_runtime_confirmation_marks_the_finding_verified(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """§7.8 path one: independent confirmation plus dynamic verification."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [candidate_payload()])
    build_output(db_session, store, tmp_path, audit_run)
    entrypoint_fact(db_session, audit_run)
    findings_before = db_session.scalar(select(Finding))
    del findings_before

    # The finding id is only known once the pipeline has promoted it, so the
    # sandbox is told to answer for whatever id it is handed.
    class Adaptive(DynamicSandbox):
        def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
            record = self.records[sandbox_id]
            if record.template is SandboxTemplateName.VALIDATION:
                target = self.dynamic_requests[-1].dynamic.targets[0]
                self.dynamic_results = [dynamic_result(str(target.finding_id))]
            return super().wait(sandbox_id, timeout_seconds)

    sandbox = Adaptive(store, tmp_path, None, None)
    DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        store,
        sandbox,
    ).process_run(audit_run.id)
    db_session.commit()

    finding = findings_of(db_session, audit_run)[0]
    assert finding.runtime_verification == RuntimeVerificationStatus.VERIFIED.value
    assert finding.confidence == FindingConfidence.CONFIRMED.value
    assert finding.status == FindingStatus.AWAITING_HUMAN_REVIEW.value
    verdicts = {row.verdict for row in dynamic_verifications(finding)}
    assert verdicts == {VerificationVerdict.CONFIRMED.value}


def test_the_probe_exchanges_are_saved_as_evidence(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """§7.7 requires the request, response, timing and exit status be kept."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [candidate_payload()])
    build_output(db_session, store, tmp_path, audit_run)
    entrypoint_fact(db_session, audit_run)

    class Adaptive(DynamicSandbox):
        def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
            record = self.records[sandbox_id]
            if record.template is SandboxTemplateName.VALIDATION:
                target = self.dynamic_requests[-1].dynamic.targets[0]
                self.dynamic_results = [dynamic_result(str(target.finding_id))]
            return super().wait(sandbox_id, timeout_seconds)

    DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        store,
        Adaptive(store, tmp_path, None, None),
    ).process_run(audit_run.id)
    db_session.commit()

    finding = findings_of(db_session, audit_run)[0]
    exchanges = [
        evidence
        for evidence in finding.evidence
        if evidence.type == EvidenceType.HTTP_EXCHANGE.value
    ]
    assert exchanges
    assert any("毫秒" in evidence.summary for evidence in exchanges)
    # Both halves, not one: the attack request is the half that carries the
    # finding, and evidence deduplication used to collapse the pair into the
    # baseline because neither row names an Artifact.
    assert {"基线请求", "攻击请求"} == {
        evidence.summary.split("：", 1)[0] for evidence in exchanges
    }


# --- what still cannot produce a runtime verdict ------------------------------


def test_no_runnable_artifact_keeps_the_inconclusive_path(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """§7.3: a build that produced nothing runnable marks dynamic verification
    unavailable rather than failing the run."""

    audit_run, sandbox = drive(db_session, tmp_path, runnable=False)

    assert sandbox.dynamic_requests == []
    finding = findings_of(db_session, audit_run)[0]
    assert dynamic_verifications(finding)[0].verdict == (
        VerificationVerdict.INCONCLUSIVE.value
    )
    assert finding.runtime_verification == RuntimeVerificationStatus.UNVERIFIED.value
    assert "DYNAMIC_BUILD_ARTIFACT_MISSING" in warnings_of(db_session, audit_run)


def test_a_finding_with_no_indexed_entrypoint_is_not_probed(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path, with_entrypoint=False)

    assert sandbox.dynamic_requests == []
    finding = findings_of(db_session, audit_run)[0]
    assert dynamic_verifications(finding)[0].verdict == (
        VerificationVerdict.INCONCLUSIVE.value
    )


def test_an_unprobeable_category_is_never_runtime_rejected(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload(category="open-redirect", cwe_ids=["CWE-601"])],
    )

    assert sandbox.dynamic_requests == []
    finding = findings_of(db_session, audit_run)[0]
    assert dynamic_verifications(finding)[0].verdict != (
        VerificationVerdict.REJECTED.value
    )


def test_a_disabled_policy_skips_the_environment_entirely(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [candidate_payload()])
    audit_run.policy.dynamic_verification = "disabled"
    build_output(db_session, store, tmp_path, audit_run)
    entrypoint_fact(db_session, audit_run)
    db_session.commit()

    sandbox = DynamicSandbox(store, tmp_path, None, None)
    DeterministicOrchestrator(
        db_session,
        settings_for(tmp_path),
        store,
        sandbox,
    ).process_run(audit_run.id)
    db_session.commit()

    assert sandbox.dynamic_requests == []
    assert "DYNAMIC_VERIFICATION_DISABLED" in warnings_of(db_session, audit_run)


# --- the request the Manager receives -----------------------------------------


def test_the_request_names_service_kinds_and_never_an_image(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(db_session, tmp_path)
    del audit_run

    assert sandbox.dynamic_requests
    spec = sandbox.dynamic_requests[0].dynamic
    payload = json.dumps(spec.model_dump(mode="json"))
    assert "postgres:16-alpine" not in payload
    assert "image" not in payload
    for service in spec.services:
        assert service in set(ServiceKind)


def test_the_echo_target_is_always_present(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """It is the platform's own out-of-band tripwire, not something the
    application asked for."""

    audit_run, sandbox = drive(db_session, tmp_path)
    del audit_run

    assert ServiceKind.ECHO in sandbox.dynamic_requests[0].dynamic.services


def test_one_environment_serves_the_whole_run(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Standing the application up is the expensive part; probing one more
    finding against a running one is not."""

    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[
            candidate_payload(),
            candidate_payload(
                fingerprint="c" * 64,
                root_cause_key="d" * 64,
                severity="medium",
            ),
        ],
    )
    del audit_run

    assert len(sandbox.dynamic_requests) == 1
    assert len(sandbox.dynamic_requests[0].dynamic.targets) >= 1


def test_the_verification_task_is_created_once(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _sandbox = drive(db_session, tmp_path)

    tasks = list(
        db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.DYNAMIC_VERIFY.value,
            )
        )
    )

    assert len(tasks) == 1
    assert tasks[0].worker_name.endswith(":dynamic-verifier")


def test_the_run_still_reaches_human_review(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _sandbox = drive(db_session, tmp_path)

    assert audit_run.status == AuditRunStatus.HUMAN_REVIEW.value
