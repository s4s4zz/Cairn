"""PoC authoring inside the dynamic stage (§7.7, §7.8).

The stage decisions are the property under test: a PoC is authored only for a
critical or high finding whose category the built-in probes miss, its verdict
flows into §7.8 exactly as a probe verdict does, and the request that reaches
the validation Manager carries service kinds and a validated plan — never an
image or a model channel.
"""

from __future__ import annotations

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.orchestrator.engine import DeterministicOrchestrator
from cairn.sandbox.contracts import SandboxOperation, SandboxTemplateName
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    AuditTaskType,
    FindingConfidence,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.persistence.models import AuditTask, Finding

from .test_dynamic_stage import (
    DynamicSandbox,
    build_output,
    entrypoint_fact,
)
from .test_machine_review import (
    CONTROLLER,
    candidate_payload,
    findings_of,
    parked_run,
    settings_for,
    warnings_of,
)


def poc_result(finding_id: str, *, verdict: str = "confirmed") -> dict[str, object]:
    return {
        "contract": "cairn-poc-plan-v1",
        "status": "completed",
        "tool_name": "poc-author",
        "model": "claude-opus-5",
        "finding_id": finding_id,
        "reason_code": None,
        "plan": {
            "finding_id": finding_id,
            "category": "expression-injection",
            "request": {
                "method": "POST",
                "path": "/orders",
                "headers": {"content-type": "application/json"},
                "body": '{"owner":"x"}',
            },
            "injection": {
                "location": "body_field",
                "name": "owner",
                "benign": "alice",
                "payload": "${7*7}",
            },
            "criterion": {
                "kind": "contains_text",
                "match_text": "49",
                "status_code": None,
                "elapsed_ms": None,
            },
            "rationale": "The owner field is evaluated as an expression.",
        },
        "warnings": [],
    }


def unprobeable(**overrides: object) -> dict[str, object]:
    """A high finding in a category with no built-in probe."""

    payload = candidate_payload(
        category="expression-injection",
        cwe_ids=["CWE-917"],
    )
    payload.update(overrides)
    return payload


def drive(
    session: Session,
    tmp_path: Path,
    *,
    candidates,
    poc_results: dict[str, dict[str, object]] | None = None,
    dynamic_results=None,
) -> tuple:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(session, store, tmp_path, candidates)
    build_output(session, store, tmp_path, audit_run)
    entrypoint_fact(session, audit_run)
    sandbox = DynamicSandbox(store, tmp_path, None, dynamic_results)
    sandbox.poc_results = poc_results or {}
    DeterministicOrchestrator(
        session, settings_for(tmp_path), store, sandbox
    ).process_run(audit_run.id)
    session.commit()
    session.refresh(audit_run)
    return audit_run, sandbox


def dynamic_verifications(finding: Finding) -> list:
    return [
        v
        for v in finding.verifications
        if v.method == VerificationMethod.DYNAMIC_POC.value
    ]


# --- who gets a PoC -----------------------------------------------------------


def test_a_poc_is_authored_for_an_unprobeable_high_finding(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[unprobeable()],
    )

    assert sandbox.poc_requests
    tasks = list(
        db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.DYNAMIC_VERIFY.value,
            )
        )
    )
    author_tasks = [t for t in tasks if t.worker_name and t.worker_name.endswith(":poc-author")]
    assert author_tasks


def test_a_probeable_category_gets_no_authored_poc(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """SQL injection has a built-in probe, so nothing is authored for it."""

    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[candidate_payload()],  # sql-injection
    )
    del audit_run

    assert sandbox.poc_requests == []


def test_a_medium_finding_gets_no_authored_poc(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = drive(
        db_session,
        tmp_path,
        candidates=[unprobeable(severity="medium")],
    )
    del audit_run

    assert sandbox.poc_requests == []


# --- a PoC verdict flows into §7.8 -------------------------------------------


def test_a_confirmed_poc_makes_the_finding_verified(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [unprobeable()])
    build_output(db_session, store, tmp_path, audit_run)
    entrypoint_fact(db_session, audit_run)

    # The finding id is known only after promotion, so answer for whatever id
    # the author is asked about, and have the executed PoC confirm.
    class Adaptive(DynamicSandbox):
        def wait(self, sandbox_id, timeout_seconds):  # noqa: ANN001
            record = self.records[sandbox_id]
            if record.operation is SandboxOperation.AUTHOR_POC:
                fid = str(self.poc_requests[-1].semantic.poc.finding_id)
                self.poc_results = {fid: poc_result(fid)}
            elif record.template is SandboxTemplateName.VALIDATION:
                fid = str(self.dynamic_requests[-1].dynamic.poc_plans[0].finding_id)
                self.dynamic_results = [_confirming_dynamic_result(fid)]
            return super().wait(sandbox_id, timeout_seconds)

    sandbox = Adaptive(store, tmp_path, None, None)
    DeterministicOrchestrator(
        db_session, settings_for(tmp_path), store, sandbox
    ).process_run(audit_run.id)
    db_session.commit()

    finding = findings_of(db_session, audit_run)[0]
    assert finding.runtime_verification == RuntimeVerificationStatus.VERIFIED.value
    assert finding.confidence == FindingConfidence.CONFIRMED.value
    verdicts = {v.verdict for v in dynamic_verifications(finding)}
    assert VerificationVerdict.CONFIRMED.value in verdicts


def test_an_author_that_declines_leaves_the_finding_inconclusive(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """No plan means no PoC to run; the finding is inconclusive, never rejected."""

    audit_run, _sandbox = drive(
        db_session,
        tmp_path,
        candidates=[unprobeable()],
        poc_results={},  # the default: author declined
    )

    finding = findings_of(db_session, audit_run)[0]
    dynamic = dynamic_verifications(finding)
    assert dynamic
    assert all(v.verdict != VerificationVerdict.REJECTED.value for v in dynamic)


# --- the request the Manager receives ----------------------------------------


def test_the_author_request_carries_a_poc_assignment_not_a_scope(
    db_session: Session,
    tmp_path: Path,
) -> None:
    _audit_run, sandbox = drive(db_session, tmp_path, candidates=[unprobeable()])

    request = sandbox.poc_requests[0]
    assert request.template is SandboxTemplateName.SEMANTIC
    assert request.operation is SandboxOperation.AUTHOR_POC
    assert request.semantic.poc is not None
    assert request.semantic.scope is None
    assert request.semantic.candidate is None
    # The author needs the route to address a request; the reviewer did not.
    assert request.semantic.poc.route is not None


def test_the_validation_request_carries_the_authored_plan_and_no_model_channel(
    db_session: Session,
    tmp_path: Path,
) -> None:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path, [unprobeable()])
    build_output(db_session, store, tmp_path, audit_run)
    entrypoint_fact(db_session, audit_run)

    class Adaptive(DynamicSandbox):
        def wait(self, sandbox_id, timeout_seconds):  # noqa: ANN001
            record = self.records[sandbox_id]
            if record.operation is SandboxOperation.AUTHOR_POC:
                fid = str(self.poc_requests[-1].semantic.poc.finding_id)
                self.poc_results = {fid: poc_result(fid)}
            return super().wait(sandbox_id, timeout_seconds)

    sandbox = Adaptive(store, tmp_path, None, None)
    DeterministicOrchestrator(
        db_session, settings_for(tmp_path), store, sandbox
    ).process_run(audit_run.id)
    db_session.commit()

    assert sandbox.dynamic_requests
    spec = sandbox.dynamic_requests[0].dynamic
    assert spec.poc_plans  # the authored plan rode into the environment
    # The validation request has no model credential — only the semantic
    # template may carry one.
    assert sandbox.dynamic_requests[0].semantic is None


def _confirming_dynamic_result(finding_id: str) -> dict[str, object]:
    """A dynamic manifest whose one PoC outcome confirms `finding_id`."""

    exchange = {
        "method": "POST",
        "url": "http://127.0.0.1:8080/orders",
        "request_body": '{"owner":"${7*7}"}',
        "status_code": 200,
        "response_excerpt": "49",
        "response_bytes": 2,
        "elapsed_ms": 12,
        "error": None,
    }
    return {
        "contract": "cairn-dynamic-result-v1",
        "status": "completed",
        "tool_name": "dynamic-verifier",
        "reason_code": None,
        "app_started": True,
        "app_exit_code": 143,
        "app_log_path": "runtime/application.log",
        "services_ready": [],
        "outcomes": [
            {
                "finding_id": finding_id,
                "category": "expression-injection",
                "verdict": "confirmed",
                "reason_code": None,
                "detail": "The authored PoC's criterion matched the attack alone.",
                "baseline": {**exchange, "request_body": '{"owner":"alice"}', "response_excerpt": "hi"},
                "payload": exchange,
                "nonce": None,
                "echo_observed": False,
            }
        ],
        "warnings": [],
    }
