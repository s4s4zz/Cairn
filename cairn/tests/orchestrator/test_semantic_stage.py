"""The semantic stage inside the Orchestrator.

Everything here runs against a fake Sandbox, because the property under test is
what the Orchestrator does with a review result — persist candidates, merge
them with scanner evidence, record an intent, report a refusal as coverage —
not whether a container starts.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from io import BytesIO
import json
from pathlib import Path
import tarfile
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import ToolStatus
from cairn.gateway.tokens import verify_grant
from cairn.model_provider import ModelProvider, ModelProviderConfigStore
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.engine import DeterministicOrchestrator
from cairn.sandbox.contracts import (
    SandboxArtifact,
    SandboxCreateRequest,
    SandboxLimits,
    SandboxRecord,
    SandboxStatus,
    SandboxTemplateName,
)
from cairn.semantic.contracts import (
    REASON_MODEL_REFUSED,
    SEMANTIC_CONTRACT,
    SEMANTIC_TOOL_NAME,
)
from cairn.semantic.findings import ReviewScope
from cairn.server.artifacts.local import LocalArtifactStore
from cairn.server.domain.enums import (
    AuditFactKind,
    AuditIntentStatus,
    AuditRunStatus,
    AuditTaskStatus,
    AuditTaskType,
    BuildStatus,
)
from cairn.server.persistence.models import (
    AuditCoverage,
    AuditFact,
    AuditIntent,
    AuditIntentSource,
    AuditRun,
    AuditTask,
)

from .test_engine import FakeSandbox, create_run

GRANT_KEY = b"orchestrator-grant-signing-key-01"
SOURCE_PATH = "web/src/main/java/com/example/app/HelloController.java"


def semantic_result(
    scope_key: str,
    *,
    status: str = "completed",
    reason_code: str | None = None,
    candidates: list[dict[str, object]] | None = None,
    findings: list[dict[str, object]] | None = None,
) -> dict[str, object]:
    return {
        "contract": SEMANTIC_CONTRACT,
        "status": status,
        "tool_name": SEMANTIC_TOOL_NAME,
        "model": "claude-opus-5",
        "scope_key": scope_key,
        "reason_code": reason_code,
        "findings": findings or [],
        "candidates": candidates or [],
        "rejections": [],
        "warnings": [],
        "usage": {
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0,
            "requests": 1,
        },
    }


def candidate_payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "rule_id": "semantic/sql-injection",
        "cwe_ids": ["CWE-89"],
        "category": "sql-injection",
        "severity": "high",
        "confidence": "medium",
        "message": "user input reaches a JDBC statement",
        "locations": [
            {
                "path": SOURCE_PATH,
                "start_line": 1,
                "end_line": 1,
                "start_column": None,
                "end_column": None,
                "symbol": "HelloController.hello",
                "role": "sink",
            }
        ],
        "sink": "java.sql.Statement.execute",
        "fingerprint": "a" * 64,
        "root_cause_key": "b" * 64,
        "discovered_by": [SEMANTIC_TOOL_NAME],
        "source_rules": ["semantic/sql-injection"],
        "call_chain": [
            {
                "path": SOURCE_PATH,
                "start_line": 1,
                "end_line": 1,
                "symbol": "HelloController.hello",
                "role": "entrypoint",
                "note": None,
            },
            {
                "path": SOURCE_PATH,
                "start_line": 2,
                "end_line": 2,
                "symbol": "Repo.find",
                "role": "sink",
                "note": None,
            },
        ],
        "controllability": "the owner request parameter is unvalidated",
        "existing_defenses": [],
        "attack_preconditions": "unauthenticated reachability",
        "impact": "arbitrary read of the orders table",
        "recommended_verification": "replay with a quote",
        "severity_conflict": [],
    }
    payload.update(overrides)
    return payload


def findings_stub() -> list[dict[str, object]]:
    """A minimal accepted finding, so `candidates` may be non-empty."""

    return [
        {
            "rule_id": "semantic/sql-injection",
            "cwe_ids": ["CWE-89"],
            "category": "sql-injection",
            "severity": "high",
            "confidence": "medium",
            "message": "user input reaches a JDBC statement",
            "locations": candidate_payload()["locations"],
            "sink": "java.sql.Statement.execute",
            "call_chain": candidate_payload()["call_chain"],
            "controllability": "the owner request parameter is unvalidated",
            "existing_defenses": [],
            "attack_preconditions": "unauthenticated reachability",
            "impact": "arbitrary read of the orders table",
            "recommended_verification": "replay with a quote",
        }
    ]


class SemanticSandbox(FakeSandbox):
    """A FakeSandbox that answers semantic operations from a queue."""

    def __init__(
        self,
        store: LocalArtifactStore,
        tmp_path: Path,
        manifests: dict[str, object],
        semantic_results: list[dict[str, object]] | None = None,
    ) -> None:
        super().__init__(store, tmp_path, manifests)
        self.semantic_results = semantic_results or []
        self.semantic_requests: list[SandboxCreateRequest] = []

    def create(self, request: SandboxCreateRequest) -> SandboxRecord:
        if request.template is SandboxTemplateName.SEMANTIC:
            self.semantic_requests.append(request)
        return super().create(request)

    def wait(self, sandbox_id: UUID, timeout_seconds: float) -> SandboxRecord:
        record = self.records[sandbox_id]
        if record.template is not SandboxTemplateName.SEMANTIC:
            return super().wait(sandbox_id, timeout_seconds)
        payload = (
            self.semantic_results.pop(0)
            if self.semantic_results
            else semantic_result(
                self.semantic_requests[-1].semantic.scope.scope_key
            )
        )
        archive_path = self.tmp_path / f"{sandbox_id}-semantic.tar"
        encoded = json.dumps(payload).encode()
        with tarfile.open(archive_path, mode="w") as archive:
            info = tarfile.TarInfo("semantic-result.json")
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


def settings_with_grant_key(tmp_path: Path) -> OrchestratorSettings:
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


def parked_run(session: Session, store: LocalArtifactStore, tmp_path: Path) -> AuditRun:
    """A run sitting exactly where subproject 5a left it."""

    audit_run = create_run(session, store, tmp_path)
    audit_run.status = AuditRunStatus.SEMANTIC_AUDITING.value
    audit_run.current_stage = AuditRunStatus.SEMANTIC_AUDITING.value
    inventory_task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.INVENTORY.value,
        scope_key="deterministic:inventory",
        scope={},
        required_capabilities=[],
        status=AuditTaskStatus.SUCCEEDED.value,
        attempt=1,
        max_attempts=3,
        timeout_seconds=60,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )
    session.add(inventory_task)
    session.flush()
    session.add(
        AuditCoverage(
            audit_run_id=audit_run.id,
            modules_total=1,
            modules_analyzed=1,
            java_files_total=1,
            java_files_analyzed=1,
            entrypoints_total=2,
            entrypoints_analyzed=0,
            sensitive_sinks_total=2,
            sensitive_sinks_analyzed=0,
            build_status=BuildStatus.SUCCESS.value,
            static_tools_completed={},
            skipped_paths=[],
            unsupported_components=[],
            coverage_warnings=[],
        )
    )
    session.add_all(
        [
            AuditFact(
                audit_run_id=audit_run.id,
                kind=AuditFactKind.ARCHITECTURE.value,
                structured_payload={
                    "modules": [{"path": "web"}],
                    "permissions": [],
                },
                evidence_ids=[],
                created_by_task_id=inventory_task.id,
            ),
            AuditFact(
                audit_run_id=audit_run.id,
                kind=AuditFactKind.ENTRYPOINT.value,
                structured_payload={
                    "items": [{"path": SOURCE_PATH, "kind": "http-route", "line": 1}]
                },
                evidence_ids=[],
                created_by_task_id=inventory_task.id,
            ),
            AuditFact(
                audit_run_id=audit_run.id,
                kind=AuditFactKind.SINK.value,
                structured_payload={
                    "items": [
                        {"path": SOURCE_PATH, "kind": "database-query", "line": 2}
                    ]
                },
                evidence_ids=[],
                created_by_task_id=inventory_task.id,
            ),
        ]
    )
    session.commit()
    return audit_run


def run_semantic(
    session: Session,
    tmp_path: Path,
    *,
    semantic_results: list[dict[str, object]] | None = None,
    settings: OrchestratorSettings | None = None,
) -> tuple[AuditRun, SemanticSandbox]:
    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(session, store, tmp_path)
    sandbox = SemanticSandbox(store, tmp_path, {}, semantic_results)
    orchestrator = DeterministicOrchestrator(
        session,
        settings or settings_with_grant_key(tmp_path),
        store,
        sandbox,
    )
    orchestrator._semantic_audit(audit_run)
    session.commit()
    return audit_run, sandbox


def test_the_stage_advances_the_run_to_dynamic_verification(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _sandbox = run_semantic(db_session, tmp_path)

    assert audit_run.status == AuditRunStatus.DYNAMIC_VERIFYING.value
    assert audit_run.progress == 80


def test_a_semantic_task_is_created_per_planned_scope(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = run_semantic(db_session, tmp_path)

    tasks = list(
        db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.SEMANTIC_REVIEW.value,
            )
        )
    )

    assert tasks
    assert len(tasks) == len(sandbox.semantic_requests)
    assert all(task.status == AuditTaskStatus.SUCCEEDED.value for task in tasks)


def test_the_sandbox_receives_a_verifiable_grant_bound_to_its_task(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """The Gateway will only honour a grant it can verify, so the seam between
    minting and verification has to agree."""

    audit_run, sandbox = run_semantic(db_session, tmp_path)
    request = sandbox.semantic_requests[0]

    grant = verify_grant(request.semantic.grant_token, GRANT_KEY)

    assert grant.audit_run_id == str(audit_run.id)
    assert grant.model == "claude-opus-5"
    assert grant.worker == "deterministic-orchestrator"
    assert grant.max_requests >= 1
    assert UUID(grant.task_id)


def test_workbench_selected_model_is_bound_into_the_real_worker_grant(
    db_session: Session,
    tmp_path: Path,
) -> None:
    provider_file = tmp_path / "llm" / "provider.json"
    ModelProviderConfigStore(provider_file, b"m" * 32).write(
        provider=ModelProvider.OPENAI,
        base_url="https://api.openai.com",
        model="gpt-5-mini",
        api_key="sk-not-readable-by-orchestrator",
    )
    settings = settings_with_grant_key(tmp_path).model_copy(
        update={"llm_provider_config_file": provider_file}
    )

    _audit_run, sandbox = run_semantic(
        db_session,
        tmp_path,
        settings=settings,
    )
    grant = verify_grant(
        sandbox.semantic_requests[0].semantic.grant_token,
        GRANT_KEY,
    )

    assert grant.model == "gpt-5-mini"


def test_a_minted_grant_is_short_lived_enough_for_the_gateway(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """The Gateway refuses a grant whose remaining life exceeds its maximum;
    a minter that ignores that produces tokens nothing will accept."""

    from cairn.gateway.config import GatewaySettings

    _audit_run, sandbox = run_semantic(db_session, tmp_path)
    api_key_file = tmp_path / "api.key"
    api_key_file.write_text("sk-ant-not-used-here")
    gateway_settings = GatewaySettings(
        api_key_file=api_key_file,
        grant_key_file=tmp_path / "grant.key",
    )

    grant = verify_grant(
        sandbox.semantic_requests[0].semantic.grant_token,
        GRANT_KEY,
        max_lifetime_seconds=gateway_settings.max_grant_lifetime_seconds,
    )

    assert grant.expires_at > datetime.now(UTC)


def test_the_grant_is_never_written_to_the_task_row(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, sandbox = run_semantic(db_session, tmp_path)
    token = sandbox.semantic_requests[0].semantic.grant_token

    tasks = list(
        db_session.scalars(
            select(AuditTask).where(AuditTask.audit_run_id == audit_run.id)
        )
    )

    assert all(token not in json.dumps(task.scope) for task in tasks)


def test_candidates_are_persisted_as_candidate_finding_facts(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _sandbox = run_semantic(
        db_session,
        tmp_path,
        semantic_results=[
            semantic_result(
                "semantic:web:http-endpoint:authorization",
                candidates=[candidate_payload()],
                findings=findings_stub(),
            ),
            semantic_result("semantic:web:http-endpoint:sql-injection"),
        ],
    )

    facts = list(
        db_session.scalars(
            select(AuditFact).where(
                AuditFact.audit_run_id == audit_run.id,
                AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
            )
        )
    )

    assert len(facts) == 1
    assert facts[0].structured_payload["candidate"]["controllability"]


def test_a_semantic_candidate_merges_with_a_scanner_candidate(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """The point of a shared root_cause_key: the call chain the model
    established has to survive contact with a scanner hit on the same
    weakness."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path)
    scanner_task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.SAST.value,
        scope_key="deterministic:semgrep",
        scope={},
        required_capabilities=[],
        status=AuditTaskStatus.SUCCEEDED.value,
        attempt=1,
        max_attempts=3,
        timeout_seconds=60,
        input_artifact_ids=[],
        output_artifact_ids=[],
    )
    db_session.add(scanner_task)
    db_session.flush()
    db_session.add(
        AuditFact(
            audit_run_id=audit_run.id,
            kind=AuditFactKind.CANDIDATE_FINDING.value,
            structured_payload={
                "candidate": candidate_payload(
                    rule_id="java.lang.security.audit.sqli",
                    discovered_by=["semgrep"],
                    source_rules=["java.lang.security.audit.sqli"],
                    call_chain=[],
                    controllability=None,
                    attack_preconditions=None,
                    impact=None,
                    recommended_verification=None,
                    fingerprint="c" * 64,
                ),
                "raw_artifact_ids": [],
            },
            evidence_ids=[],
            created_by_task_id=scanner_task.id,
        )
    )
    db_session.commit()

    sandbox = SemanticSandbox(
        store,
        tmp_path,
        {},
        [
            semantic_result(
                "semantic:web:http-endpoint:authorization",
                candidates=[candidate_payload()],
                findings=findings_stub(),
            ),
            semantic_result("semantic:web:http-endpoint:sql-injection"),
        ],
    )
    DeterministicOrchestrator(
        db_session,
        settings_with_grant_key(tmp_path),
        store,
        sandbox,
    )._semantic_audit(audit_run)
    db_session.commit()

    facts = list(
        db_session.scalars(
            select(AuditFact).where(
                AuditFact.audit_run_id == audit_run.id,
                AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
            )
        )
    )

    assert len(facts) == 1
    merged = facts[0].structured_payload["candidate"]
    assert len(merged["call_chain"]) == 2
    assert merged["controllability"]
    assert set(merged["discovered_by"]) == {"semgrep", SEMANTIC_TOOL_NAME}


def test_one_audit_intent_is_recorded_per_scope(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """The hand-off dynamic verification claims. Recorded even for a scope that
    found nothing: 'reviewed and clean' is a result the later stages need."""

    audit_run, sandbox = run_semantic(db_session, tmp_path)

    intents = list(
        db_session.scalars(
            select(AuditIntent).where(AuditIntent.audit_run_id == audit_run.id)
        )
    )

    assert len(intents) == len(sandbox.semantic_requests)
    assert all(
        intent.status == AuditIntentStatus.PENDING.value for intent in intents
    )
    assert all(intent.scope["scope_key"] for intent in intents)


def test_an_intent_links_the_candidate_facts_that_motivated_it(
    db_session: Session,
    tmp_path: Path,
) -> None:
    audit_run, _sandbox = run_semantic(
        db_session,
        tmp_path,
        semantic_results=[
            semantic_result(
                "semantic:web:http-endpoint:authorization",
                candidates=[candidate_payload()],
                findings=findings_stub(),
            ),
            semantic_result("semantic:web:http-endpoint:sql-injection"),
        ],
    )

    links = list(db_session.scalars(select(AuditIntentSource)))

    assert len(links) == 1


def test_a_model_refusal_becomes_a_coverage_warning_not_a_crash(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """A security auditor tripping a cyber classifier has to be visible."""

    audit_run, _sandbox = run_semantic(
        db_session,
        tmp_path,
        semantic_results=[
            semantic_result(
                "semantic:web:http-endpoint:authorization",
                status="unavailable",
                reason_code=REASON_MODEL_REFUSED,
            ),
            semantic_result(
                "semantic:web:http-endpoint:sql-injection",
                status="unavailable",
                reason_code=REASON_MODEL_REFUSED,
            ),
        ],
    )

    coverage = db_session.get(AuditCoverage, audit_run.id)

    assert coverage is not None
    assert REASON_MODEL_REFUSED in {
        warning["reason_code"] for warning in coverage.coverage_warnings
    }
    assert audit_run.status == AuditRunStatus.DYNAMIC_VERIFYING.value
    assert audit_run.warning_count > 0


def test_an_empty_plan_still_advances_the_run(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """A repository with no reachable entrypoint is a valid audit result."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = create_run(db_session, store, tmp_path)
    audit_run.status = AuditRunStatus.SEMANTIC_AUDITING.value
    audit_run.current_stage = AuditRunStatus.SEMANTIC_AUDITING.value
    db_session.commit()
    sandbox = SemanticSandbox(store, tmp_path, {}, [])

    DeterministicOrchestrator(
        db_session,
        settings_with_grant_key(tmp_path),
        store,
        sandbox,
    )._semantic_audit(audit_run)
    db_session.commit()

    assert audit_run.status == AuditRunStatus.DYNAMIC_VERIFYING.value
    assert sandbox.semantic_requests == []


def test_a_missing_grant_key_fails_the_scope_and_is_reported(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """Fails closed and visibly, rather than quietly skipping semantic review."""

    token_file = tmp_path / "sandbox-token"
    token_file.write_text("s" * 40)
    settings = OrchestratorSettings(
        database_url="sqlite+pysqlite:///:memory:",
        artifact_root=tmp_path / "artifacts",
        ingestion_work_root=tmp_path / "ingestion",
        sandbox_auth_token_file=token_file,
    )
    audit_run, sandbox = run_semantic(db_session, tmp_path, settings=settings)

    coverage = db_session.get(AuditCoverage, audit_run.id)

    assert sandbox.semantic_requests == []
    assert coverage is not None
    assert "SEMANTIC_GRANT_KEY_UNAVAILABLE" in {
        warning["reason_code"] for warning in coverage.coverage_warnings
    }
    assert audit_run.status == AuditRunStatus.DYNAMIC_VERIFYING.value


def test_the_stage_is_idempotent_on_a_second_pass(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """`uq_audit_tasks_run_scope_key` is what stops a re-run from paying for
    every conversation twice."""

    store = LocalArtifactStore(tmp_path / "artifacts")
    audit_run = parked_run(db_session, store, tmp_path)
    settings = settings_with_grant_key(tmp_path)

    first = SemanticSandbox(store, tmp_path, {}, [])
    DeterministicOrchestrator(
        db_session, settings, store, first
    )._semantic_audit(audit_run)
    db_session.commit()
    task_ids = {
        task.id
        for task in db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.SEMANTIC_REVIEW.value,
            )
        )
    }

    audit_run.status = AuditRunStatus.SEMANTIC_AUDITING.value
    db_session.commit()
    second = SemanticSandbox(store, tmp_path, {}, [])
    DeterministicOrchestrator(
        db_session, settings, store, second
    )._semantic_audit(audit_run)
    db_session.commit()

    replayed_ids = {
        task.id
        for task in db_session.scalars(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.type == AuditTaskType.SEMANTIC_REVIEW.value,
            )
        )
    }

    assert replayed_ids == task_ids
    assert second.semantic_requests == []


def test_coverage_records_what_was_actually_reviewed(
    db_session: Session,
    tmp_path: Path,
) -> None:
    """`entrypoints_analyzed` was hardcoded to zero before this stage existed."""

    audit_run, _sandbox = run_semantic(db_session, tmp_path)

    coverage = db_session.get(AuditCoverage, audit_run.id)

    assert coverage is not None
    assert coverage.entrypoints_analyzed > 0
    assert coverage.entrypoints_analyzed <= coverage.entrypoints_total
