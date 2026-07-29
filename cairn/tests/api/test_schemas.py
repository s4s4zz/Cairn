from uuid import uuid4

from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError
import pytest

from cairn.server.domain.enums import (
    DynamicVerificationMode,
    FindingConfidence,
    FindingSeverity,
    LocationOriginKind,
    LocationRole,
    SourceType,
)
from cairn.server.errors import NotFoundError, register_error_handlers
from cairn.server.schemas.audit_runs import AuditRunCreate
from cairn.server.schemas.findings import CandidateFindingCommand
from cairn.server.schemas.policies import AuditPolicyCreate, SUPPORTED_SCANNERS
from cairn.server.schemas.repositories import RepositoryCreate


def test_repository_create_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        RepositoryCreate.model_validate(
            {
                "name": "demo",
                "source_type": "git",
                "remote_url": "https://example.invalid/demo.git",
                "origin": "legacy",
            }
        )


def test_git_repository_requires_supported_remote_url() -> None:
    with pytest.raises(ValidationError):
        RepositoryCreate(name="demo", source_type=SourceType.GIT)
    with pytest.raises(ValidationError):
        RepositoryCreate(
            name="demo",
            source_type=SourceType.GIT,
            remote_url="file:///srv/demo",
        )
    with pytest.raises(ValidationError):
        RepositoryCreate(
            name="demo",
            source_type=SourceType.GIT,
            remote_url="https://token@example.invalid/demo.git",
        )

    repository = RepositoryCreate(
        name=" demo ",
        source_type=SourceType.GIT,
        remote_url="git@example.invalid:team/demo.git",
    )
    assert repository.name == "demo"


def test_upload_repository_rejects_git_only_fields() -> None:
    with pytest.raises(ValidationError):
        RepositoryCreate(
            name="upload",
            source_type=SourceType.ZIP,
            remote_url="https://example.invalid/demo.git",
        )


def test_policy_defaults_to_comprehensive_dynamic_audit() -> None:
    policy = AuditPolicyCreate(name="comprehensive")

    assert set(policy.enabled_scanners) == SUPPORTED_SCANNERS
    assert policy.dynamic_verification is DynamicVerificationMode.REQUIRED


def test_policy_rejects_unknown_or_duplicate_scanners() -> None:
    with pytest.raises(ValidationError):
        AuditPolicyCreate(name="bad", enabled_scanners=["unknown"])
    with pytest.raises(ValidationError):
        AuditPolicyCreate(name="bad", enabled_scanners=["semgrep", "semgrep"])


def test_audit_run_source_request_is_a_strict_discriminated_union() -> None:
    request = AuditRunCreate.model_validate(
        {
            "repository_id": str(uuid4()),
            "policy_id": str(uuid4()),
            "source_request": {"type": "git_ref", "ref": "main"},
        }
    )
    assert request.source_request.type == "git_ref"

    with pytest.raises(ValidationError):
        AuditRunCreate.model_validate(
            {
                "repository_id": str(uuid4()),
                "policy_id": str(uuid4()),
                "source_request": {
                    "type": "git_ref",
                    "ref": "main",
                    "local_path": "C:/source",
                },
            }
        )


def candidate_payload() -> dict[str, object]:
    return {
        "audit_run_id": str(uuid4()),
        "fingerprint": "a" * 64,
        "title": "SQL injection",
        "description": "Untrusted input reaches a SQL sink.",
        "category": "injection",
        "cwe_id": "CWE-89",
        "severity": FindingSeverity.HIGH,
        "confidence": FindingConfidence.HIGH,
        "attack_preconditions": "Attacker controls the query parameter.",
        "impact": "Database confidentiality and integrity loss.",
        "remediation": "Use parameterized queries.",
        "discovered_by": "semantic-reviewer",
        "locations": [
            {
                "role": LocationRole.SINK,
                "file_path": "src/main/java/Demo.java",
                "start_line": 42,
                "end_line": 42,
                "code_snippet": "statement.execute(input);",
                "snapshot_sha": "b" * 64,
                "ordinal": 0,
            }
        ],
    }


def test_candidate_command_forbids_public_state_and_confirmed_confidence() -> None:
    payload = candidate_payload()
    payload["status"] = "confirmed"
    with pytest.raises(ValidationError):
        CandidateFindingCommand.model_validate(payload)

    payload = candidate_payload()
    payload["confidence"] = FindingConfidence.CONFIRMED
    with pytest.raises(ValidationError):
        CandidateFindingCommand.model_validate(payload)


def test_candidate_command_requires_at_least_one_location() -> None:
    payload = candidate_payload()
    payload["locations"] = []
    with pytest.raises(ValidationError):
        CandidateFindingCommand.model_validate(payload)


def test_legacy_candidate_location_defaults_to_source_origin() -> None:
    command = CandidateFindingCommand.model_validate(candidate_payload())

    location = command.locations[0]
    assert location.origin_kind is LocationOriginKind.SOURCE
    assert location.source_path == "src/main/java/Demo.java"
    assert location.file_path == location.source_path


def test_candidate_command_accepts_bytecode_location_without_source_lines() -> None:
    payload = candidate_payload()
    payload["locations"] = [
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
    ]

    command = CandidateFindingCommand.model_validate(payload)

    location = command.locations[0]
    assert location.origin_kind is LocationOriginKind.BYTECODE
    assert location.file_path is None
    assert location.start_line is None
    assert location.code_snippet is None
    assert location.bytecode_offset == 18


def test_candidate_command_rejects_partial_bytecode_method_identity() -> None:
    payload = candidate_payload()
    payload["locations"] = [
        {
            "role": "sink",
            "origin_kind": "bytecode",
            "entry_path": "demo/Action.class",
            "class_name": "demo.Action",
            "method_name": "execute",
            "snapshot_sha": "b" * 64,
            "ordinal": 0,
        }
    ]

    with pytest.raises(ValidationError):
        CandidateFindingCommand.model_validate(payload)


def test_domain_error_handler_returns_stable_body_and_request_id() -> None:
    app = FastAPI()
    register_error_handlers(app)

    @app.get("/missing")
    def missing() -> None:
        raise NotFoundError("repository", "repo-1")

    client = TestClient(app)
    response = client.get("/missing", headers={"X-Request-ID": "request-123"})

    assert response.status_code == 404
    assert response.headers["X-Request-ID"] == "request-123"
    assert response.json() == {
        "error_code": "repository_not_found",
        "message": "repository repo-1 was not found",
        "request_id": "request-123",
    }
