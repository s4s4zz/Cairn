"""The blind channel that carries a candidate to its independent reviewer.

§7.8 says the independent worker does not read the reporting worker's
reasoning. That is a rule someone has to keep, unless the channel simply has
nowhere to put it — which is the design here, and what these tests assert.

Subproject three's property also has to survive: a create request still cannot
choose an image, a command, an environment variable, a mount, a capability, a
device, a port or a network.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxOperation,
    SandboxRecord,
    SandboxTemplateName,
    SemanticSandboxSpec,
    SemanticScopeSpec,
    SnapshotArtifact,
    VerifyCandidateSpec,
    VerifyLocationSpec,
)
from cairn.sandbox.manager import VERIFY_CANDIDATE_FILENAME
from cairn.sandbox.templates import NetworkPolicy, TemplateRegistry

SHA = "a" * 64
GRANT = f"{'A' * 40}.{'B' * 40}"
LOCATION = {
    "path": "web/src/main/java/dev/cairn/OrderController.java",
    "start_line": 10,
    "end_line": 12,
    "symbol": "OrderController.list",
    "role": "sink",
}
CANDIDATE = {
    "root_cause_key": "b" * 64,
    "module": "web",
    "category": "sql-injection",
    "cwe_ids": ["CWE-89"],
    "sink": "Statement.executeQuery",
    "locations": [LOCATION],
}


def snapshot() -> SnapshotArtifact:
    return SnapshotArtifact(
        storage_key=f"sha256/{SHA[:2]}/{SHA}",
        sha256=SHA,
        size_bytes=4096,
    )


def scope() -> SemanticScopeSpec:
    return SemanticScopeSpec(
        module="web",
        attack_surface="HTTP endpoint",
        category="sql-injection",
        scope_key="web:http-endpoint:sql-injection",
    )


def request(operation: SandboxOperation, **spec: object) -> SandboxCreateRequest:
    return SandboxCreateRequest(
        template=SandboxTemplateName.SEMANTIC,
        operation=operation,
        snapshot=snapshot(),
        task_id=uuid4(),
        semantic=SemanticSandboxSpec(
            grant_token=GRANT,
            gateway_url="http://cairn-llm-gateway:8002",
            **spec,
        ),
    )


# --- the blindness is a property of the channel ------------------------------


@pytest.mark.parametrize(
    "field",
    [
        "message",
        "controllability",
        "call_chain",
        "attack_preconditions",
        "impact",
        "existing_defenses",
        "recommended_verification",
        "severity",
        "confidence",
        "reasoning",
    ],
)
def test_the_reporting_workers_reasoning_has_no_field_to_travel_in(
    field: str,
) -> None:
    """A future caller cannot widen the assignment by filling one more field."""

    with pytest.raises(ValidationError):
        VerifyCandidateSpec.model_validate({**CANDIDATE, field: "anything at all"})


def test_the_assignment_carries_exactly_the_facts_7_8_permits() -> None:
    assert set(VerifyCandidateSpec.model_fields) == {
        "root_cause_key",
        "module",
        "category",
        "cwe_ids",
        "sink",
        "locations",
    }
    assert set(VerifyLocationSpec.model_fields) == {
        "path",
        "start_line",
        "end_line",
        "symbol",
        "role",
    }


def test_a_traversal_path_is_refused_in_an_assignment() -> None:
    with pytest.raises(ValidationError):
        VerifyCandidateSpec.model_validate(
            {**CANDIDATE, "locations": [{**LOCATION, "path": "web/../../etc/passwd"}]}
        )


# --- the assignment must match the operation ---------------------------------


def test_independent_verify_requires_a_candidate() -> None:
    with pytest.raises(ValidationError):
        request(SandboxOperation.INDEPENDENT_VERIFY, scope=scope())


def test_a_semantic_review_requires_a_scope() -> None:
    with pytest.raises(ValidationError):
        request(
            SandboxOperation.SEMANTIC,
            candidate=VerifyCandidateSpec.model_validate(CANDIDATE),
        )


@pytest.mark.parametrize(
    "spec",
    [
        pytest.param({}, id="neither"),
        pytest.param(
            {"scope": scope(), "candidate": VerifyCandidateSpec.model_validate(CANDIDATE)},
            id="both",
        ),
    ],
)
def test_exactly_one_assignment_is_carried(spec: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        SemanticSandboxSpec(
            grant_token=GRANT,
            gateway_url="http://cairn-llm-gateway:8002",
            **spec,
        )


@pytest.mark.parametrize(
    "template",
    [
        SandboxTemplateName.ANALYSIS,
        SandboxTemplateName.BUILD,
        SandboxTemplateName.VALIDATION,
    ],
)
def test_no_other_template_may_be_handed_a_model_credential(
    template: SandboxTemplateName,
) -> None:
    with pytest.raises(ValidationError):
        SandboxCreateRequest(
            template=template,
            operation=SandboxOperation.DEFAULT,
            snapshot=snapshot(),
            semantic=SemanticSandboxSpec(
                grant_token=GRANT,
                gateway_url="http://cairn-llm-gateway:8002",
                candidate=VerifyCandidateSpec.model_validate(CANDIDATE),
            ),
        )


# --- the grant is write-only --------------------------------------------------


def test_the_record_returned_to_the_caller_has_nowhere_to_echo_a_grant() -> None:
    """The record is persisted, served by the Sandbox API and logged by the
    Orchestrator, none of which should ever hold a live credential."""

    assert "semantic" not in SandboxRecord.model_fields
    assert not any(
        "grant" in name or "token" in name for name in SandboxRecord.model_fields
    )


def test_the_grant_does_not_survive_a_round_trip_through_the_request_dump() -> None:
    payload = request(
        SandboxOperation.INDEPENDENT_VERIFY,
        candidate=VerifyCandidateSpec.model_validate(CANDIDATE),
    )
    record = SandboxRecord(
        id=uuid4(),
        task_id=payload.task_id,
        template=payload.template,
        operation=payload.operation,
        snapshot=payload.snapshot,
        limits=TemplateRegistry.from_settings(_settings()).get(
            SandboxTemplateName.SEMANTIC
        ).defaults,
        status="created",
        created_at="2026-07-27T00:00:00Z",
        deadline_at="2026-07-27T00:30:00Z",
    )

    assert GRANT not in json.dumps(record.model_dump(mode="json"))


# --- the template still refuses everything subproject three refused ----------


def _settings():
    from cairn.sandbox.config import SandboxSettings

    return SandboxSettings(
        docker_host="unix:///run/cairn-rootless-docker.sock",
        state_root=Path("/var/lib/cairn/sandbox-state"),
        artifact_root=Path("/var/lib/cairn/artifacts"),
        auth_token_file=Path("/run/secrets/cairn-sandbox-token"),
    )


def test_independent_verify_runs_on_the_reviewer_template_unchanged() -> None:
    registry = TemplateRegistry.from_settings(_settings())

    template = registry.resolve(
        SandboxTemplateName.SEMANTIC,
        SandboxOperation.INDEPENDENT_VERIFY,
    )

    # Same image, same non-root user, same network policy as the semantic
    # review: §9.7 gives the two reviewers identical permissions.
    base = registry.get(SandboxTemplateName.SEMANTIC)
    assert template.image == base.image
    assert template.user == "65532:65532"
    assert template.network_policy is base.network_policy
    assert template.command == (*base.command, "independent-verify")


def test_the_caller_still_cannot_choose_an_image_command_mount_or_network() -> None:
    assert set(SandboxCreateRequest.model_fields) == {
        "template",
        "operation",
        "snapshot",
        "task_id",
        "limits",
        "semantic",
    }


def test_the_assignment_filename_is_the_one_the_runner_reads() -> None:
    from cairn.verify.runner import ASSIGNMENT_FILENAME

    assert VERIFY_CANDIDATE_FILENAME == ASSIGNMENT_FILENAME
