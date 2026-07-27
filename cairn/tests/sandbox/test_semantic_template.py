"""The closed semantic channel into the Sandbox.

Subproject three's core property is that a create request cannot choose an
image, a command, an environment variable, a mount, a capability, a device, a
port or a network. The semantic template needs a credential and an assignment
to reach the container, and these tests exist to show that need was met with
one typed block rather than by reopening any of those.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError
import pytest

from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxOperation,
    SandboxTemplateName,
    SemanticSandboxSpec,
    SemanticScopeSpec,
)
from cairn.sandbox.docker_backend import _CREDENTIAL_KEYS, _environment
from cairn.sandbox.manager import SEMANTIC_SCOPE_FILENAME, SandboxManager
from cairn.sandbox.templates import NetworkPolicy, TemplateRegistry

from .test_manager import FakeBackend

GRANT = "eyJhdWRpdCI6InJ1bi0xIn0.c2lnbmF0dXJlLWJ5dGVz"


def scope_spec(**overrides: object) -> SemanticScopeSpec:
    values: dict[str, object] = {
        "module": "core",
        "attack_surface": "HTTP endpoint",
        "category": "sql-injection",
        "scope_key": "semantic:core:http-endpoint:sql-injection",
        "entrypoint_paths": ["core/src/main/java/A.java"],
    }
    values.update(overrides)
    return SemanticScopeSpec(**values)


def semantic_spec(**overrides: object) -> SemanticSandboxSpec:
    values: dict[str, object] = {
        "grant_token": GRANT,
        "gateway_url": "http://cairn-llm-gateway:8002",
        "scope": scope_spec(),
    }
    values.update(overrides)
    return SemanticSandboxSpec(**values)


def test_the_semantic_template_requires_a_semantic_block(snapshot_artifact) -> None:
    with pytest.raises(ValidationError):
        SandboxCreateRequest(
            template=SandboxTemplateName.SEMANTIC,
            operation=SandboxOperation.SEMANTIC,
            snapshot=snapshot_artifact,
        )


@pytest.mark.parametrize(
    "template",
    [
        SandboxTemplateName.ANALYSIS,
        SandboxTemplateName.BUILD,
        SandboxTemplateName.VALIDATION,
    ],
)
def test_no_other_template_may_carry_a_grant(
    snapshot_artifact,
    template: SandboxTemplateName,
) -> None:
    """A model credential has no business reaching a build or scanner container."""

    with pytest.raises(ValidationError):
        SandboxCreateRequest(
            template=template,
            snapshot=snapshot_artifact,
            semantic=semantic_spec(),
        )


@pytest.mark.parametrize(
    "gateway_url",
    [
        "ftp://cairn-llm-gateway:8002",
        "http://user:pass@cairn-llm-gateway:8002",
        "http://cairn-llm-gateway:8002/v1/messages",
        "http://cairn-llm-gateway:8002?x=1",
        "http://",
        "",
    ],
)
def test_the_gateway_url_must_be_a_bare_service_origin(gateway_url: str) -> None:
    with pytest.raises(ValidationError):
        semantic_spec(gateway_url=gateway_url)


@pytest.mark.parametrize(
    "grant",
    ["", "no-separator", "a.b.c", "not base64!.mac", "." , "payload."],
)
def test_a_malformed_grant_is_refused_at_the_wire(grant: str) -> None:
    with pytest.raises(ValidationError):
        semantic_spec(grant_token=grant)


@pytest.mark.parametrize(
    "path",
    ["/etc/passwd", "../../etc/passwd", "a\\b"],
)
def test_entrypoint_hints_cannot_be_absolute_or_escape(path: str) -> None:
    with pytest.raises(ValidationError):
        scope_spec(entrypoint_paths=[path])


def test_the_scope_lands_in_scratch_as_canonical_json(
    sandbox_settings,
    snapshot_artifact,
) -> None:
    backend = FakeBackend()
    manager = SandboxManager(sandbox_settings, backend)

    record = manager.create(
        SandboxCreateRequest(
            template=SandboxTemplateName.SEMANTIC,
            operation=SandboxOperation.SEMANTIC,
            snapshot=snapshot_artifact,
            semantic=semantic_spec(),
        )
    )

    workspace = backend.workspaces[record.id]
    written = (workspace.scratch / SEMANTIC_SCOPE_FILENAME).read_text()

    assert json.loads(written) == scope_spec().model_dump(mode="json")
    # Canonical form, matching every other serialized contract in the codebase.
    assert written == json.dumps(
        json.loads(written), sort_keys=True, separators=(",", ":")
    )


def test_the_grant_reaches_the_backend_and_never_the_record(
    sandbox_settings,
    snapshot_artifact,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The record is persisted, served by the internal API and logged by the
    Orchestrator. A live credential must not be in it."""

    backend = FakeBackend()
    manager = SandboxManager(sandbox_settings, backend)

    with caplog.at_level(logging.DEBUG):
        record = manager.create(
            SandboxCreateRequest(
                template=SandboxTemplateName.SEMANTIC,
                operation=SandboxOperation.SEMANTIC,
                snapshot=snapshot_artifact,
                semantic=semantic_spec(),
            )
        )

    assert backend.credentials[record.id]["CAIRN_LLM_GRANT_TOKEN"] == GRANT
    assert "semantic" not in record.model_dump()
    assert GRANT not in record.model_dump_json()
    assert GRANT not in caplog.text
    assert all(GRANT not in str(item.__dict__) for item in caplog.records)


def test_the_scope_file_is_not_written_for_other_templates(
    sandbox_settings,
    snapshot_artifact,
) -> None:
    backend = FakeBackend()
    manager = SandboxManager(sandbox_settings, backend)

    record = manager.create(
        SandboxCreateRequest(
            template=SandboxTemplateName.ANALYSIS,
            operation=SandboxOperation.SEMGREP,
            snapshot=snapshot_artifact,
        )
    )

    workspace = backend.workspaces[record.id]

    assert not (workspace.scratch / SEMANTIC_SCOPE_FILENAME).exists()
    assert backend.credentials[record.id] == {}


class TestEnvironmentInjection:
    """The container environment is a closed set of names, not a mapping the
    caller can extend."""

    def test_only_the_sandbox_id_is_injected_by_default(self) -> None:
        sandbox_id = uuid4()

        assert _environment(sandbox_id, None) == {
            "CAIRN_SANDBOX_ID": str(sandbox_id)
        }

    def test_the_credential_keys_are_the_documented_two(self) -> None:
        assert _CREDENTIAL_KEYS == {
            "CAIRN_LLM_GRANT_TOKEN",
            "CAIRN_LLM_GATEWAY_URL",
        }

    def test_a_name_outside_the_closed_set_is_refused(self) -> None:
        from cairn.sandbox.backend import BackendFailure

        with pytest.raises(BackendFailure):
            _environment(uuid4(), {"LD_PRELOAD": "/tmp/evil.so"})

    def test_the_sandbox_id_cannot_be_overwritten_by_a_credential(self) -> None:
        from cairn.sandbox.backend import BackendFailure

        with pytest.raises(BackendFailure):
            _environment(uuid4(), {"CAIRN_SANDBOX_ID": "spoofed"})


class TestSemanticTemplate:
    def test_it_has_no_network_without_an_operator_supplied_one(
        self,
        sandbox_settings,
    ) -> None:
        """Fails closed: no route to the Gateway means the review fails and is
        reported, not that it runs unreviewed."""

        registry = TemplateRegistry.from_settings(sandbox_settings)
        template = registry.get(SandboxTemplateName.SEMANTIC)

        assert template.network_policy is NetworkPolicy.NONE
        assert template.network_name is None

    def test_an_operator_network_makes_it_fixed(self, sandbox_settings) -> None:
        settings = sandbox_settings.model_copy(
            update={"semantic_network": "cairn-analysis-net"}
        )
        registry = TemplateRegistry.from_settings(settings)
        template = registry.get(SandboxTemplateName.SEMANTIC)

        assert template.network_policy is NetworkPolicy.FIXED
        assert template.network_name == "cairn-analysis-net"

    def test_it_runs_unprivileged_like_every_other_template(
        self,
        sandbox_settings,
    ) -> None:
        registry = TemplateRegistry.from_settings(sandbox_settings)
        template = registry.get(SandboxTemplateName.SEMANTIC)

        assert template.user == "65532:65532"
        assert template.command == ("/opt/cairn/bin/run-semantic",)

    def test_it_accepts_only_its_own_operation(self, sandbox_settings) -> None:
        from cairn.sandbox.errors import SandboxError

        registry = TemplateRegistry.from_settings(sandbox_settings)

        with pytest.raises(SandboxError):
            registry.resolve(
                SandboxTemplateName.SEMANTIC,
                SandboxOperation.SEMGREP,
            )

    def test_no_other_template_accepts_the_semantic_operation(
        self,
        sandbox_settings,
    ) -> None:
        from cairn.sandbox.errors import SandboxError

        registry = TemplateRegistry.from_settings(sandbox_settings)

        with pytest.raises(SandboxError):
            registry.resolve(
                SandboxTemplateName.ANALYSIS,
                SandboxOperation.SEMANTIC,
            )
