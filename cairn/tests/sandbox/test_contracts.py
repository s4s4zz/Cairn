from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError
import pytest

from cairn.sandbox.config import SandboxSettings, read_auth_token
from cairn.sandbox.contracts import (
    SandboxCreateRequest,
    SandboxLimitsOverride,
    SandboxOperation,
    SandboxTemplateName,
    SnapshotArtifact,
)
from cairn.sandbox.errors import SandboxError
from cairn.sandbox.templates import NetworkPolicy, TemplateRegistry


def valid_snapshot() -> dict[str, object]:
    digest = "a" * 64
    return {
        "storage_key": f"sha256/{digest[:2]}/{digest}",
        "sha256": digest,
        "size_bytes": 1024,
    }


@pytest.mark.parametrize(
    "extra",
    [
        {"image": "attacker/image"},
        {"command": ["/bin/sh"]},
        {"mounts": ["/:/host"]},
        {"privileged": True},
        {"network_mode": "host"},
        {"environment": {"TOKEN": "secret"}},
    ],
)
def test_create_contract_rejects_backend_control_fields(
    extra: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        SandboxCreateRequest.model_validate(
            {
                "template": "analysis",
                "snapshot": valid_snapshot(),
                **extra,
            }
        )


def test_snapshot_contract_requires_matching_content_address_shape() -> None:
    with pytest.raises(ValidationError):
        SnapshotArtifact(
            storage_key="sha256/aa/" + "b" * 64,
            sha256="b" * 64,
            size_bytes=1,
        )


def test_template_registry_owns_image_command_and_network(
    sandbox_settings: SandboxSettings,
) -> None:
    registry = TemplateRegistry.from_settings(sandbox_settings)

    analysis = registry.get(SandboxTemplateName.ANALYSIS)
    validation = registry.get(SandboxTemplateName.VALIDATION)

    assert analysis.image == sandbox_settings.analysis_image
    assert analysis.command == ("/opt/cairn/bin/run-analysis",)
    assert analysis.network_policy is NetworkPolicy.NONE
    assert validation.network_policy is NetworkPolicy.ISOLATED


def test_template_registry_expands_only_fixed_operation_commands(
    sandbox_settings: SandboxSettings,
) -> None:
    registry = TemplateRegistry.from_settings(sandbox_settings)

    inventory = registry.resolve(
        SandboxTemplateName.ANALYSIS,
        SandboxOperation.INVENTORY,
    )

    assert inventory.command == (
        "/opt/cairn/bin/run-analysis",
        "inventory",
    )
    with pytest.raises(SandboxError) as captured:
        registry.resolve(
            SandboxTemplateName.ANALYSIS,
            SandboxOperation.BUILD,
        )
    assert captured.value.error_code == "SANDBOX_OPERATION_INVALID"


def test_template_rejects_limit_above_ceiling(
    sandbox_settings: SandboxSettings,
) -> None:
    template = TemplateRegistry.from_settings(sandbox_settings).get(
        SandboxTemplateName.BUILD
    )

    with pytest.raises(SandboxError) as captured:
        template.resolve_limits(SandboxLimitsOverride(cpu_millis=5000))

    assert captured.value.error_code == "SANDBOX_LIMIT_EXCEEDED"


def test_build_network_is_admin_owned(
    sandbox_settings: SandboxSettings,
) -> None:
    configured = sandbox_settings.model_copy(
        update={"build_network": "cairn-restricted-build"}
    )
    template = TemplateRegistry.from_settings(configured).get(
        SandboxTemplateName.BUILD
    )

    assert template.network_policy is NetworkPolicy.FIXED
    assert template.network_name == "cairn-restricted-build"


def test_settings_reject_overlapping_roots(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 32)

    with pytest.raises(ValidationError):
        SandboxSettings(
            auth_token_file=token_file,
            artifact_root=tmp_path / "data",
            state_root=tmp_path / "data" / "state",
            work_root=tmp_path / "work",
        )


@pytest.mark.parametrize(
    "docker_host",
    [
        "tcp://127.0.0.1:2375",
        "http://docker.example:2375",
        "unix:///var/run/docker.sock",
    ],
)
def test_settings_reject_insecure_or_conventional_daemon_endpoints(
    tmp_path: Path,
    docker_host: str,
) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("x" * 32)

    with pytest.raises(ValidationError):
        SandboxSettings(
            docker_host=docker_host,
            auth_token_file=token_file,
            artifact_root=tmp_path / "artifacts",
            state_root=tmp_path / "state",
            work_root=tmp_path / "work",
        )


def test_auth_token_is_file_backed_and_length_checked(tmp_path: Path) -> None:
    token_file = tmp_path / "token"
    token_file.write_text("s" * 40 + "\n")

    assert read_auth_token(token_file) == b"s" * 40

    token_file.write_text("short")
    with pytest.raises(ValueError):
        read_auth_token(token_file)


def test_task_id_is_the_only_optional_caller_correlation() -> None:
    request = SandboxCreateRequest.model_validate(
        {
            "template": "analysis",
            "snapshot": valid_snapshot(),
            "task_id": str(uuid4()),
        }
    )

    assert request.task_id is not None
    assert request.operation is SandboxOperation.DEFAULT


def test_create_contract_accepts_only_known_operation_enum() -> None:
    request = SandboxCreateRequest.model_validate(
        {
            "template": "analysis",
            "operation": "semgrep",
            "snapshot": valid_snapshot(),
        }
    )
    assert request.operation is SandboxOperation.SEMGREP

    with pytest.raises(ValidationError):
        SandboxCreateRequest.model_validate(
            {
                "template": "analysis",
                "operation": "attacker-command",
                "snapshot": valid_snapshot(),
            }
        )
