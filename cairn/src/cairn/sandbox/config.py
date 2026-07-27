from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class SandboxSettings(BaseSettings):
    """Configuration owned by the independently deployed Sandbox Manager."""

    model_config = SettingsConfigDict(env_prefix="CAIRN_SANDBOX_", extra="ignore")

    docker_host: str = "unix:///run/cairn-rootless-docker.sock"
    require_rootless: bool = True
    auth_token_file: Path
    artifact_root: Path = Path("/var/lib/cairn/artifacts")
    state_root: Path = Path("/var/lib/cairn/sandbox-state")
    work_root: Path = Path("/var/lib/cairn/sandbox-work")
    reap_interval_seconds: float = Field(default=1.0, ge=0.1, le=60)
    created_ttl_seconds: int = Field(default=60, ge=5, le=3600)
    max_active_sandboxes: int = Field(default=4, ge=1, le=64)
    max_snapshot_files: int = Field(default=100_000, ge=1, le=1_000_000)
    max_snapshot_bytes: int = Field(
        default=2 * 1024 * 1024 * 1024,
        ge=1,
        le=16 * 1024 * 1024 * 1024,
    )
    max_output_files: int = Field(default=100_000, ge=1, le=1_000_000)

    analysis_image: str = "cairn-sandbox-analysis:local"
    build_image: str = "cairn-sandbox-build:local"
    validation_image: str = "cairn-sandbox-validation:local"
    helper_image: str = "cairn-sandbox-helper:local"
    semantic_image: str = "cairn-sandbox-semantic:local"
    build_network: str | None = None
    # The network on the sandbox daemon that routes to the LLM Gateway. The
    # Manager drives its own rootless daemon, so the Compose network
    # `cairn-analysis-net` is not visible to it — the operator has to create an
    # equivalent one here, exactly as for the build dependency proxy. Left
    # unset, the semantic template has no route to the Gateway and its tasks
    # fail with a coverage warning instead of silently reviewing nothing.
    semantic_network: str | None = None

    @field_validator("docker_host")
    @classmethod
    def validate_docker_host(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("docker_host must not be empty")
        if not value.startswith("unix:///"):
            raise ValueError("docker_host must be an absolute Unix socket")
        return value

    @field_validator(
        "analysis_image",
        "build_image",
        "validation_image",
        "helper_image",
        "semantic_image",
    )
    @classmethod
    def validate_image(cls, value: str) -> str:
        value = value.strip()
        if not value or any(character.isspace() for character in value):
            raise ValueError("sandbox image names must be non-empty single tokens")
        return value

    @field_validator("build_network", "semantic_network")
    @classmethod
    def validate_build_network(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        if not value:
            return None
        if value.lower() in {"host", "bridge", "default", "none"}:
            raise ValueError(
                "a sandbox network must be a dedicated restricted network"
            )
        if (
            len(value) > 128
            or not value[0].isalnum()
            or any(
                not (character.isascii() and (character.isalnum() or character in "_.-"))
                for character in value
            )
        ):
            raise ValueError("sandbox network has an invalid name")
        return value

    @model_validator(mode="after")
    def validate_roots(self) -> "SandboxSettings":
        if self.require_rootless and self.docker_host in {
            "unix:///var/run/docker.sock",
            "unix:///run/docker.sock",
        }:
            raise ValueError("the conventional host Docker socket is forbidden")
        roots = [
            self.artifact_root.resolve(),
            self.state_root.resolve(),
            self.work_root.resolve(),
        ]
        for root in roots:
            if root == Path(root.anchor):
                raise ValueError("sandbox roots must be dedicated subdirectories")
        if len(set(roots)) != len(roots):
            raise ValueError("sandbox roots must be distinct")
        for left in roots:
            for right in roots:
                if left != right and (left.is_relative_to(right) or right.is_relative_to(left)):
                    raise ValueError("sandbox roots must not overlap")
        return self


def read_auth_token(path: Path) -> bytes:
    try:
        token = path.read_bytes().strip()
    except OSError as exc:
        raise ValueError("sandbox auth token file is unavailable") from exc
    if not 32 <= len(token) <= 512:
        raise ValueError("sandbox auth token must contain 32 to 512 bytes")
    if any(byte < 33 or byte > 126 for byte in token):
        raise ValueError("sandbox auth token must contain printable ASCII bytes")
    return token


@lru_cache
def get_sandbox_settings() -> SandboxSettings:
    return SandboxSettings()
