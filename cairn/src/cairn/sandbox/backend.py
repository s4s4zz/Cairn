from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Protocol
from uuid import UUID

from cairn.sandbox.contracts import SandboxLimits
from cairn.sandbox.templates import SandboxTemplate


class BackendContainerStatus(StrEnum):
    CREATED = "created"
    RUNNING = "running"
    EXITED = "exited"
    MISSING = "missing"


@dataclass(frozen=True, slots=True)
class BackendState:
    status: BackendContainerStatus
    exit_code: int | None = None
    oom_killed: bool = False


@dataclass(frozen=True, slots=True)
class SandboxWorkspace:
    root: Path
    source: Path
    scratch: Path
    output: Path


class BackendFailure(RuntimeError):
    """A redacted execution-backend failure safe for Manager control flow."""


class SandboxContainerBackend(Protocol):
    def validate_ready(self) -> None: ...

    def create(
        self,
        sandbox_id: UUID,
        template: SandboxTemplate,
        limits: SandboxLimits,
        workspace: SandboxWorkspace,
    ) -> None: ...

    def start(self, sandbox_id: UUID) -> None: ...

    def inspect(self, sandbox_id: UUID) -> BackendState: ...

    def cancel(self, sandbox_id: UUID) -> None: ...

    def destroy(self, sandbox_id: UUID) -> None: ...

    def prepare_collection(
        self,
        sandbox_id: UUID,
        workspace: SandboxWorkspace,
    ) -> None: ...

    def managed_sandbox_ids(self) -> set[UUID]: ...

    def close(self) -> None: ...
