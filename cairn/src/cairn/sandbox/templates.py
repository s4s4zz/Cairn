from __future__ import annotations

from dataclasses import dataclass, replace
from enum import StrEnum

from cairn.sandbox.config import SandboxSettings
from cairn.sandbox.contracts import (
    SandboxLimits,
    SandboxLimitsOverride,
    SandboxOperation,
    SandboxTemplateName,
)
from cairn.sandbox.errors import SandboxError


class NetworkPolicy(StrEnum):
    NONE = "none"
    FIXED = "fixed"
    ISOLATED = "isolated"


@dataclass(frozen=True, slots=True)
class SandboxTemplate:
    name: SandboxTemplateName
    image: str
    command: tuple[str, ...]
    user: str
    network_policy: NetworkPolicy
    network_name: str | None
    allowed_operations: frozenset[SandboxOperation]
    defaults: SandboxLimits
    ceilings: SandboxLimits

    def resolve_limits(self, override: SandboxLimitsOverride) -> SandboxLimits:
        values = self.defaults.model_dump()
        values.update(override.model_dump(exclude_none=True))
        limits = SandboxLimits.model_validate(values)
        for field_name, requested in limits.model_dump().items():
            ceiling = getattr(self.ceilings, field_name)
            if requested > ceiling:
                raise SandboxError(
                    "SANDBOX_LIMIT_EXCEEDED",
                    f"Requested {field_name} exceeds the template ceiling",
                )
        if limits.output_bytes > limits.disk_bytes:
            raise SandboxError(
                "SANDBOX_LIMIT_EXCEEDED",
                "Requested output_bytes exceeds disk_bytes",
            )
        if limits.tmpfs_bytes > limits.memory_bytes:
            raise SandboxError(
                "SANDBOX_LIMIT_EXCEEDED",
                "Requested tmpfs_bytes exceeds memory_bytes",
            )
        return limits


class TemplateRegistry:
    def __init__(self, templates: tuple[SandboxTemplate, ...]) -> None:
        self._templates = {template.name: template for template in templates}
        if set(self._templates) != set(SandboxTemplateName):
            raise ValueError("all built-in Sandbox templates must be registered")

    def get(self, name: SandboxTemplateName) -> SandboxTemplate:
        try:
            return self._templates[name]
        except KeyError as exc:
            raise SandboxError(
                "SANDBOX_TEMPLATE_UNKNOWN",
                "Sandbox template is not registered",
            ) from exc

    def resolve(
        self,
        name: SandboxTemplateName,
        operation: SandboxOperation,
    ) -> SandboxTemplate:
        template = self.get(name)
        if operation not in template.allowed_operations:
            raise SandboxError(
                "SANDBOX_OPERATION_INVALID",
                "Sandbox operation is not allowed for the selected template",
            )
        if operation is SandboxOperation.DEFAULT:
            return template
        return replace(
            template,
            command=(*template.command, operation.value),
        )

    @classmethod
    def from_settings(cls, settings: SandboxSettings) -> "TemplateRegistry":
        defaults = SandboxLimits(
            cpu_millis=1000,
            memory_bytes=512 * 1024 * 1024,
            pids=128,
            disk_bytes=1024 * 1024 * 1024,
            output_bytes=256 * 1024 * 1024,
            tmpfs_bytes=64 * 1024 * 1024,
            timeout_seconds=900,
        )
        ceilings = SandboxLimits(
            cpu_millis=4000,
            memory_bytes=4 * 1024 * 1024 * 1024,
            pids=512,
            disk_bytes=10 * 1024 * 1024 * 1024,
            output_bytes=2 * 1024 * 1024 * 1024,
            tmpfs_bytes=256 * 1024 * 1024,
            timeout_seconds=3600,
        )
        build_policy = (
            NetworkPolicy.FIXED
            if settings.build_network is not None
            else NetworkPolicy.NONE
        )
        return cls(
            (
                SandboxTemplate(
                    name=SandboxTemplateName.ANALYSIS,
                    image=settings.analysis_image,
                    command=("/opt/cairn/bin/run-analysis",),
                    user="65532:65532",
                    network_policy=NetworkPolicy.NONE,
                    network_name=None,
                    allowed_operations=frozenset(
                        {
                            SandboxOperation.DEFAULT,
                            SandboxOperation.INVENTORY,
                            SandboxOperation.SEMGREP,
                            SandboxOperation.DEPENDENCY_CHECK,
                            SandboxOperation.TRIVY,
                            SandboxOperation.GITLEAKS,
                            SandboxOperation.CONFIG_RULES,
                        }
                    ),
                    defaults=defaults,
                    ceilings=ceilings,
                ),
                SandboxTemplate(
                    name=SandboxTemplateName.BUILD,
                    image=settings.build_image,
                    command=("/opt/cairn/bin/run-build",),
                    user="65532:65532",
                    network_policy=build_policy,
                    network_name=settings.build_network,
                    allowed_operations=frozenset(
                        {
                            SandboxOperation.DEFAULT,
                            SandboxOperation.BUILD,
                            SandboxOperation.CODEQL,
                            SandboxOperation.FINDSECBUGS,
                        }
                    ),
                    defaults=defaults,
                    ceilings=ceilings,
                ),
                SandboxTemplate(
                    name=SandboxTemplateName.VALIDATION,
                    image=settings.validation_image,
                    command=("/opt/cairn/bin/run-validation",),
                    user="65532:65532",
                    network_policy=NetworkPolicy.ISOLATED,
                    network_name=None,
                    allowed_operations=frozenset(
                        {SandboxOperation.DEFAULT}
                    ),
                    defaults=defaults,
                    ceilings=ceilings,
                ),
            )
        )
