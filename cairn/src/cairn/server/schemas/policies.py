from datetime import datetime
from uuid import UUID

from pydantic import Field, field_validator

from cairn.server.domain.enums import DynamicVerificationMode
from cairn.server.schemas.common import Page, StrictModel


SUPPORTED_SCANNERS = frozenset(
    {
        "codeql",
        "config-rules",
        "dependency-check",
        "findsecbugs",
        "gitleaks",
        "semgrep",
        "trivy",
    }
)


def default_scanners() -> list[str]:
    return sorted(SUPPORTED_SCANNERS)


class AuditPolicyCreate(StrictModel):
    name: str = Field(min_length=1, max_length=255)
    include_paths: list[str] = Field(default_factory=lambda: ["**"])
    exclude_paths: list[str] = Field(default_factory=list)
    enabled_scanners: list[str] = Field(default_factory=default_scanners, min_length=1)
    dynamic_verification: DynamicVerificationMode = DynamicVerificationMode.REQUIRED
    severity_thresholds: dict[str, object] = Field(default_factory=dict)
    resource_budget: dict[str, object] = Field(default_factory=dict)
    active: bool = True

    @field_validator("include_paths", "exclude_paths")
    @classmethod
    def validate_paths(cls, values: list[str]) -> list[str]:
        if any(not value.strip() for value in values):
            raise ValueError("paths must not contain empty values")
        if len(values) != len(set(values)):
            raise ValueError("paths must not contain duplicates")
        return values

    @field_validator("enabled_scanners")
    @classmethod
    def validate_scanners(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("enabled_scanners must not contain duplicates")
        unknown = set(values) - SUPPORTED_SCANNERS
        if unknown:
            raise ValueError(f"unsupported scanners: {', '.join(sorted(unknown))}")
        return values


class AuditPolicyResponse(StrictModel):
    id: UUID
    name: str
    version: int
    include_paths: list[str]
    exclude_paths: list[str]
    enabled_scanners: list[str]
    dynamic_verification: DynamicVerificationMode
    severity_thresholds: dict[str, object]
    resource_budget: dict[str, object]
    active: bool
    created_at: datetime


class AuditPolicyFilters(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    active: bool | None = None
    limit: int = Field(default=50, ge=1, le=100)
    offset: int = Field(default=0, ge=0)


AuditPolicyPage = Page[AuditPolicyResponse]
