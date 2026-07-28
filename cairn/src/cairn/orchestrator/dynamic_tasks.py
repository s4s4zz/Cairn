"""Planning and budgeting for the dynamic verification stage (§7.7).

Standing an application up is the expensive part, so one Sandbox serves a whole
run and the budget bounds how many findings are probed inside it rather than
how many environments are built.

The probe plan is derived from the deterministic index: a Finding is probeable
only where the index recorded an entrypoint the probe can address. Everything
else is reported as inconclusive with a reason, never quietly skipped.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.dynamic.probes import PROBEABLE_CATEGORIES
from cairn.sandbox.contracts import DynamicTargetSpec
from cairn.server.domain.enums import AuditTaskStatus, AuditTaskType
from cairn.server.persistence.models import AuditRun, AuditTask, Finding
from cairn.orchestrator.errors import OrchestratorError

DEFAULT_MAX_FINDINGS = 32
DEFAULT_ENVIRONMENT_TIMEOUT = 900
DEFAULT_PROBE_TIMEOUT = 30

DYNAMIC_TIMEOUT_SECONDS = 1_800
DYNAMIC_MAX_ATTEMPTS = 2

TRUNCATION_REASON = "DYNAMIC_BUDGET_EXHAUSTED"

# Annotation names the index records, mapped to the HTTP method they imply.
_METHOD_BY_ANNOTATION = {
    "GetMapping": "GET",
    "PostMapping": "POST",
    "PutMapping": "PUT",
    "PatchMapping": "PATCH",
    "DeleteMapping": "DELETE",
    "RequestMapping": "GET",
}


@dataclass(frozen=True, slots=True)
class DynamicBudget:
    """Per-run ceilings, read from ``AuditPolicy.dynamic_budget``."""

    max_findings: int = DEFAULT_MAX_FINDINGS
    environment_timeout_seconds: int = DEFAULT_ENVIRONMENT_TIMEOUT
    per_probe_timeout_seconds: int = DEFAULT_PROBE_TIMEOUT

    @classmethod
    def from_policy(cls, payload: object) -> "DynamicBudget":
        if not isinstance(payload, dict):
            return cls()
        return cls(
            max_findings=_positive(
                payload.get("max_findings"), DEFAULT_MAX_FINDINGS
            ),
            environment_timeout_seconds=_positive(
                payload.get("environment_timeout_seconds"),
                DEFAULT_ENVIRONMENT_TIMEOUT,
            ),
            per_probe_timeout_seconds=_positive(
                payload.get("per_probe_timeout_seconds"), DEFAULT_PROBE_TIMEOUT
            ),
        )


def _positive(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return value


@dataclass(frozen=True, slots=True)
class ProbePlan:
    targets: tuple[DynamicTargetSpec, ...]
    dropped: int

    @property
    def truncated(self) -> bool:
        return self.dropped > 0


def plan_probe_targets(
    findings: list[Finding],
    entrypoints: list[dict[str, object]],
    *,
    budget: DynamicBudget,
) -> ProbePlan:
    """Derive one probe target per probeable Finding.

    A Finding is probeable when its category has a deterministic probe and the
    index recorded an entrypoint in one of its locations. Findings that fail
    either test are simply absent from the plan; the caller records them as
    inconclusive with the reason, so a gap is never silence.

    Ordered by fingerprint so a truncated plan drops the same tail every time.
    """

    by_path: dict[str, list[dict[str, object]]] = {}
    for record in entrypoints:
        if not isinstance(record, dict):
            continue
        path = str(record.get("path") or "")
        if path:
            by_path.setdefault(path, []).append(record)

    candidates: list[DynamicTargetSpec] = []
    for finding in sorted(findings, key=lambda item: item.fingerprint):
        if finding.category not in PROBEABLE_CATEGORIES:
            continue
        record = _entrypoint_for(finding, by_path)
        if record is None:
            continue
        annotations = record.get("annotations")
        annotation = (
            str(annotations[0])
            if isinstance(annotations, list) and annotations
            else "RequestMapping"
        )
        candidates.append(
            DynamicTargetSpec(
                finding_id=finding.id,
                category=finding.category,
                http_method=_METHOD_BY_ANNOTATION.get(annotation, "GET"),
                route=str(record["route"]) if record.get("route") else None,
                # The index does not resolve class-level @RequestMapping
                # prefixes, so every route recorded in the same file is offered
                # as a possible prefix and the probe tries them in order.
                route_prefixes=_prefixes_for(record, by_path),
            )
        )

    kept = candidates[: budget.max_findings]
    return ProbePlan(tuple(kept), len(candidates) - len(kept))


def _entrypoint_for(
    finding: Finding,
    by_path: dict[str, list[dict[str, object]]],
) -> dict[str, object] | None:
    """The indexed entrypoint a probe should address for this Finding."""

    ordered = sorted(
        finding.locations,
        # An entrypoint location is the request the attacker actually sends;
        # anything else is a step further along the chain.
        key=lambda location: (location.role != "entrypoint", location.ordinal),
    )
    for location in ordered:
        for record in by_path.get(location.file_path, []):
            if record.get("route"):
                return record
    return None


def _prefixes_for(
    record: dict[str, object],
    by_path: dict[str, list[dict[str, object]]],
) -> list[str]:
    path = str(record.get("path") or "")
    prefixes: list[str] = []
    for sibling in by_path.get(path, []):
        route = sibling.get("route")
        if not route or sibling is record:
            continue
        rendered = str(route)
        if rendered not in prefixes:
            prefixes.append(rendered)
    return prefixes[:8]


def get_or_create_dynamic_task(
    session: Session,
    audit_run: AuditRun,
    *,
    timeout_seconds: int = DYNAMIC_TIMEOUT_SECONDS,
    max_attempts: int = DYNAMIC_MAX_ATTEMPTS,
) -> AuditTask:
    """One verification task per run, made idempotent by its scope key."""

    scope_key = "dynamic:verification"
    task = session.scalar(
        select(AuditTask).where(
            AuditTask.audit_run_id == audit_run.id,
            AuditTask.scope_key == scope_key,
        )
    )
    if task is not None:
        return task
    if audit_run.snapshot is None:
        raise OrchestratorError(
            "ORCHESTRATOR_SNAPSHOT_REQUIRED",
            "A ready Snapshot is required to create a verification task",
        )
    task = AuditTask(
        audit_run_id=audit_run.id,
        type=AuditTaskType.DYNAMIC_VERIFY.value,
        scope_key=scope_key,
        scope={},
        required_capabilities=["dynamic:http"],
        status=AuditTaskStatus.QUEUED.value,
        worker_name=None,
        attempt=0,
        max_attempts=max_attempts,
        timeout_seconds=timeout_seconds,
        input_artifact_ids=[str(audit_run.snapshot.artifact_id)],
        output_artifact_ids=[],
    )
    session.add(task)
    session.flush()
    return task
