from typing import Annotated, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import RequireAnyRole, client_ip
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    AuditLogAction,
    UserRole,
)
from cairn.server.errors import DomainError, ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.reports import ReportFilters, ReportPage, ReportResponse
from cairn.server.services.artifacts import ArtifactService
from cairn.server.services.reports import ReportService


router = APIRouter(tags=["artifacts"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]

# §9.8 gives viewer read-only results and reports. Sensitive Artifacts are the
# raw material behind those results — runtime logs, PoC traffic, scanner
# output — and can carry credentials and payloads that a read-only account has
# no reason to hold.
_SENSITIVE_ARTIFACT_ROLES = frozenset(
    {UserRole.ADMIN, UserRole.AUDITOR, UserRole.REVIEWER}
)


class SensitiveArtifactForbiddenError(DomainError):
    def __init__(self) -> None:
        super().__init__(
            "artifact_access_forbidden",
            "this artifact is marked sensitive and your role cannot read it",
            403,
        )


@router.get("/artifacts/{artifact_id}", response_class=FileResponse)
def download_artifact(
    artifact_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAnyRole,
) -> FileResponse:
    """Download one Artifact, checking role and writing an audit row (§11.5).

    The refusal is committed before it is raised: the request transaction is
    rolled back when the error propagates, and a rolled-back audit row would
    lose exactly the attempt worth keeping.
    """

    service = ArtifactService(session, artifact_store)
    artifact = service.get(artifact_id)
    log = AuditLogService(session)
    sensitive = artifact.access_level == ArtifactAccessLevel.SENSITIVE.value
    if sensitive and principal.role not in _SENSITIVE_ARTIFACT_ROLES:
        log.record(
            AuditLogAction.ARTIFACT_DOWNLOADED,
            actor=principal,
            target_type="artifact",
            target_id=artifact.id,
            outcome="denied",
            http_status=403,
            request_id=ensure_request_id(request),
            client_ip=client_ip(request),
            detail={"kind": artifact.kind, "access_level": artifact.access_level},
        )
        session.commit()
        raise SensitiveArtifactForbiddenError()

    path = service.resolve_bytes(artifact)

    log.record(
        AuditLogAction.ARTIFACT_DOWNLOADED,
        actor=principal,
        target_type="artifact",
        target_id=artifact.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "kind": artifact.kind,
            "access_level": artifact.access_level,
            "sha256": artifact.sha256,
        },
    )
    session.commit()
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=f"{artifact.id}",
        headers={
            "ETag": f'"sha256:{artifact.sha256}"',
            "X-Content-SHA256": artifact.sha256,
            "X-Artifact-Kind": artifact.kind,
        },
    )


@router.get("/reports", response_model=ReportPage)
def list_reports(
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAnyRole,
    audit_run_id: UUID | None = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ReportPage:
    del principal
    filters = ReportFilters(
        audit_run_id=audit_run_id,
        limit=limit,
        offset=offset,
    )
    reports, total = ReportService(session, artifact_store).list(filters)
    return ReportPage(
        items=[ReportResponse.model_validate(report) for report in reports],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/reports/{report_id}", response_class=FileResponse)
def download_report(
    report_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAnyRole,
    report_format: Annotated[
        Literal["html", "json", "sarif"],
        Query(alias="format"),
    ] = "html",
) -> FileResponse:
    report, artifact, path = ReportService(session, artifact_store).resolve(
        report_id,
        report_format,
    )
    AuditLogService(session).record(
        AuditLogAction.REPORT_DOWNLOADED,
        actor=principal,
        target_type="report",
        target_id=report.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "audit_run_id": str(report.audit_run_id),
            "version": report.version,
            "format": report_format,
            "artifact_id": str(artifact.id),
        },
    )
    session.commit()
    suffix = {"html": "html", "json": "json", "sarif": "sarif.json"}[
        report_format
    ]
    return FileResponse(
        path,
        media_type=artifact.media_type,
        filename=f"cairn-report-{report.audit_run_id}-v{report.version}.{suffix}",
        headers={
            "ETag": f'"sha256:{artifact.sha256}"',
            "X-Content-SHA256": artifact.sha256,
        },
    )
