import asyncio
from datetime import timedelta
import hashlib
import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response, status
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from cairn.server.artifacts.dependencies import ArtifactStoreDependency
from cairn.server.auth.audit_log import AuditLogService
from cairn.server.auth.dependencies import (
    RequireAdmin,
    RequireAnyRole,
    RequireAuditor,
    client_ip,
)
from cairn.server.auth.sessions import SESSION_COOKIE_NAME, SessionService
from cairn.server.domain.enums import AuditLogAction, AuditRunStatus
from cairn.server.errors import ensure_request_id
from cairn.server.persistence.session import get_db_session
from cairn.server.schemas.audit_runs import (
    AuditCoverageResponse,
    AuditRunCreate,
    AuditRunFilters,
    AuditRunPage,
    AuditRunResponse,
    AuditTaskPage,
    AuditTaskResponse,
)
from cairn.server.schemas.common import PageMeta
from cairn.server.schemas.reports import ReportResponse
from cairn.server.services.audit_runs import AuditRunService
from cairn.server.services.reports import ReportService


router = APIRouter(prefix="/audit-runs", tags=["audit-runs"])
DatabaseSession = Annotated[Session, Depends(get_db_session)]


@router.post(
    "",
    response_model=AuditRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_audit_run(
    payload: AuditRunCreate,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> AuditRunResponse:
    audit_run = AuditRunService(session).create(payload, actor=principal.username)
    AuditLogService(session).record(
        AuditLogAction.AUDIT_RUN_CREATED,
        actor=principal,
        target_type="audit_run",
        target_id=audit_run.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "repository_id": str(audit_run.repository_id),
            "policy_id": str(audit_run.policy_id),
            "policy_version": audit_run.policy_version,
        },
    )
    session.commit()
    return AuditRunResponse.model_validate(audit_run)


@router.get("", response_model=AuditRunPage)
def list_audit_runs(
    session: DatabaseSession,
    principal: RequireAnyRole,
    repository_id: UUID | None = None,
    run_status: Annotated[AuditRunStatus | None, Query(alias="status")] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditRunPage:
    del principal
    filters = AuditRunFilters(
        repository_id=repository_id,
        status=run_status,
        limit=limit,
        offset=offset,
    )
    runs, total = AuditRunService(session).list(filters)
    return AuditRunPage(
        items=[AuditRunResponse.model_validate(item) for item in runs],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{run_id}", response_model=AuditRunResponse)
def get_audit_run(
    run_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> AuditRunResponse:
    del principal
    audit_run = AuditRunService(session).get(run_id)
    return AuditRunResponse.model_validate(audit_run)


@router.delete("/{run_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_audit_run(
    run_id: UUID,
    request: Request,
    session: DatabaseSession,
    principal: RequireAdmin,
) -> Response:
    audit_run = AuditRunService(session).delete(run_id)
    AuditLogService(session).record(
        AuditLogAction.AUDIT_RUN_DELETED,
        actor=principal,
        target_type="audit_run",
        target_id=run_id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "repository_id": str(audit_run.repository_id),
            "snapshot_id": (
                str(audit_run.snapshot_id)
                if audit_run.snapshot_id is not None
                else None
            ),
            "status": audit_run.status,
        },
    )
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{run_id}/tasks", response_model=AuditTaskPage)
def list_audit_tasks(
    run_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
    limit: Annotated[int, Query(ge=1, le=500)] = 100,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AuditTaskPage:
    del principal
    tasks, total = AuditRunService(session).list_tasks(
        run_id,
        limit=limit,
        offset=offset,
    )
    return AuditTaskPage(
        items=[AuditTaskResponse.model_validate(task) for task in tasks],
        meta=PageMeta(limit=limit, offset=offset, total=total),
    )


@router.get("/{run_id}/coverage", response_model=AuditCoverageResponse)
def get_audit_coverage(
    run_id: UUID,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> AuditCoverageResponse:
    del principal
    coverage = AuditRunService(session).get_coverage(run_id)
    return AuditCoverageResponse.model_validate(coverage)


@router.get("/{run_id}/events", response_class=StreamingResponse)
def stream_audit_run_events(
    run_id: UUID,
    request: Request,
    session: DatabaseSession,
    principal: RequireAnyRole,
) -> StreamingResponse:
    del principal
    service = AuditRunService(session)
    service.get(run_id)
    session.rollback()
    poll_sessions = sessionmaker(
        bind=session.get_bind(),
        class_=Session,
        autoflush=False,
        expire_on_commit=False,
    )
    session_token = request.cookies.get(SESSION_COOKIE_NAME, "")
    session_ttl = timedelta(minutes=request.app.state.settings.session_ttl_minutes)
    terminal = {
        AuditRunStatus.COMPLETED.value,
        AuditRunStatus.COMPLETED_WITH_WARNINGS.value,
        AuditRunStatus.CANCELLED.value,
        AuditRunStatus.FAILED.value,
    }

    def poll_snapshot() -> dict[str, object] | None:
        # A streaming dependency session would otherwise remain checked out for
        # the entire SSE connection and be moved from FastAPI's worker thread to
        # the event loop. A fresh short-lived Session also observes committed
        # worker updates without relying on identity-map expiration.
        with poll_sessions() as poll_session:
            resolved = SessionService(poll_session, ttl=session_ttl).resolve(
                session_token
            )
            if resolved is None:
                return None
            payload = AuditRunService(poll_session).event_snapshot(run_id)
            poll_session.rollback()
            return payload

    async def events():
        last_event_id = request.headers.get("last-event-id") or None
        idle_polls = 0
        while True:
            if await request.is_disconnected():
                break
            payload = await run_in_threadpool(poll_snapshot)
            if payload is None:
                break
            encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True)
            event_id = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
            if event_id != last_event_id:
                yield (
                    "retry: 3000\n"
                    f"id: {event_id}\n"
                    "event: audit-run\n"
                    f"data: {encoded}\n\n"
                )
                last_event_id = event_id
                idle_polls = 0
            else:
                idle_polls += 1
                if idle_polls >= 15:
                    yield ": heartbeat\n\n"
                    idle_polls = 0
            if payload["status"] in terminal:
                break
            await asyncio.sleep(1)

    return StreamingResponse(
        events(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-store",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@router.post("/{run_id}/cancel", response_model=AuditRunResponse)
def cancel_audit_run(
    run_id: UUID,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> AuditRunResponse:
    audit_run = AuditRunService(session).request_cancel(
        run_id,
        actor=principal.username,
    )
    AuditLogService(session).record(
        AuditLogAction.AUDIT_RUN_CANCELLED,
        actor=principal,
        target_type="audit_run",
        target_id=audit_run.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
    )
    session.commit()
    return AuditRunResponse.model_validate(audit_run)


@router.post(
    "/{run_id}/retry",
    response_model=AuditRunResponse,
    status_code=status.HTTP_201_CREATED,
)
def retry_audit_run(
    run_id: UUID,
    request: Request,
    session: DatabaseSession,
    principal: RequireAuditor,
) -> AuditRunResponse:
    """Re-run a failed or cancelled audit as a new AuditRun (§11.2).

    201 rather than 200: the body is a different run from the one named in the
    path, and a client that treated it as the same run would show the retry
    under the original's id.
    """

    audit_run = AuditRunService(session).retry(run_id, actor=principal.username)
    AuditLogService(session).record(
        AuditLogAction.AUDIT_RUN_RETRIED,
        actor=principal,
        target_type="audit_run",
        target_id=audit_run.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={"retry_of": str(run_id)},
    )
    session.commit()
    return AuditRunResponse.model_validate(audit_run)


@router.post(
    "/{run_id}/reports",
    response_model=ReportResponse,
    status_code=status.HTTP_201_CREATED,
)
def generate_report(
    run_id: UUID,
    request: Request,
    session: DatabaseSession,
    artifact_store: ArtifactStoreDependency,
    principal: RequireAuditor,
) -> ReportResponse:
    report = ReportService(session, artifact_store).generate(run_id)
    AuditLogService(session).record(
        AuditLogAction.REPORT_GENERATED,
        actor=principal,
        target_type="report",
        target_id=report.id,
        request_id=ensure_request_id(request),
        client_ip=client_ip(request),
        detail={
            "audit_run_id": str(run_id),
            "version": report.version,
            "formats": ["html", "json", "sarif"],
        },
    )
    session.commit()
    return ReportResponse.model_validate(report)
