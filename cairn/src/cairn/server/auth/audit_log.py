"""The operator audit log (§9.8).

Every privileged action lands here through a single writer, so "which
operations are audited" is answerable by reading the ``AuditLogAction`` enum
rather than by grepping the routers.

What must never appear in ``detail``: passwords, session or CSRF tokens, Git
credentials, decrypted secrets, or the body of a sensitive Artifact. Call sites
pass identifiers and decisions — what was done to what — not payloads.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from cairn.server.domain.enums import AuditLogAction, UserRole
from cairn.server.persistence.models.identity import AuditLogEntry


MAX_DETAIL_KEYS = 24
MAX_DETAIL_VALUE_CHARS = 512


@dataclass(frozen=True, slots=True)
class Principal:
    """The authenticated caller, decoupled from the ORM row.

    Services take this rather than a ``User``: it cannot be mutated by a
    service, it survives the request session closing, and it makes the actor of
    an action explicit at every call site that used to hardcode ``"system"``.

    ``role`` is optional for exactly one case — a failed login, where the
    username was supplied but never authenticated. Recording that attempt under
    some placeholder role would put a fact in the audit log that was never
    true.
    """

    id: UUID | None
    username: str
    role: UserRole | None

    @property
    def is_admin(self) -> bool:
        return self.role is UserRole.ADMIN


SYSTEM_PRINCIPAL = Principal(id=None, username="system", role=UserRole.ADMIN)


def _clamp_detail(detail: dict[str, object] | None) -> dict[str, object]:
    if not detail:
        return {}
    clamped: dict[str, object] = {}
    for key, value in list(detail.items())[:MAX_DETAIL_KEYS]:
        if isinstance(value, str) and len(value) > MAX_DETAIL_VALUE_CHARS:
            value = value[:MAX_DETAIL_VALUE_CHARS]
        clamped[str(key)[:64]] = value
    return clamped


class AuditLogService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def record(
        self,
        action: AuditLogAction,
        *,
        actor: Principal,
        target_type: str | None = None,
        target_id: object | None = None,
        outcome: str = "success",
        http_status: int | None = None,
        request_id: str | None = None,
        client_ip: str | None = None,
        detail: dict[str, object] | None = None,
    ) -> AuditLogEntry:
        entry = AuditLogEntry(
            actor_id=actor.id,
            actor_username=actor.username[:64],
            actor_role=actor.role.value if actor.role is not None else None,
            action=action.value,
            target_type=target_type,
            target_id=None if target_id is None else str(target_id)[:128],
            outcome=outcome[:16],
            http_status=http_status,
            request_id=request_id[:128] if request_id else None,
            client_ip=client_ip[:45] if client_ip else None,
            detail=_clamp_detail(detail),
        )
        self.session.add(entry)
        return entry

    def list(
        self,
        *,
        action: AuditLogAction | None = None,
        actor_username: str | None = None,
        target_type: str | None = None,
        target_id: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[AuditLogEntry], int]:
        conditions = []
        if action is not None:
            conditions.append(AuditLogEntry.action == action.value)
        if actor_username:
            conditions.append(AuditLogEntry.actor_username == actor_username)
        if target_type:
            conditions.append(AuditLogEntry.target_type == target_type)
        if target_id:
            conditions.append(AuditLogEntry.target_id == target_id)
        total = self.session.scalar(
            select(func.count()).select_from(AuditLogEntry).where(*conditions)
        )
        entries = list(
            self.session.scalars(
                select(AuditLogEntry)
                .where(*conditions)
                .order_by(AuditLogEntry.created_at.desc(), AuditLogEntry.id.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        return entries, int(total or 0)
