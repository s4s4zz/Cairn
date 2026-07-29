from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.errors import ConflictError, NotFoundError
from cairn.server.persistence.models import AuditPolicy
from cairn.server.schemas.policies import AuditPolicyCreate, AuditPolicyFilters


class AuditPolicyService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_version(self, request: AuditPolicyCreate) -> AuditPolicy:
        existing = list(
            self.session.scalars(
                select(AuditPolicy)
                .where(AuditPolicy.name == request.name)
                .order_by(AuditPolicy.version.desc())
                .with_for_update()
            )
        )
        version = existing[0].version + 1 if existing else 1

        if request.active:
            for policy in existing:
                if policy.active:
                    policy.active = False
            self.session.flush()

        policy = AuditPolicy(
            name=request.name,
            version=version,
            include_paths=request.include_paths,
            exclude_paths=request.exclude_paths,
            enabled_scanners=request.enabled_scanners,
            dynamic_verification=request.dynamic_verification.value,
            severity_thresholds=request.severity_thresholds,
            resource_budget=request.resource_budget,
            active=request.active,
        )
        self.session.add(policy)
        try:
            self.session.flush()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                f"concurrent policy version creation for {request.name!r}",
                error_code="policy_version_conflict",
            ) from exc
        return policy

    def get(self, policy_id: UUID) -> AuditPolicy:
        policy = self.session.get(AuditPolicy, policy_id)
        if policy is None:
            raise NotFoundError("audit_policy", policy_id)
        return policy

    def list(self, filters: AuditPolicyFilters) -> tuple[list[AuditPolicy], int]:
        conditions = []
        if filters.name is not None:
            conditions.append(AuditPolicy.name == filters.name)
        if filters.active is not None:
            conditions.append(AuditPolicy.active.is_(filters.active))

        count_statement = select(func.count()).select_from(AuditPolicy)
        statement = select(AuditPolicy)
        if conditions:
            count_statement = count_statement.where(*conditions)
            statement = statement.where(*conditions)
        total = self.session.scalar(count_statement) or 0
        policies = list(
            self.session.scalars(
                statement.order_by(AuditPolicy.name, AuditPolicy.version.desc())
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return policies, total
