from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from cairn.server.errors import ConflictError, NotFoundError
from cairn.server.persistence.models import AuditRun, Repository
from cairn.server.schemas.repositories import RepositoryCreate, RepositoryFilters


class RepositoryService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create(self, request: RepositoryCreate, actor: str) -> Repository:
        duplicate = self.session.scalar(
            select(Repository.id).where(
                func.lower(Repository.name) == request.name.casefold()
            )
        )
        if duplicate is not None:
            raise ConflictError(
                f"repository name {request.name!r} already exists",
                error_code="repository_name_conflict",
            )

        repository = Repository(
            name=request.name,
            source_type=request.source_type.value,
            remote_url=request.remote_url,
            credential_ref=request.credential_ref,
            default_branch=request.default_branch,
            created_by=actor,
        )
        self.session.add(repository)
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                f"repository name {request.name!r} already exists",
                error_code="repository_name_conflict",
            ) from exc
        self.session.refresh(repository)
        return repository

    def get(self, repository_id: UUID) -> Repository:
        repository = self.session.get(Repository, repository_id)
        if repository is None:
            raise NotFoundError("repository", repository_id)
        return repository

    def list(self, filters: RepositoryFilters) -> tuple[list[Repository], int]:
        conditions = []
        if filters.source_type is not None:
            conditions.append(Repository.source_type == filters.source_type.value)

        count_statement = select(func.count()).select_from(Repository)
        statement = select(Repository)
        if conditions:
            count_statement = count_statement.where(*conditions)
            statement = statement.where(*conditions)
        total = self.session.scalar(count_statement) or 0
        repositories = list(
            self.session.scalars(
                statement.order_by(Repository.created_at.desc(), Repository.name)
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return repositories, total

    def delete(self, repository_id: UUID) -> None:
        repository = self.get(repository_id)
        has_runs = self.session.scalar(
            select(AuditRun.id).where(AuditRun.repository_id == repository_id).limit(1)
        )
        if has_runs is not None:
            raise ConflictError(
                "repository cannot be deleted while audit runs reference it",
                error_code="repository_has_audit_runs",
            )

        self.session.delete(repository)
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "repository is still referenced by audit data",
                error_code="repository_in_use",
            ) from exc
