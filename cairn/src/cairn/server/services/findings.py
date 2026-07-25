from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from cairn.server.domain.enums import FindingStatus, RuntimeVerificationStatus
from cairn.server.errors import ConflictError, NotFoundError
from cairn.server.persistence.models import (
    AuditRun,
    Finding,
    FindingLocation,
)
from cairn.server.schemas.findings import CandidateFindingCommand, FindingFilters


class FindingService:
    def __init__(self, session: Session) -> None:
        self.session = session

    def create_candidate(self, command: CandidateFindingCommand) -> Finding:
        if self.session.get(AuditRun, command.audit_run_id) is None:
            raise NotFoundError("audit_run", command.audit_run_id)

        duplicate = self.session.scalar(
            select(Finding.id).where(
                Finding.audit_run_id == command.audit_run_id,
                Finding.fingerprint == command.fingerprint,
            )
        )
        if duplicate is not None:
            self._raise_duplicate(command)

        finding = Finding(
            audit_run_id=command.audit_run_id,
            fingerprint=command.fingerprint,
            title=command.title,
            description=command.description,
            category=command.category,
            cwe_id=command.cwe_id,
            owasp_category=command.owasp_category,
            severity=command.severity.value,
            confidence=command.confidence.value,
            status=FindingStatus.CANDIDATE.value,
            attack_preconditions=command.attack_preconditions,
            impact=command.impact,
            remediation=command.remediation,
            runtime_verification=RuntimeVerificationStatus.UNVERIFIED.value,
            discovered_by=command.discovered_by,
        )
        finding.locations = [
            FindingLocation(
                role=location.role.value,
                file_path=location.file_path,
                start_line=location.start_line,
                end_line=location.end_line,
                symbol=location.symbol,
                code_snippet=location.code_snippet,
                snapshot_sha=location.snapshot_sha,
                ordinal=location.ordinal,
            )
            for location in command.locations
        ]
        self.session.add(finding)
        try:
            self.session.commit()
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                "finding fingerprint already exists in this audit run",
                error_code="finding_fingerprint_conflict",
            ) from exc
        self.session.refresh(finding)
        return finding

    def get(self, finding_id: UUID) -> Finding:
        finding = self.session.scalar(
            select(Finding)
            .where(Finding.id == finding_id)
            .options(
                selectinload(Finding.locations),
                selectinload(Finding.evidence),
                selectinload(Finding.verifications),
            )
        )
        if finding is None:
            raise NotFoundError("finding", finding_id)
        return finding

    def list(self, filters: FindingFilters) -> tuple[list[Finding], int]:
        conditions = []
        if filters.audit_run_id is not None:
            conditions.append(Finding.audit_run_id == filters.audit_run_id)
        if filters.cwe_id is not None:
            conditions.append(Finding.cwe_id == filters.cwe_id)
        if filters.severity is not None:
            conditions.append(Finding.severity == filters.severity.value)
        if filters.status is not None:
            conditions.append(Finding.status == filters.status.value)

        count_statement = select(func.count()).select_from(Finding)
        statement = select(Finding)
        if conditions:
            count_statement = count_statement.where(*conditions)
            statement = statement.where(*conditions)
        total = self.session.scalar(count_statement) or 0
        findings = list(
            self.session.scalars(
                statement.order_by(Finding.first_seen_at.desc(), Finding.id)
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return findings, total

    @staticmethod
    def _raise_duplicate(command: CandidateFindingCommand) -> None:
        raise ConflictError(
            (
                f"finding fingerprint {command.fingerprint!r} already exists "
                f"in audit run {command.audit_run_id}"
            ),
            error_code="finding_fingerprint_conflict",
        )
