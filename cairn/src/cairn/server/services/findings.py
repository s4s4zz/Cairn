from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from cairn.server.domain.enums import (
    EvidenceType,
    FindingSeverity,
    FindingStatus,
    RuntimeVerificationStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.domain.state_machines import InvalidTransition, transition_finding
from cairn.server.errors import ConflictError, InvalidStateError, NotFoundError
from cairn.server.persistence.models import (
    AuditRun,
    Evidence,
    Finding,
    FindingLocation,
    Verification,
)
from cairn.server.schemas.findings import CandidateFindingCommand, FindingFilters

# §7.8 requires these into independent review, and §13.6 makes that a gate on
# the human queue.
_REVIEW_REQUIRED_SEVERITIES = frozenset(
    {FindingSeverity.CRITICAL, FindingSeverity.HIGH}
)


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

    def promote(self, command: CandidateFindingCommand) -> Finding:
        """Create the candidate Finding, or return the one already there.

        The Finding Pipeline is re-entered whenever the run is resumed, so a
        fingerprint that already landed is a normal outcome rather than a
        conflict. `create_candidate` keeps raising for API callers, where a
        duplicate genuinely is a client error.
        """

        existing = self.session.scalar(
            select(Finding).where(
                Finding.audit_run_id == command.audit_run_id,
                Finding.fingerprint == command.fingerprint,
            )
        )
        if existing is not None:
            return existing
        return self.create_candidate(command)

    def transition(self, finding: Finding, target: FindingStatus) -> Finding:
        """Move a Finding through its state machine (§6.6)."""

        try:
            finding.status = transition_finding(
                FindingStatus(finding.status),
                target,
            ).value
        except InvalidTransition as exc:
            raise InvalidStateError(
                str(exc),
                error_code="finding_invalid_transition",
            ) from exc
        return finding

    def enter_human_queue(self, finding: Finding) -> Finding:
        """Move a machine-confirmed Finding into the human queue.

        §13.6 requires that critical and high findings cannot enter the human
        queue before machine review. The gate is the presence of an
        `independent_agent` verification rather than a flag someone has to
        remember to set: a review that ran but could not conclude records an
        `inconclusive` verification and passes, a review that never ran records
        nothing and is refused here.
        """

        severity = FindingSeverity(finding.severity)
        if severity in _REVIEW_REQUIRED_SEVERITIES and not any(
            verification.method == VerificationMethod.INDEPENDENT_AGENT.value
            for verification in finding.verifications
        ):
            raise InvalidStateError(
                (
                    f"{severity.value} findings require an independent machine "
                    "review before human review"
                ),
                error_code="finding_machine_review_required",
            )
        return self.transition(finding, FindingStatus.AWAITING_HUMAN_REVIEW)

    def record_verification(
        self,
        finding: Finding,
        *,
        method: VerificationMethod,
        verdict: VerificationVerdict,
        verifier: str,
        reasoning: str,
        evidence_ids: list[UUID] | None = None,
        discovered_by: list[str] | None = None,
    ) -> Verification:
        """Attach a verification result to a Finding.

        §6.10: the worker that discovered a Finding cannot be its independent
        reviewer. The check lives here rather than at the call site so no future
        caller can arrange the same worker on both sides. `discovered_by` takes
        the authoritative tool list from the candidate fact; `Finding`'s own
        column is a display string that may have been truncated.
        """

        if method is VerificationMethod.INDEPENDENT_AGENT:
            discoverers = {
                name.strip()
                for name in (
                    discovered_by
                    if discovered_by is not None
                    else finding.discovered_by.split(",")
                )
                if name.strip()
            }
            if verifier.strip() in discoverers:
                raise InvalidStateError(
                    (
                        "the worker that discovered a finding cannot perform its "
                        "independent review"
                    ),
                    error_code="verifier_not_independent",
                )
        verification = Verification(
            finding_id=finding.id,
            method=method.value,
            verdict=verdict.value,
            verifier=verifier[:255],
            evidence_ids=[str(identifier) for identifier in (evidence_ids or [])],
            reasoning=reasoning,
        )
        self.session.add(verification)
        # Appended to the relationship, not merely added to the session:
        # `enter_human_queue` reads `finding.verifications` in the same
        # transaction that records the review, and an already-loaded collection
        # would not show the new row — turning the §13.6 gate into a refusal of
        # findings that were in fact reviewed.
        finding.verifications.append(verification)
        return verification

    def record_evidence(
        self,
        finding: Finding,
        *,
        evidence_type: EvidenceType,
        summary: str,
        produced_by_task_id: UUID,
        artifact_id: UUID | None = None,
        sha256: str | None = None,
    ) -> Evidence:
        """Attach one evidence record, skipping an identical existing one.

        Deduplicated on (type, artifact) so re-running a stage after a crash
        does not multiply the evidence list.
        """

        for existing in finding.evidence:
            if existing.type == evidence_type.value and existing.artifact_id == artifact_id:
                return existing
        evidence = Evidence(
            finding_id=finding.id,
            type=evidence_type.value,
            artifact_id=artifact_id,
            summary=summary,
            sha256=sha256,
            produced_by_task_id=produced_by_task_id,
        )
        self.session.add(evidence)
        finding.evidence.append(evidence)
        return evidence

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
