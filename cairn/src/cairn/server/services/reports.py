from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from html import escape
from io import BytesIO
import json
from pathlib import Path
from typing import Literal
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import (
    ArtifactAccessLevel,
    ArtifactKind,
    AuditIntentStatus,
    AuditRunStatus,
    AuditStage,
    AuditTaskStatus,
    AuditTaskType,
    BuildStatus,
    FindingSeverity,
    FindingStatus,
    ReviewVerdict,
    RuntimeVerificationStatus,
    VerificationMethod,
)
from cairn.server.domain.state_machines import transition_audit_run
from cairn.server.errors import InvalidStateError, NotFoundError
from cairn.server.persistence.models import (
    Artifact,
    AuditCoverage,
    AuditRun,
    AuditTask,
    Finding,
    FindingLocation,
    Report,
)
from cairn.server.schemas.reports import ReportFilters
from cairn.server.services.artifacts import ArtifactService


ReportFormat = Literal["html", "json", "sarif"]
_FINAL_HUMAN_STATUSES = frozenset(
    {
        FindingStatus.CONFIRMED.value,
        FindingStatus.REJECTED.value,
        FindingStatus.ACCEPTED_RISK.value,
    }
)
_UNSETTLED_TASK_STATUSES = frozenset(
    {
        AuditTaskStatus.QUEUED.value,
        AuditTaskStatus.CLAIMED.value,
        AuditTaskStatus.RUNNING.value,
    }
)
_SEVERITY_ORDER = (
    FindingSeverity.CRITICAL.value,
    FindingSeverity.HIGH.value,
    FindingSeverity.MEDIUM.value,
    FindingSeverity.LOW.value,
    FindingSeverity.INFO.value,
)


def _location_uri(location: FindingLocation) -> str:
    if location.file_path is not None:
        return location.file_path
    if location.container_path is not None and location.entry_path is not None:
        return f"{location.container_path}!/{location.entry_path}"
    return location.entry_path or "unresolved-location"


def _location_label(location: FindingLocation) -> str:
    value = _location_uri(location)
    if location.start_line is not None and location.end_line is not None:
        value += f":{location.start_line}-{location.end_line}"
    if location.class_name is not None:
        value += f"::{location.class_name}"
    if location.method_name is not None:
        value += f".{location.method_name}{location.method_descriptor}"
    if location.bytecode_offset is not None:
        value += f"@{location.bytecode_offset}"
    return value


@dataclass(frozen=True, slots=True)
class CompletionGateResult:
    blockers: tuple[str, ...]
    has_warnings: bool

    @property
    def ready(self) -> bool:
        return not self.blockers


class ReportService:
    def __init__(
        self,
        session: Session,
        artifact_store: ArtifactStore,
    ) -> None:
        self.session = session
        self.artifact_store = artifact_store

    def generate(self, run_id: UUID) -> Report:
        """Generate all formats and complete the run in the caller's transaction."""

        audit_run = self._locked_run(run_id)
        gate = self.completion_gate(audit_run)
        if not gate.ready:
            detail = "; ".join(gate.blockers[:8])
            raise InvalidStateError(
                f"audit run completion gate failed: {detail}",
                error_code="audit_run_completion_gate_failed",
            )

        next_version = int(
            self.session.scalar(
                select(func.coalesce(func.max(Report.version), 0)).where(
                    Report.audit_run_id == audit_run.id
                )
            )
            or 0
        ) + 1
        audit_run.status = transition_audit_run(
            AuditRunStatus(audit_run.status),
            AuditRunStatus.REPORTING,
        ).value
        audit_run.current_stage = AuditStage.REPORTING.value
        audit_run.progress = 95

        coverage_task = AuditTask(
            audit_run_id=audit_run.id,
            type=AuditTaskType.COVERAGE_CHECK.value,
            scope_key=f"coverage:report:v{next_version}",
            scope={"report_version": next_version},
            required_capabilities=["coverage:completion-gate"],
            status=AuditTaskStatus.SUCCEEDED.value,
            worker_name="completion-gate",
            attempt=1,
            max_attempts=1,
            timeout_seconds=60,
            input_artifact_ids=[],
            output_artifact_ids=[],
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        report_task = AuditTask(
            audit_run_id=audit_run.id,
            type=AuditTaskType.REPORT.value,
            scope_key=f"report:v{next_version}",
            scope={"version": next_version, "formats": ["html", "json", "sarif"]},
            required_capabilities=["structured_findings"],
            status=AuditTaskStatus.RUNNING.value,
            worker_name="reporter",
            attempt=1,
            max_attempts=1,
            timeout_seconds=300,
            input_artifact_ids=[],
            output_artifact_ids=[],
            started_at=datetime.now(UTC),
        )
        self.session.add_all([coverage_task, report_task])
        self.session.flush()

        document, summary = self._document(audit_run, next_version)
        json_bytes = json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        sarif_bytes = json.dumps(
            self._sarif(audit_run),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        html_bytes = self._html(audit_run, summary).encode("utf-8")

        artifacts = [
            self._store_report_artifact(
                audit_run.id,
                report_task.id,
                html_bytes,
                "text/html; charset=utf-8",
            ),
            self._store_report_artifact(
                audit_run.id,
                report_task.id,
                json_bytes,
                "application/json",
            ),
            self._store_report_artifact(
                audit_run.id,
                report_task.id,
                sarif_bytes,
                "application/sarif+json",
            ),
        ]
        self.session.add_all(artifacts)
        self.session.flush()

        report = Report(
            audit_run_id=audit_run.id,
            version=next_version,
            summary_json=summary,
            html_artifact_id=artifacts[0].id,
            json_artifact_id=artifacts[1].id,
            sarif_artifact_id=artifacts[2].id,
        )
        self.session.add(report)
        report_task.output_artifact_ids = [str(item.id) for item in artifacts]
        report_task.status = AuditTaskStatus.SUCCEEDED.value
        report_task.finished_at = datetime.now(UTC)

        terminal = (
            AuditRunStatus.COMPLETED_WITH_WARNINGS
            if gate.has_warnings
            else AuditRunStatus.COMPLETED
        )
        audit_run.status = transition_audit_run(
            AuditRunStatus(audit_run.status),
            terminal,
        ).value
        audit_run.progress = 100
        audit_run.completed_at = datetime.now(UTC)
        self.session.flush()
        return report

    def get(self, report_id: UUID) -> Report:
        report = self.session.get(Report, report_id)
        if report is None:
            raise NotFoundError("report", report_id)
        return report

    def list(self, filters: ReportFilters) -> tuple[list[Report], int]:
        conditions = []
        if filters.audit_run_id is not None:
            conditions.append(Report.audit_run_id == filters.audit_run_id)

        count_statement = select(func.count()).select_from(Report)
        statement = select(Report)
        if conditions:
            count_statement = count_statement.where(*conditions)
            statement = statement.where(*conditions)
        total = self.session.scalar(count_statement) or 0
        reports = list(
            self.session.scalars(
                statement.order_by(Report.generated_at.desc(), Report.id)
                .limit(filters.limit)
                .offset(filters.offset)
            )
        )
        return reports, total

    def resolve(
        self,
        report_id: UUID,
        report_format: ReportFormat,
    ) -> tuple[Report, Artifact, Path]:
        report = self.get(report_id)
        artifact_id = {
            "html": report.html_artifact_id,
            "json": report.json_artifact_id,
            "sarif": report.sarif_artifact_id,
        }[report_format]
        artifact, path = ArtifactService(
            self.session,
            self.artifact_store,
        ).resolve(artifact_id)
        return report, artifact, path

    def completion_gate(self, audit_run: AuditRun) -> CompletionGateResult:
        blockers: list[str] = []
        if audit_run.status != AuditRunStatus.HUMAN_REVIEW.value:
            blockers.append("run is not in human_review")
        if audit_run.snapshot is None:
            blockers.append("run has no immutable snapshot")

        coverage = audit_run.coverage
        has_warnings = bool(audit_run.warning_count)
        if coverage is None:
            blockers.append("coverage record is missing")
        else:
            blockers.extend(self._coverage_blockers(audit_run, coverage))
            has_warnings = has_warnings or self._coverage_has_warnings(coverage)

        for task in audit_run.tasks:
            if task.status in _UNSETTLED_TASK_STATUSES:
                blockers.append(f"task {task.id} is still {task.status}")
            if task.status in {
                AuditTaskStatus.FAILED.value,
                AuditTaskStatus.SKIPPED.value,
                AuditTaskStatus.CANCELLED.value,
            }:
                has_warnings = True
                if not task.error_code:
                    blockers.append(f"task {task.id} ended without a reason code")

        inventory_succeeded = any(
            task.type == AuditTaskType.INVENTORY.value
            and task.status == AuditTaskStatus.SUCCEEDED.value
            for task in audit_run.tasks
        )
        if not inventory_succeeded:
            blockers.append("successful inventory task is missing")

        for intent in audit_run.intents:
            if intent.status in {
                AuditIntentStatus.PENDING.value,
                AuditIntentStatus.CLAIMED.value,
            }:
                blockers.append(f"audit intent {intent.id} is still {intent.status}")

        for finding in audit_run.findings:
            if finding.status in {
                FindingStatus.CANDIDATE.value,
                FindingStatus.VALIDATING.value,
                FindingStatus.AWAITING_HUMAN_REVIEW.value,
            }:
                blockers.append(f"finding {finding.id} is still {finding.status}")
            if self._was_severe(finding):
                if not any(
                    verification.method
                    == VerificationMethod.INDEPENDENT_AGENT.value
                    for verification in finding.verifications
                ):
                    blockers.append(
                        f"critical/high finding {finding.id} lacks independent verification"
                    )
                if (
                    finding.runtime_verification
                    != RuntimeVerificationStatus.NOT_APPLICABLE.value
                    and not any(
                        verification.method == VerificationMethod.DYNAMIC_POC.value
                        for verification in finding.verifications
                    )
                ):
                    blockers.append(
                        f"critical/high finding {finding.id} lacks dynamic verification"
                    )
            if self._requires_human_disposition(finding):
                if finding.status not in _FINAL_HUMAN_STATUSES:
                    blockers.append(f"critical/high finding {finding.id} is not disposed")
                if not any(
                    review.verdict != ReviewVerdict.REVERIFY.value
                    for review in finding.human_reviews
                ):
                    blockers.append(f"critical/high finding {finding.id} lacks human review")

        return CompletionGateResult(tuple(dict.fromkeys(blockers)), has_warnings)

    def _locked_run(self, run_id: UUID) -> AuditRun:
        statement = (
            select(AuditRun)
            .where(AuditRun.id == run_id)
            .with_for_update()
            .options(
                selectinload(AuditRun.repository),
                selectinload(AuditRun.snapshot),
                selectinload(AuditRun.policy),
                selectinload(AuditRun.tasks),
                selectinload(AuditRun.coverage),
                selectinload(AuditRun.intents),
                selectinload(AuditRun.findings).selectinload(Finding.locations),
                selectinload(AuditRun.findings).selectinload(Finding.evidence),
                selectinload(AuditRun.findings).selectinload(Finding.verifications),
                selectinload(AuditRun.findings).selectinload(Finding.human_reviews),
            )
        )
        audit_run = self.session.scalar(statement)
        if audit_run is None:
            raise NotFoundError("audit_run", run_id)
        return audit_run

    @staticmethod
    def _coverage_blockers(
        audit_run: AuditRun,
        coverage: AuditCoverage,
    ) -> list[str]:
        blockers: list[str] = []
        warning_tools = {
            str(item.get("tool"))
            for item in coverage.coverage_warnings
            if item.get("reason_code") and item.get("tool")
        }
        semantic_warning = any(
            tool == "semantic-review" or tool.startswith("semantic-review:")
            for tool in warning_tools
        )
        build_warning = "build" in warning_tools
        skipped_java = {
            str(path)
            for path in coverage.skipped_paths
            if str(path).lower().endswith(".java")
        }
        if (
            coverage.modules_analyzed < coverage.modules_total
            and not coverage.unsupported_components
        ):
            blockers.append("module coverage gap has no recorded reason")
        if (
            coverage.java_files_analyzed < coverage.java_files_total
            and len(skipped_java)
            < coverage.java_files_total - coverage.java_files_analyzed
        ):
            blockers.append("Java file coverage gap has no recorded reason")
        if (
            coverage.entrypoints_analyzed < coverage.entrypoints_total
            and not semantic_warning
        ):
            blockers.append("entrypoint coverage gap has no recorded reason")
        if (
            coverage.sensitive_sinks_analyzed < coverage.sensitive_sinks_total
            and not semantic_warning
        ):
            blockers.append("sensitive sink coverage gap has no recorded reason")
        if coverage.build_status != BuildStatus.SUCCESS.value and not build_warning:
            blockers.append("non-successful build has no coverage warning")

        completed = coverage.static_tools_completed or {}
        for tool in audit_run.policy.enabled_scanners:
            value = completed.get(tool)
            if not isinstance(value, dict):
                blockers.append(f"required static tool {tool} has no result")
                continue
            status = value.get("status")
            if not isinstance(status, str):
                blockers.append(f"required static tool {tool} has no terminal status")
            if status != "completed" and not value.get("reason_code"):
                blockers.append(f"required static tool {tool} failed without a reason")
        return blockers

    @staticmethod
    def _coverage_has_warnings(coverage: AuditCoverage) -> bool:
        return bool(
            coverage.coverage_warnings
            or coverage.skipped_paths
            or coverage.unsupported_components
            or coverage.build_status != BuildStatus.SUCCESS.value
            or coverage.modules_analyzed < coverage.modules_total
            or coverage.java_files_analyzed < coverage.java_files_total
            or coverage.entrypoints_analyzed < coverage.entrypoints_total
            or coverage.sensitive_sinks_analyzed < coverage.sensitive_sinks_total
            or any(
                isinstance(result, dict) and result.get("status") != "completed"
                for result in coverage.static_tools_completed.values()
            )
        )

    @staticmethod
    def _requires_human_disposition(finding: Finding) -> bool:
        return ReportService._was_severe(finding)

    @staticmethod
    def _was_severe(finding: Finding) -> bool:
        if finding.severity in {
            FindingSeverity.CRITICAL.value,
            FindingSeverity.HIGH.value,
        }:
            return True
        return any(
            review.original_severity
            in {FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value}
            for review in finding.human_reviews
        )

    def _document(
        self,
        audit_run: AuditRun,
        version: int,
    ) -> tuple[dict[str, object], dict[str, object]]:
        severity_counts = Counter(finding.severity for finding in audit_run.findings)
        status_counts = Counter(finding.status for finding in audit_run.findings)
        active = [
            finding
            for finding in audit_run.findings
            if finding.status != FindingStatus.REJECTED.value
        ]
        overall_risk = next(
            (
                severity
                for severity in _SEVERITY_ORDER
                if any(finding.severity == severity for finding in active)
            ),
            "none",
        )
        coverage = audit_run.coverage
        assert coverage is not None
        snapshot = audit_run.snapshot
        assert snapshot is not None
        summary: dict[str, object] = {
            "repository": {
                "id": str(audit_run.repository.id),
                "name": audit_run.repository.name,
            },
            "snapshot": {
                "id": str(snapshot.id),
                "commit_sha": snapshot.commit_sha,
                "content_sha256": snapshot.content_sha256,
            },
            "policy": {
                "id": str(audit_run.policy_id),
                "name": audit_run.policy.name,
                "version": audit_run.policy_version,
            },
            "overall_risk": overall_risk,
            "severity_counts": {
                severity: severity_counts.get(severity, 0)
                for severity in _SEVERITY_ORDER
            },
            "status_counts": dict(sorted(status_counts.items())),
            "build_status": coverage.build_status,
            "coverage_warning_count": len(coverage.coverage_warnings),
            "warning_count": audit_run.warning_count,
        }
        document: dict[str, object] = {
            "schema_version": "cairn-report-v1",
            "report_version": version,
            "audit_run_id": str(audit_run.id),
            "generated_at": datetime.now(UTC).isoformat(),
            "summary": summary,
            "coverage": self._coverage_dict(coverage),
            "findings": [self._finding_dict(item) for item in audit_run.findings],
        }
        return document, summary

    @staticmethod
    def _coverage_dict(coverage: AuditCoverage) -> dict[str, object]:
        return {
            "modules_total": coverage.modules_total,
            "modules_analyzed": coverage.modules_analyzed,
            "java_files_total": coverage.java_files_total,
            "java_files_analyzed": coverage.java_files_analyzed,
            "entrypoints_total": coverage.entrypoints_total,
            "entrypoints_analyzed": coverage.entrypoints_analyzed,
            "sensitive_sinks_total": coverage.sensitive_sinks_total,
            "sensitive_sinks_analyzed": coverage.sensitive_sinks_analyzed,
            "build_status": coverage.build_status,
            "static_tools_completed": coverage.static_tools_completed,
            "skipped_paths": coverage.skipped_paths,
            "unsupported_components": coverage.unsupported_components,
            "coverage_warnings": coverage.coverage_warnings,
        }

    @staticmethod
    def _finding_dict(finding: Finding) -> dict[str, object]:
        return {
            "id": str(finding.id),
            "fingerprint": finding.fingerprint,
            "title": finding.title,
            "description": finding.description,
            "category": finding.category,
            "cwe_id": finding.cwe_id,
            "owasp_category": finding.owasp_category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "status": finding.status,
            "attack_preconditions": finding.attack_preconditions,
            "impact": finding.impact,
            "remediation": finding.remediation,
            "runtime_verification": finding.runtime_verification,
            "discovered_by": finding.discovered_by,
            "locations": [
                {
                    "role": location.role,
                    "origin_kind": location.origin_kind,
                    "file_path": location.file_path,
                    "source_path": location.file_path,
                    "start_line": location.start_line,
                    "end_line": location.end_line,
                    "symbol": location.symbol,
                    "code_snippet": location.code_snippet,
                    "container_path": location.container_path,
                    "entry_path": location.entry_path,
                    "class_name": location.class_name,
                    "method_name": location.method_name,
                    "method_descriptor": location.method_descriptor,
                    "bytecode_offset": location.bytecode_offset,
                    "decompiled_artifact_id": (
                        str(location.decompiled_artifact_id)
                        if location.decompiled_artifact_id
                        else None
                    ),
                    "decompiled_start_line": location.decompiled_start_line,
                    "decompiled_end_line": location.decompiled_end_line,
                    "snapshot_sha": location.snapshot_sha,
                    "ordinal": location.ordinal,
                }
                for location in finding.locations
            ],
            "evidence": [
                {
                    "id": str(evidence.id),
                    "type": evidence.type,
                    "artifact_id": (
                        str(evidence.artifact_id) if evidence.artifact_id else None
                    ),
                    "summary": evidence.summary,
                    "sha256": evidence.sha256,
                }
                for evidence in finding.evidence
            ],
            "verifications": [
                {
                    "method": verification.method,
                    "verdict": verification.verdict,
                    "verifier": verification.verifier,
                    "evidence_ids": verification.evidence_ids,
                    "reasoning": verification.reasoning,
                }
                for verification in finding.verifications
            ],
            "human_reviews": [
                {
                    "verdict": review.verdict,
                    "original_severity": review.original_severity,
                    "final_severity": review.final_severity,
                    "reviewer_id": review.reviewer_id,
                    "comment": review.comment,
                    "reviewed_at": review.reviewed_at.isoformat(),
                }
                for review in finding.human_reviews
            ],
        }

    @staticmethod
    def _sarif(audit_run: AuditRun) -> dict[str, object]:
        included = [
            finding
            for finding in audit_run.findings
            if finding.status != FindingStatus.REJECTED.value
        ]
        rule_ids = sorted({finding.cwe_id for finding in included})
        rules = [
            {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": rule_id},
            }
            for rule_id in rule_ids
        ]
        results: list[dict[str, object]] = []
        for finding in included:
            result: dict[str, object] = {
                "ruleId": finding.cwe_id,
                "level": (
                    "error"
                    if finding.severity
                    in {FindingSeverity.CRITICAL.value, FindingSeverity.HIGH.value}
                    else "warning"
                    if finding.severity == FindingSeverity.MEDIUM.value
                    else "note"
                ),
                "message": {"text": finding.title},
                "fingerprints": {"cairn/v1": finding.fingerprint},
                "properties": {
                    "severity": finding.severity,
                    "confidence": finding.confidence,
                    "status": finding.status,
                    "runtimeVerification": finding.runtime_verification,
                },
            }
            if finding.locations:
                primary = finding.locations[0]
                physical_location: dict[str, object] = {
                    "artifactLocation": {"uri": _location_uri(primary)},
                }
                if primary.start_line is not None and primary.end_line is not None:
                    physical_location["region"] = {
                        "startLine": primary.start_line,
                        "endLine": primary.end_line,
                    }
                location_properties = {
                    key: value
                    for key, value in {
                        "originKind": primary.origin_kind,
                        "containerPath": primary.container_path,
                        "entryPath": primary.entry_path,
                        "className": primary.class_name,
                        "methodName": primary.method_name,
                        "methodDescriptor": primary.method_descriptor,
                        "bytecodeOffset": primary.bytecode_offset,
                        "decompiledArtifactId": (
                            str(primary.decompiled_artifact_id)
                            if primary.decompiled_artifact_id
                            else None
                        ),
                    }.items()
                    if value is not None
                }
                result["locations"] = [
                    {
                        "physicalLocation": physical_location,
                        "properties": location_properties,
                    }
                ]
            if finding.status == FindingStatus.ACCEPTED_RISK.value:
                result["suppressions"] = [
                    {"kind": "external", "status": "accepted"}
                ]
            results.append(result)
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Cairn Java Audit",
                            "informationUri": "https://github.com/",
                            "rules": rules,
                        }
                    },
                    "automationDetails": {"id": str(audit_run.id)},
                    "results": results,
                }
            ],
        }

    def _html(
        self,
        audit_run: AuditRun,
        summary: dict[str, object],
    ) -> str:
        coverage = audit_run.coverage
        assert coverage is not None
        finding_sections: list[str] = []
        for finding in audit_run.findings:
            location_items: list[str] = []
            for location in finding.locations:
                snippet = (
                    f"<pre><code>{escape(location.code_snippet)}</code></pre>"
                    if location.code_snippet is not None
                    else ""
                )
                symbol = (
                    f" &middot; {escape(location.symbol)}"
                    if location.symbol
                    else ""
                )
                location_items.append(
                    "<li><strong>"
                    + escape(location.role)
                    + " / "
                    + escape(location.origin_kind)
                    + "</strong> <code>"
                    + escape(_location_label(location))
                    + "</code>"
                    + symbol
                    + snippet
                    + "</li>"
                )
            locations = "".join(location_items) or "<li>No code location</li>"
            evidence = "".join(
                "<li><strong>"
                + escape(item.type)
                + "</strong>: "
                + escape(item.summary)
                + (
                    f" <code>sha256:{escape(item.sha256)}</code>"
                    if item.sha256
                    else ""
                )
                + "</li>"
                for item in finding.evidence
            ) or "<li>None recorded</li>"
            verifications = "".join(
                "<li><strong>"
                + escape(item.method)
                + " / "
                + escape(item.verdict)
                + "</strong> by "
                + escape(item.verifier)
                + ": "
                + escape(item.reasoning)
                + "</li>"
                for item in finding.verifications
            ) or "<li>None recorded</li>"
            reviews = "".join(
                "<li>"
                + escape(review.verdict)
                + " ("
                + escape(review.final_severity)
                + "): "
                + escape(review.comment)
                + "</li>"
                for review in finding.human_reviews
            ) or "<li>Not required</li>"
            finding_sections.append(
                "<section class=\"finding\">"
                f"<h2>{escape(finding.title)}</h2>"
                f"<p><strong>{escape(finding.severity.upper())}</strong> "
                f"{escape(finding.cwe_id)} &middot; {escape(finding.status)} &middot; "
                f"confidence {escape(finding.confidence)} &middot; runtime "
                f"{escape(finding.runtime_verification)}</p>"
                f"<p>{escape(finding.description)}</p>"
                f"<h3>Attack preconditions</h3>"
                f"<p>{escape(finding.attack_preconditions)}</p>"
                f"<h3>Impact</h3><p>{escape(finding.impact)}</p>"
                f"<h3>Call chain and locations</h3><ol>{locations}</ol>"
                f"<h3>Evidence</h3><ul>{evidence}</ul>"
                f"<h3>Machine verification</h3><ul>{verifications}</ul>"
                f"<h3>Remediation</h3><p>{escape(finding.remediation)}</p>"
                f"<h3>Human review</h3><ul>{reviews}</ul>"
                "</section>"
            )
        warnings = "".join(
            f"<li>{escape(json.dumps(item, ensure_ascii=True, sort_keys=True))}</li>"
            for item in coverage.coverage_warnings
        ) or "<li>None</li>"
        skipped_paths = "".join(
            f"<li><code>{escape(path)}</code></li>" for path in coverage.skipped_paths
        ) or "<li>None</li>"
        unsupported_components = "".join(
            f"<li>{escape(json.dumps(item, ensure_ascii=True, sort_keys=True))}</li>"
            for item in coverage.unsupported_components
        ) or "<li>None</li>"
        static_tools = "".join(
            f"<li><strong>{escape(tool)}</strong>: "
            f"{escape(json.dumps(result, ensure_ascii=True, sort_keys=True))}</li>"
            for tool, result in sorted(coverage.static_tools_completed.items())
        ) or "<li>None</li>"
        counts = summary["severity_counts"]
        assert isinstance(counts, dict)
        count_cells = "".join(
            f"<td><strong>{escape(key)}</strong><br>{int(value)}</td>"
            for key, value in counts.items()
        )
        return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Cairn audit report</title>
<style>body{{font:14px system-ui,sans-serif;max-width:1100px;margin:32px auto;padding:0 20px;color:#202124}}h1,h2,h3{{letter-spacing:0}}table{{border-collapse:collapse;width:100%}}td{{border:1px solid #ccc;padding:10px}}.finding{{border-top:2px solid #444;padding:18px 0}}code,pre{{white-space:pre-wrap;overflow-wrap:anywhere}}pre{{padding:10px;background:#f4f6f5;border:1px solid #ddd}}</style>
</head><body><header><h1>Cairn Java Audit Report</h1>
<p>Run <code>{escape(str(audit_run.id))}</code> &middot; Overall risk: <strong>{escape(str(summary['overall_risk']))}</strong></p></header>
<table><tr>{count_cells}</tr></table>
<section><h2>Coverage</h2><p>Build: {escape(coverage.build_status)}. Java files: {coverage.java_files_analyzed}/{coverage.java_files_total}. Entrypoints: {coverage.entrypoints_analyzed}/{coverage.entrypoints_total}. Sensitive sinks: {coverage.sensitive_sinks_analyzed}/{coverage.sensitive_sinks_total}.</p><h3>Static tools</h3><ul>{static_tools}</ul><h3>Warnings</h3><ul>{warnings}</ul><h3>Skipped paths</h3><ul>{skipped_paths}</ul><h3>Unsupported components</h3><ul>{unsupported_components}</ul></section>
{''.join(finding_sections)}</body></html>"""

    def _store_report_artifact(
        self,
        run_id: UUID,
        task_id: UUID,
        payload: bytes,
        media_type: str,
    ) -> Artifact:
        stored = self.artifact_store.put_stream(BytesIO(payload))
        return Artifact(
            audit_run_id=run_id,
            kind=ArtifactKind.REPORT.value,
            storage_key=stored.storage_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
            media_type=media_type,
            access_level=ArtifactAccessLevel.NORMAL.value,
            produced_by_task_id=task_id,
        )
