from __future__ import annotations

from datetime import UTC, datetime, timedelta
import logging
from pathlib import PurePosixPath
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session

from cairn.analysis.contracts import (
    AnalysisManifest,
    AnalysisOperation,
    BYTECODE_SCANNERS,
    ToolStatus,
)
from cairn.analysis.fingerprints import merge_candidates
from cairn.gateway.config import read_key_file
from cairn.gateway.tokens import ModelGrant, mint_grant
from cairn.orchestrator.artifacts import SandboxArtifactRegistrar
from cairn.orchestrator.client import SandboxBackend
from cairn.orchestrator.config import OrchestratorSettings
from cairn.orchestrator.errors import OrchestratorError
from cairn.orchestrator.semantic_tasks import (
    TRUNCATION_REASON,
    SemanticBudget,
    plan_semantic_reviews,
)
from cairn.orchestrator.tasks import (
    TASK_SPECS,
    get_or_create_semantic_task,
    get_or_create_task,
)
from cairn.orchestrator.dynamic_tasks import (
    TRUNCATION_REASON as DYNAMIC_TRUNCATION_REASON,
    DynamicBudget,
    get_or_create_dynamic_task,
    plan_probe_targets,
)
from cairn.dynamic.contracts import DynamicResult, ProbeOutcome
from cairn.dynamic.probes import PROBEABLE_CATEGORIES
from cairn.poc.contracts import PocResult
from cairn.orchestrator.poc_tasks import (
    POC_AUTHOR_TOOL,
    TRUNCATION_REASON as POC_TRUNCATION_REASON,
    _METHOD_BY_ANNOTATION as _POC_METHOD_BY_ANNOTATION,
    get_or_create_poc_task,
)
from cairn.orchestrator.verification import (
    TRUNCATION_REASON as VERIFY_TRUNCATION_REASON,
    VerificationBudget,
    get_or_create_verify_task,
)
from cairn.pipeline.decide import REVIEW_REQUIRED_SEVERITIES, decide
from cairn.pipeline.promote import promote_candidates
from cairn.sandbox.contracts import (
    ACTIVE_SANDBOX_STATUSES,
    DynamicSandboxSpec,
    PocAssignmentSpec,
    PocPlanSpec,
    SandboxCreateRequest,
    SandboxLimitsOverride,
    SandboxOperation,
    SandboxRecord,
    SandboxStatus,
    SandboxTemplateName,
    SemanticSandboxSpec,
    SemanticScopeSpec,
    SnapshotArtifact,
    VerifyCandidateSpec,
    VerifyLocationSpec,
)
from cairn.sandbox.services import ServiceKind
from cairn.semantic.client import DEFAULT_MODEL as SEMANTIC_MODEL
from cairn.semantic.contracts import SEMANTIC_TOOL_NAME, SemanticReviewResult
from cairn.semantic.findings import ReviewScope
from cairn.server.artifacts import ArtifactStore
from cairn.server.domain.enums import (
    ArtifactKind,
    AuditFactKind,
    AuditIntentStatus,
    AuditRunStatus,
    AuditTaskStatus,
    BuildStatus,
    DynamicVerificationMode,
    EvidenceType,
    FindingSeverity,
    FindingStatus,
    VerificationMethod,
    VerificationVerdict,
)
from cairn.server.errors import DomainError
from cairn.server.ingestion import GitFetcher, IngestionLimits
from cairn.server.persistence.models import (
    Artifact,
    AuditCoverage,
    AuditFact,
    AuditIntent,
    AuditIntentSource,
    AuditRun,
    AuditTask,
    Finding,
    SourceSnapshot,
)
from cairn.server.services.audit_runs import AuditRunService
from cairn.server.services.findings import FindingService
from cairn.server.services.snapshots import SnapshotService
from cairn.verify.contracts import VERIFY_TOOL_NAME, VerifyResult


LOG = logging.getLogger(__name__)
# Every non-terminal status the worker can pick up. The three model-backed and
# verification stages are here because a process that dies mid-stage leaves the
# run parked in one of them, and a status absent from this set is a run
# `process_next` will never look at again.
_ELIGIBLE_STATUSES = {
    AuditRunStatus.CREATED.value,
    AuditRunStatus.INGESTING.value,
    AuditRunStatus.PREPROCESSING.value,
    AuditRunStatus.STATIC_SCANNING.value,
    AuditRunStatus.SEMANTIC_AUDITING.value,
    AuditRunStatus.DYNAMIC_VERIFYING.value,
    AuditRunStatus.MACHINE_REVIEW.value,
    AuditRunStatus.CANCELLING.value,
}
_SCANNER_ORDER = (
    AnalysisOperation.CODEQL,
    AnalysisOperation.SEMGREP,
    AnalysisOperation.FINDSECBUGS,
    AnalysisOperation.DEPENDENCY_CHECK,
    AnalysisOperation.TRIVY,
    AnalysisOperation.GITLEAKS,
    AnalysisOperation.CONFIG_RULES,
)
_RETRYABLE_MANIFEST_CODES = {
    "ANALYSIS_COMMAND_FAILED",
    "ANALYSIS_COMMAND_TIMEOUT",
    "ANALYSIS_INTERNAL_FAILURE",
    "SCANNER_EXIT_NONZERO",
    "SCANNER_OUTPUT_MISSING",
    "SCANNER_VERSION_FAILED",
}
_RETRYABLE_OUTPUT_CODES = {
    "ANALYSIS_MANIFEST_INVALID",
    "ANALYSIS_MANIFEST_MISSING",
    "ANALYSIS_OPERATION_MISMATCH",
    "ANALYSIS_OUTPUT_INVALID",
    "SANDBOX_ARTIFACT_INVALID",
}

PIPELINE_TOOL_NAME = "finding-pipeline"
DYNAMIC_VERIFIER_NAME = "dynamic-verifier"
MAX_EVIDENCE_PER_FINDING = 16
MAX_VERIFY_LOCATIONS = 32
_SEVERITY_RANK = {
    FindingSeverity.CRITICAL.value: 4,
    FindingSeverity.HIGH.value: 3,
    FindingSeverity.MEDIUM.value: 2,
    FindingSeverity.LOW.value: 1,
    FindingSeverity.INFO.value: 0,
}


class _RunCancelled(Exception):
    pass


class DeterministicOrchestrator:
    def __init__(
        self,
        session: Session,
        settings: OrchestratorSettings,
        artifact_store: ArtifactStore,
        sandbox: SandboxBackend,
    ) -> None:
        self.session = session
        self.settings = settings
        self.artifact_store = artifact_store
        self.sandbox = sandbox
        # Set while the dynamic stage runs, so probe evidence can name the
        # task that produced it.
        self._dynamic_task_id: UUID | None = None

    def process_next(self) -> UUID | None:
        audit_run = self.session.scalar(
            select(AuditRun)
            .where(AuditRun.status.in_(_ELIGIBLE_STATUSES))
            .order_by(AuditRun.created_at, AuditRun.id)
            .with_for_update(skip_locked=True)
            .limit(1)
        )
        if audit_run is None:
            self.session.rollback()
            return None
        run_id = audit_run.id
        self.session.commit()
        self.process_run(run_id)
        return run_id

    def process_run(self, run_id: UUID) -> AuditRun:
        try:
            while True:
                audit_run = self._run(run_id)
                status = AuditRunStatus(audit_run.status)
                if status is AuditRunStatus.CANCELLING:
                    self._cancel_run(audit_run)
                    raise _RunCancelled
                if status is AuditRunStatus.CREATED:
                    AuditRunService(self.session).transition(
                        run_id,
                        AuditRunStatus.INGESTING,
                    )
                    continue
                if status is AuditRunStatus.INGESTING:
                    snapshot = self._resolve_snapshot(audit_run)
                    AuditRunService(self.session).transition(
                        run_id,
                        AuditRunStatus.PREPROCESSING,
                        snapshot_id=snapshot.id,
                    )
                    continue
                if status is AuditRunStatus.PREPROCESSING:
                    self._preprocess(audit_run)
                    continue
                if status is AuditRunStatus.STATIC_SCANNING:
                    self._static_scan(audit_run)
                    continue
                if status is AuditRunStatus.SEMANTIC_AUDITING:
                    self._semantic_audit(audit_run)
                    continue
                if status is AuditRunStatus.DYNAMIC_VERIFYING:
                    self._dynamic_verify(audit_run)
                    continue
                if status is AuditRunStatus.MACHINE_REVIEW:
                    self._machine_review(audit_run)
                    continue
                return audit_run
        except _RunCancelled:
            return self._run(run_id)
        except OrchestratorError as exc:
            self.session.rollback()
            if not exc.retryable:
                self._fail_run(run_id, exc)
            else:
                LOG.warning("orchestrator retryable error: %s", exc.error_code)
            return self._run(run_id)

    def _resolve_snapshot(self, audit_run: AuditRun) -> SourceSnapshot:
        if audit_run.snapshot is not None:
            return audit_run.snapshot
        source_request = audit_run.source_request
        source_type = source_request.get("type")
        service = SnapshotService(
            self.session,
            self.artifact_store,
            IngestionLimits.from_settings(self.settings),
            git_fetcher=GitFetcher(
                allowed_hosts=self.settings.git_allowed_hosts,
                timeout_seconds=self.settings.git_clone_timeout_seconds,
                max_checkout_bytes=self.settings.snapshot_max_total_bytes,
            ),
            secret_key_file=self.settings.secret_key_file,
            work_root=self.settings.ingestion_work_root,
        )
        try:
            if source_type == "git_ref":
                ref = source_request.get("ref")
                if not isinstance(ref, str):
                    raise OrchestratorError(
                        "ORCHESTRATOR_SOURCE_REQUEST_INVALID",
                        "Git source request is invalid",
                    )
                return service.create_from_git(audit_run.repository_id, ref)
            if source_type == "upload":
                try:
                    upload_id = UUID(str(source_request["upload_id"]))
                except (KeyError, TypeError, ValueError) as exc:
                    raise OrchestratorError(
                        "ORCHESTRATOR_SOURCE_REQUEST_INVALID",
                        "Upload source request is invalid",
                    ) from exc
                return service.create_from_upload(audit_run.repository_id, upload_id)
        except DomainError as exc:
            raise OrchestratorError(
                exc.error_code,
                "Source ingestion failed",
            ) from exc
        raise OrchestratorError(
            "ORCHESTRATOR_SNAPSHOT_REQUIRED",
            "AuditRun source did not resolve to a Snapshot",
        )

    def _preprocess(self, audit_run: AuditRun) -> None:
        coverage = self._coverage(audit_run)
        inventory_task, inventory, inventory_artifacts = self._execute_profile(
            audit_run,
            AnalysisOperation.INVENTORY,
        )
        if inventory is None or inventory.status is not ToolStatus.COMPLETED:
            raise OrchestratorError(
                inventory.reason_code if inventory else "INVENTORY_FAILED",
                "Java inventory did not complete",
            )
        assert inventory.inventory is not None
        self._persist_inventory(
            audit_run,
            inventory_task,
            inventory,
            inventory_artifacts,
        )
        data = inventory.inventory
        coverage.modules_total = len(data.modules)
        coverage.modules_analyzed = len(data.modules)
        coverage.java_files_total = data.java_files_total
        skipped_java = sum(path.lower().endswith(".java") for path in data.skipped_paths)
        coverage.java_files_analyzed = max(0, data.java_files_total - skipped_java)
        coverage.entrypoints_total = len(data.entrypoints)
        coverage.entrypoints_analyzed = 0
        coverage.sensitive_sinks_total = len(data.sinks)
        coverage.sensitive_sinks_analyzed = 0
        coverage.skipped_paths = list(data.skipped_paths)
        coverage.unsupported_components = list(data.unsupported_components)
        audit_run.progress = 25
        self.session.commit()

        build_task, build_manifest, build_artifacts = self._execute_profile(
            audit_run,
            AnalysisOperation.BUILD,
        )
        del build_artifacts
        if (
            build_manifest is not None
            and build_manifest.status is ToolStatus.COMPLETED
            and build_manifest.build is not None
        ):
            coverage.build_status = build_manifest.build.status
            if build_manifest.build.status != BuildStatus.SUCCESS.value:
                self._add_warning(
                    coverage,
                    "PROJECT_BUILD_FAILED",
                    tool="build",
                    task_id=build_task.id,
                )
        else:
            coverage.build_status = BuildStatus.FAILED.value
            self._add_warning(
                coverage,
                build_manifest.reason_code
                if build_manifest is not None
                else build_task.error_code or "BUILD_EXECUTION_FAILED",
                tool="build",
                task_id=build_task.id,
            )
        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 40
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.STATIC_SCANNING,
        )

    def _static_scan(self, audit_run: AuditRun) -> None:
        coverage = self._coverage(audit_run)
        enabled = set(audit_run.policy.enabled_scanners)
        completed = dict(coverage.static_tools_completed)
        for operation in _SCANNER_ORDER:
            if operation.value not in enabled or operation.value in completed:
                continue
            if (
                operation in BYTECODE_SCANNERS
                and coverage.build_status == BuildStatus.FAILED.value
            ):
                task = get_or_create_task(self.session, audit_run, operation)
                task.status = AuditTaskStatus.SKIPPED.value
                task.error_code = "BYTECODE_UNAVAILABLE"
                task.finished_at = datetime.now(UTC)
                completed[operation.value] = self._tool_coverage(
                    task,
                    status=ToolStatus.SKIPPED,
                    version=None,
                    artifact_ids=[],
                    reason_code="BYTECODE_UNAVAILABLE",
                    candidate_count=0,
                )
                coverage.static_tools_completed = dict(completed)
                self._add_warning(
                    coverage,
                    "BYTECODE_UNAVAILABLE",
                    tool=operation.value,
                    task_id=task.id,
                )
                self.session.commit()
                continue

            task, manifest, artifacts = self._execute_profile(
                audit_run,
                operation,
            )
            if manifest is None:
                status = ToolStatus.FAILED
                version = None
                reason_code = task.error_code or "SCANNER_EXECUTION_FAILED"
                candidate_count = 0
            else:
                status = manifest.status
                version = manifest.tool_version
                reason_code = manifest.reason_code
                candidate_count = len(manifest.candidates)
                if manifest.candidates:
                    self._persist_candidates(
                        audit_run,
                        task,
                        [
                            candidate.model_dump(mode="json")
                            for candidate in manifest.candidates
                        ],
                        artifacts,
                    )
            completed[operation.value] = self._tool_coverage(
                task,
                status=status,
                version=version,
                artifact_ids=[UUID(identifier) for identifier in task.output_artifact_ids],
                reason_code=reason_code,
                candidate_count=candidate_count,
            )
            coverage.static_tools_completed = dict(completed)
            if status is not ToolStatus.COMPLETED:
                self._add_warning(
                    coverage,
                    reason_code or "SCANNER_EXECUTION_FAILED",
                    tool=operation.value,
                    task_id=task.id,
                )
            audit_run.warning_count = len(coverage.coverage_warnings)
            finished = len(completed)
            total = max(1, len(enabled))
            audit_run.progress = min(60, 40 + int(20 * finished / total))
            self.session.commit()

        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 60
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.SEMANTIC_AUDITING,
        )
        # The semantic stage is a `process_run` branch, not an inline call: a
        # crash inside it must leave a run the worker can pick up again.

    def _semantic_audit(self, audit_run: AuditRun) -> None:
        """Run the AI semantic review stage (§7.5) and hand off to verification.

        Every scope is independent: one refusal or one malformed result costs
        that scope and is recorded as a coverage gap, rather than failing the
        run. A run whose plan is empty still advances — a repository with no
        reachable entrypoint is a valid audit result, not an error.
        """

        coverage = self._coverage(audit_run)
        inventory = self._inventory_payload(audit_run)
        budget = SemanticBudget.from_policy(self._semantic_policy(audit_run))
        plan = plan_semantic_reviews(inventory, budget=budget)
        if plan.truncated:
            # A silent cap reads as "fully covered" when it is not.
            self._add_warning(
                coverage,
                TRUNCATION_REASON,
                tool=SEMANTIC_TOOL_NAME,
                task_id=audit_run.id,
            )

        reviewed_entrypoints: set[str] = set()
        reviewed_sinks: set[str] = set()
        completed = 0
        for scope in plan.scopes:
            task, result, artifacts = self._execute_semantic_scope(
                audit_run,
                scope,
                plan.budget,
            )
            if result is None:
                self._add_warning(
                    coverage,
                    task.error_code or "SEMANTIC_REVIEW_FAILED",
                    tool=f"{SEMANTIC_TOOL_NAME}:{scope.category}",
                    task_id=task.id,
                )
            else:
                if result.status is not ToolStatus.COMPLETED:
                    # A cyber-classifier refusal is a visible coverage gap, not
                    # a silent zero-finding pass.
                    self._add_warning(
                        coverage,
                        result.reason_code or "SEMANTIC_REVIEW_INCOMPLETE",
                        tool=f"{SEMANTIC_TOOL_NAME}:{scope.category}",
                        task_id=task.id,
                    )
                self._persist_semantic_result(
                    audit_run,
                    task,
                    scope,
                    result,
                    artifacts,
                )
                if result.status is ToolStatus.COMPLETED:
                    completed += 1
                    reviewed_entrypoints.update(scope.entrypoint_paths)
                    for finding in result.findings:
                        reviewed_sinks.update(
                            location.path
                            for location in finding.locations
                            if location.role == "sink"
                        )
            audit_run.warning_count = len(coverage.coverage_warnings)
            audit_run.progress = min(
                80,
                60 + int(20 * (completed + 1) / max(1, len(plan.scopes))),
            )
            self.session.commit()

        coverage.entrypoints_analyzed = min(
            coverage.entrypoints_total,
            len(reviewed_entrypoints),
        )
        coverage.sensitive_sinks_analyzed = min(
            coverage.sensitive_sinks_total,
            len(reviewed_sinks),
        )
        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 80
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.DYNAMIC_VERIFYING,
        )

    def _dynamic_verify(self, audit_run: AuditRun) -> None:
        """Promote candidates to Findings, then verify them at runtime (§7.7).

        The promotion happens here rather than at the end of the semantic stage
        because a ``Verification`` and an ``Evidence`` row both hang off a
        ``finding_id``: nothing can be verified until the Findings exist.

        One validation Sandbox serves the whole run. Standing the application
        and its dependencies up is the expensive part; probing one more finding
        against an environment that is already running is not, so a sandbox per
        finding would multiply the cost of the environment by the number of
        findings for no gain.

        When the environment cannot be built — the policy disables it, the
        build produced nothing runnable, the Sandbox failed — every Finding
        still receives an ``inconclusive`` dynamic verification naming why.
        §7.7 permits no other answer, and recording the absence is what keeps
        the §7.10 completion gate honest.
        """

        coverage = self._coverage(audit_run)
        service = FindingService(self.session)
        findings = self._promote_findings(audit_run, coverage, service)
        for finding in findings:
            if FindingStatus(finding.status) is FindingStatus.CANDIDATE:
                service.transition(finding, FindingStatus.VALIDATING)

        outcomes: dict[str, ProbeOutcome] = {}
        if findings:
            outcomes = self._run_dynamic_environment(
                audit_run,
                findings,
                coverage,
            )

        reason_code, detail = self._dynamic_unavailable_reason(audit_run)
        for finding in findings:
            if any(
                verification.method == VerificationMethod.DYNAMIC_POC.value
                for verification in finding.verifications
            ):
                continue
            outcome = outcomes.get(str(finding.id))
            if outcome is None:
                service.record_verification(
                    finding,
                    method=VerificationMethod.DYNAMIC_POC,
                    verdict=VerificationVerdict.INCONCLUSIVE,
                    verifier=DYNAMIC_VERIFIER_NAME,
                    reasoning=detail,
                )
                continue
            service.record_verification(
                finding,
                method=VerificationMethod.DYNAMIC_POC,
                verdict=VerificationVerdict(outcome.verdict),
                verifier=DYNAMIC_VERIFIER_NAME,
                reasoning=outcome.detail,
            )
            self._record_probe_evidence(finding, outcome, service)
        if findings and not outcomes:
            self._add_warning(
                coverage,
                reason_code,
                tool=DYNAMIC_VERIFIER_NAME,
                task_id=audit_run.id,
            )
        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 85
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.MACHINE_REVIEW,
        )

    def _author_pocs(
        self,
        audit_run: AuditRun,
        findings: list[Finding],
        coverage: AuditCoverage,
        budget: DynamicBudget,
    ) -> list[PocPlanSpec]:
        """Author PoCs for critical/high findings the built-in probes miss.

        The author sees the model and the source and never the target — the
        application does not exist yet. Its plans are validated against the
        contract on return; a finding whose author produced no usable plan is
        simply absent from the result and stays inconclusive.
        """

        by_fingerprint = self._discovered_by_fingerprint(audit_run)
        candidates = [
            finding
            for finding in sorted(findings, key=lambda item: item.fingerprint)
            if FindingSeverity(finding.severity) in REVIEW_REQUIRED_SEVERITIES
            and finding.category not in PROBEABLE_CATEGORIES
        ]
        if not candidates:
            return []

        entrypoints = self._entrypoints_by_path(audit_run)
        plans: list[PocPlanSpec] = []
        authored = 0
        for finding in candidates:
            if authored >= budget.max_authored_pocs:
                self._add_warning(
                    coverage,
                    POC_TRUNCATION_REASON,
                    tool=POC_AUTHOR_TOOL,
                    task_id=audit_run.id,
                )
                break
            plan = self._author_one_poc(
                audit_run,
                finding,
                entrypoints,
                budget,
                by_fingerprint.get(finding.fingerprint, [finding.discovered_by]),
            )
            authored += 1
            if plan is not None:
                plans.append(plan)
        return plans

    def _author_one_poc(
        self,
        audit_run: AuditRun,
        finding: Finding,
        entrypoints: dict[str, list[dict[str, object]]],
        budget: DynamicBudget,
        tools: list[str],
    ) -> PocPlanSpec | None:
        del tools
        # The author is a model conversation, so its grant is sized by a
        # conversation budget, not by the environment budget that governs how
        # many findings are probed. The verification budget's shape
        # (turns, output tokens per task) is exactly right and already read from
        # policy for the blind reviewer.
        grant_budget = VerificationBudget.from_policy(
            getattr(getattr(audit_run, "policy", None), "verification_budget", None)
        )
        task = get_or_create_poc_task(self.session, audit_run, finding)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
            AuditTaskStatus.SKIPPED.value,
        }:
            artifacts = self._task_artifacts(task)
            if not artifacts:
                return None
            try:
                result = SandboxArtifactRegistrar(
                    self.session, self.artifact_store
                ).load_poc_result(artifacts[-1], expected_finding_id=str(finding.id))
            except OrchestratorError:
                return None
            return self._poc_plan_spec(finding, result)

        task.status = AuditTaskStatus.RUNNING.value
        task.worker_name = f"{self.settings.orchestrator_worker_name}:poc-author"
        task.attempt += 1
        task.started_at = task.started_at or datetime.now(UTC)
        task.finished_at = None
        task.error_code = None
        self.session.commit()

        snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
        if snapshot is None:
            raise OrchestratorError(
                "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                "AuditTask Snapshot is unavailable",
            )
        try:
            request = SandboxCreateRequest(
                template=SandboxTemplateName.SEMANTIC,
                operation=SandboxOperation.AUTHOR_POC,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(timeout_seconds=task.timeout_seconds),
                semantic=SemanticSandboxSpec(
                    grant_token=self._mint_grant(audit_run, task, grant_budget),
                    gateway_url=self.settings.llm_gateway_url,
                    poc=self._poc_assignment(finding, entrypoints),
                ),
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return None

        sandbox_record = self._drive_model_sandbox(
            audit_run, task, request, missing_result_code="POC_RESULT_MISSING"
        )
        if sandbox_record is None:
            return None

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task, sandbox_record.artifacts[0], kind=ArtifactKind.SCAN_RESULT
            )
            result = registrar.load_poc_result(
                artifact, expected_finding_id=str(finding.id)
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return None

        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if result.status == "completed":
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = result.reason_code
        self.session.commit()
        return self._poc_plan_spec(finding, result)

    def _poc_assignment(
        self,
        finding: Finding,
        entrypoints: dict[str, list[dict[str, object]]],
    ) -> PocAssignmentSpec:
        record = self._entrypoint_record(finding, entrypoints)
        annotations = (record or {}).get("annotations")
        annotation = (
            str(annotations[0])
            if isinstance(annotations, list) and annotations
            else "RequestMapping"
        )
        return PocAssignmentSpec(
            finding_id=str(finding.id),
            module=(
                PurePosixPath(finding.locations[0].file_path).parts[0]
                if finding.locations
                else "."
            ),
            category=finding.category,
            cwe_ids=[finding.cwe_id],
            sink=None,
            http_method=_POC_METHOD_BY_ANNOTATION.get(annotation, "GET"),
            route=str(record["route"]) if record and record.get("route") else None,
            route_prefixes=self._route_prefixes(record, entrypoints),
            locations=[
                VerifyLocationSpec(
                    path=location.file_path,
                    start_line=location.start_line,
                    end_line=location.end_line,
                    symbol=location.symbol,
                    role=location.role,
                )
                for location in finding.locations[:MAX_VERIFY_LOCATIONS]
            ],
        )

    def _poc_plan_spec(
        self,
        finding: Finding,
        result: PocResult,
    ) -> PocPlanSpec | None:
        if result.plan is None:
            return None
        payload = result.plan.model_dump(mode="json")
        payload["finding_id"] = str(finding.id)
        try:
            return PocPlanSpec.model_validate(payload)
        except ValidationError:
            # The plan validated inside the sandbox but not against the wire
            # spec here — a version skew, say. Treat it as no plan rather than
            # trusting a shape the executor's contract did not accept.
            return None

    def _entrypoints_by_path(
        self,
        audit_run: AuditRun,
    ) -> dict[str, list[dict[str, object]]]:
        mapping: dict[str, list[dict[str, object]]] = {}
        for record in self._inventory_payload(audit_run)["entrypoints"]:
            if isinstance(record, dict) and record.get("path"):
                mapping.setdefault(str(record["path"]), []).append(record)
        return mapping

    def _entrypoint_record(
        self,
        finding: Finding,
        entrypoints: dict[str, list[dict[str, object]]],
    ) -> dict[str, object] | None:
        for location in finding.locations:
            for record in entrypoints.get(location.file_path, []):
                if record.get("route"):
                    return record
        return None

    def _route_prefixes(
        self,
        record: dict[str, object] | None,
        entrypoints: dict[str, list[dict[str, object]]],
    ) -> list[str]:
        if record is None:
            return []
        path = str(record.get("path") or "")
        prefixes: list[str] = []
        for sibling in entrypoints.get(path, []):
            route = sibling.get("route")
            if route and sibling is not record and str(route) not in prefixes:
                prefixes.append(str(route))
        return prefixes[:8]

    def _run_dynamic_environment(
        self,
        audit_run: AuditRun,
        findings: list[Finding],
        coverage: AuditCoverage,
    ) -> dict[str, ProbeOutcome]:
        """Stand the application up once and probe every probeable Finding.

        Returns the outcomes keyed by Finding id, empty when the environment
        could not be built. An empty result is not a failure: the caller records
        the §7.7 inconclusive verdict and the run continues.
        """

        self._dynamic_task_id = None
        policy = getattr(audit_run, "policy", None)
        if getattr(policy, "dynamic_verification", None) == (
            DynamicVerificationMode.DISABLED.value
        ):
            return {}

        runtime_plan = self._runtime_plan(audit_run)
        runnable = self._runnable_artifact(audit_run)
        if runnable is None:
            # §7.3: a build that produced nothing runnable marks dynamic
            # verification unavailable rather than failing the run.
            self._add_warning(
                coverage,
                "DYNAMIC_BUILD_ARTIFACT_MISSING",
                tool=DYNAMIC_VERIFIER_NAME,
                task_id=audit_run.id,
            )
            return {}
        build_artifact, app_jar = runnable

        budget = DynamicBudget.from_policy(
            getattr(policy, "dynamic_budget", None)
        )
        plan = plan_probe_targets(
            findings,
            self._inventory_payload(audit_run)["entrypoints"],
            budget=budget,
        )
        if plan.truncated:
            self._add_warning(
                coverage,
                DYNAMIC_TRUNCATION_REASON,
                tool=DYNAMIC_VERIFIER_NAME,
                task_id=audit_run.id,
            )
        # Findings whose category the built-in probes do not cover get a
        # model-authored PoC, written before the environment stands up. The
        # author runs on the semantic template with no target network; the
        # plans it produces run here, in the same one environment as the
        # deterministic probes.
        poc_plans = self._author_pocs(audit_run, findings, coverage, budget)
        if not plan.targets and not poc_plans:
            return {}

        task = get_or_create_dynamic_task(self.session, audit_run)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        self._dynamic_task_id = task.id
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
            AuditTaskStatus.SKIPPED.value,
        }:
            artifacts = self._task_artifacts(task)
            if not artifacts:
                return {}
            try:
                result = SandboxArtifactRegistrar(
                    self.session,
                    self.artifact_store,
                ).load_dynamic_result(artifacts[-1])
            except OrchestratorError:
                return {}
            return self._outcomes_by_finding(result, coverage, task)

        task.status = AuditTaskStatus.RUNNING.value
        task.worker_name = f"{self.settings.orchestrator_worker_name}:dynamic-verifier"
        task.attempt += 1
        task.started_at = task.started_at or datetime.now(UTC)
        task.finished_at = None
        task.error_code = None
        self.session.commit()

        snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
        if snapshot is None:
            raise OrchestratorError(
                "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                "AuditTask Snapshot is unavailable",
            )
        services = [
            ServiceKind(name)
            for name in runtime_plan.get("services", [])
            if name in {kind.value for kind in ServiceKind}
        ]
        # The echo service is the platform's own out-of-band target, not
        # something the application asked for, so it is always present.
        if ServiceKind.ECHO not in services:
            services.append(ServiceKind.ECHO)
        try:
            request = SandboxCreateRequest(
                template=SandboxTemplateName.VALIDATION,
                operation=SandboxOperation.DEFAULT,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(
                    timeout_seconds=budget.environment_timeout_seconds,
                ),
                dynamic=DynamicSandboxSpec(
                    build_output=SnapshotArtifact(
                        storage_key=build_artifact.storage_key,
                        sha256=build_artifact.sha256,
                        size_bytes=build_artifact.size_bytes,
                    ),
                    app_jar=app_jar,
                    app_port=int(runtime_plan.get("app_port") or 8080),
                    services=services,
                    targets=list(plan.targets),
                    poc_plans=poc_plans,
                ),
            )
        except (OrchestratorError, ValueError) as exc:
            self._queue_or_fail_task(task, "DYNAMIC_PLAN_INVALID", False)
            LOG.warning("dynamic verification plan rejected: %s", exc)
            return {}

        sandbox_record = self._drive_model_sandbox(
            audit_run,
            task,
            request,
            missing_result_code="DYNAMIC_RESULT_MISSING",
        )
        if sandbox_record is None:
            return {}

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task,
                sandbox_record.artifacts[0],
                kind=ArtifactKind.RUNTIME_LOG,
            )
            result = registrar.load_dynamic_result(artifact)
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return {}

        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if result.status is ToolStatus.COMPLETED:
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = result.reason_code
        self.session.commit()

        self._assert_environment_destroyed(sandbox_record.id, coverage, task)
        return self._outcomes_by_finding(result, coverage, task)

    def _outcomes_by_finding(
        self,
        result: DynamicResult,
        coverage: AuditCoverage,
        task: AuditTask,
    ) -> dict[str, ProbeOutcome]:
        if result.status is not ToolStatus.COMPLETED and result.reason_code:
            self._add_warning(
                coverage,
                result.reason_code,
                tool=DYNAMIC_VERIFIER_NAME,
                task_id=task.id,
            )
        for outcome in result.outcomes:
            if outcome.verdict == "inconclusive" and outcome.reason_code:
                self._add_warning(
                    coverage,
                    outcome.reason_code,
                    tool=f"{DYNAMIC_VERIFIER_NAME}:{outcome.category}",
                    task_id=task.id,
                )
        return {outcome.finding_id: outcome for outcome in result.outcomes}

    def _assert_environment_destroyed(
        self,
        sandbox_id: UUID,
        coverage: AuditCoverage,
        task: AuditTask,
    ) -> None:
        """§13.6: after destruction the target service must be unreachable.

        Asked of the Sandbox API rather than assumed, because "we called
        destroy" and "nothing is left running" are different claims and only the
        second is the acceptance criterion.
        """

        try:
            record = self.sandbox.get(sandbox_id)
        except OrchestratorError:
            # The sandbox is gone entirely, which is the strongest form of the
            # property holding.
            return
        if not record.resources_destroyed:
            self._add_warning(
                coverage,
                "DYNAMIC_ENVIRONMENT_NOT_DESTROYED",
                tool=DYNAMIC_VERIFIER_NAME,
                task_id=task.id,
            )

    def _runtime_plan(self, audit_run: AuditRun) -> dict[str, object]:
        for fact in self.session.scalars(
            select(AuditFact).where(
                AuditFact.audit_run_id == audit_run.id,
                AuditFact.kind == AuditFactKind.ARCHITECTURE.value,
            )
        ):
            plan = fact.structured_payload.get("runtime_plan")
            if isinstance(plan, dict):
                return plan
        return {}

    def _runnable_artifact(
        self,
        audit_run: AuditRun,
    ) -> tuple[Artifact, str] | None:
        """The build Artifact and the archive path inside it, if there is one."""

        task = self.session.scalar(
            select(AuditTask).where(
                AuditTask.audit_run_id == audit_run.id,
                AuditTask.scope_key == TASK_SPECS[AnalysisOperation.BUILD].scope_key,
            )
        )
        if task is None:
            return None
        artifacts = self._task_artifacts(task)
        if not artifacts:
            return None
        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        for artifact in reversed(artifacts):
            try:
                manifest = registrar.load_manifest(
                    artifact,
                    expected_operation=AnalysisOperation.BUILD,
                )
            except OrchestratorError:
                continue
            if manifest.build is None or not manifest.build.runnable_artifacts:
                continue
            # The first archive in module order; a multi-module repository that
            # packages several is verified through its first, and the rest are
            # reported as unprobed rather than silently ignored.
            return artifact, manifest.build.runnable_artifacts[0].path
        return None

    def _record_probe_evidence(
        self,
        finding: Finding,
        outcome: ProbeOutcome,
        service: FindingService,
    ) -> None:
        """Save the request, response and timing §7.7 requires.

        Stored as evidence text rather than only as a verdict, because "the
        payload took 5.2 s longer than the baseline" is the part a reviewer has
        to be able to check.
        """

        task_id = self._dynamic_task_id
        if task_id is None:
            return
        for label, exchange in (
            ("baseline", outcome.baseline),
            ("payload", outcome.payload),
        ):
            if exchange is None:
                continue
            service.record_evidence(
                finding,
                evidence_type=EvidenceType.HTTP_EXCHANGE,
                summary=(
                    f"{label}: {exchange.method} {exchange.url} -> "
                    f"{exchange.status_code} in {exchange.elapsed_ms} ms"
                    f"{' (echo hit)' if label == 'payload' and outcome.echo_observed else ''}"
                )[:2048],
                produced_by_task_id=task_id,
            )

    def _dynamic_unavailable_reason(self, audit_run: AuditRun) -> tuple[str, str]:
        policy = getattr(audit_run, "policy", None)
        mode = getattr(policy, "dynamic_verification", None)
        if mode == DynamicVerificationMode.DISABLED.value:
            return (
                "DYNAMIC_VERIFICATION_DISABLED",
                "The audit policy disables dynamic verification, so no runtime "
                "evidence was gathered for this finding.",
            )
        return (
            "DYNAMIC_ENVIRONMENT_UNAVAILABLE",
            "No dynamic verification environment was available, so the finding "
            "could not be exercised at runtime. Per §7.7 an unavailable "
            "environment yields an inconclusive verdict and never a rejection.",
        )

    def _promote_findings(
        self,
        audit_run: AuditRun,
        coverage: AuditCoverage,
        service: FindingService,
    ) -> list[Finding]:
        """Run the Finding Pipeline over this run's candidate facts (§6.14)."""

        facts = list(
            self.session.scalars(
                select(AuditFact).where(
                    AuditFact.audit_run_id == audit_run.id,
                    AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
                )
            )
        )
        candidates: list[dict[str, object]] = []
        by_fingerprint: dict[str, AuditFact] = {}
        for fact in facts:
            candidate = fact.structured_payload.get("candidate")
            if not isinstance(candidate, dict):
                continue
            candidates.append(candidate)
            by_fingerprint[str(candidate.get("fingerprint"))] = fact
        if not candidates:
            return []

        snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
        if snapshot is None:
            raise OrchestratorError(
                "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                "A ready Snapshot is required to promote candidates",
            )
        try:
            archive_path = self.artifact_store.resolve(
                snapshot.artifact.storage_key,
                expected_sha256=snapshot.artifact.sha256,
                expected_size=snapshot.artifact.size_bytes,
            )
        except Exception as exc:  # noqa: BLE001 - store raises its own hierarchy
            raise OrchestratorError(
                "PIPELINE_SNAPSHOT_UNAVAILABLE",
                "The Snapshot Artifact could not be read",
            ) from exc

        result = promote_candidates(
            candidates,
            audit_run_id=audit_run.id,
            archive_path=archive_path,
            snapshot_sha256=snapshot.content_sha256,
        )
        for rejection in result.rejections:
            # A discarded candidate is a coverage gap, not a silent drop.
            self._add_warning(
                coverage,
                rejection.reason_code,
                tool=PIPELINE_TOOL_NAME,
                task_id=audit_run.id,
            )

        findings: list[Finding] = []
        for command in result.commands:
            finding = service.promote(command)
            findings.append(finding)
            fact = by_fingerprint.get(command.fingerprint)
            if fact is None:
                continue
            for raw_id in fact.evidence_ids[:MAX_EVIDENCE_PER_FINDING]:
                try:
                    artifact_id = UUID(str(raw_id))
                except (TypeError, ValueError):
                    continue
                service.record_evidence(
                    finding,
                    evidence_type=EvidenceType.TOOL_RESULT,
                    summary=(
                        "Raw tool output the candidate was normalised from "
                        f"({command.discovered_by})."
                    ),
                    produced_by_task_id=fact.created_by_task_id,
                    artifact_id=artifact_id,
                )
        self.session.commit()
        return findings

    def _machine_review(self, audit_run: AuditRun) -> None:
        """Run independent blind review and settle each Finding (§7.8, §13.6).

        Critical and high findings are reviewed by a worker that never sees the
        original's reasoning. Everything else is settled on what it already has:
        §7.9 does not force medium and below through human confirmation, so they
        stop at ``machine_confirmed``.
        """

        coverage = self._coverage(audit_run)
        service = FindingService(self.session)
        budget = VerificationBudget.from_policy(
            getattr(getattr(audit_run, "policy", None), "verification_budget", None)
        )
        discovered_by = self._discovered_by_fingerprint(audit_run)

        findings = list(
            self.session.scalars(
                select(Finding).where(
                    Finding.audit_run_id == audit_run.id,
                    Finding.status == FindingStatus.VALIDATING.value,
                )
            )
        )
        # Severity first, then fingerprint: a truncated budget must spend itself
        # on the most serious findings, reproducibly.
        findings.sort(
            key=lambda item: (
                -_SEVERITY_RANK.get(item.severity, 0),
                item.fingerprint,
            )
        )

        reviewed = 0
        for finding in findings:
            severity = FindingSeverity(finding.severity)
            tools = discovered_by.get(finding.fingerprint, [finding.discovered_by])
            blind_verdict: VerificationVerdict | None = None
            if severity in REVIEW_REQUIRED_SEVERITIES:
                if reviewed >= budget.max_findings:
                    blind_verdict = VerificationVerdict.INCONCLUSIVE
                    service.record_verification(
                        finding,
                        method=VerificationMethod.INDEPENDENT_AGENT,
                        verdict=blind_verdict,
                        verifier=VERIFY_TOOL_NAME,
                        reasoning=(
                            "The run's independent-review budget of "
                            f"{budget.max_findings} findings was exhausted "
                            "before this finding was reached."
                        ),
                        discovered_by=tools,
                    )
                    self._add_warning(
                        coverage,
                        VERIFY_TRUNCATION_REASON,
                        tool=VERIFY_TOOL_NAME,
                        task_id=audit_run.id,
                    )
                else:
                    blind_verdict = self._review_finding(
                        audit_run,
                        finding,
                        coverage,
                        service,
                        budget,
                        tools,
                    )
                    reviewed += 1

            dynamic_verdict = self._dynamic_verdict(finding)
            decision = decide(
                severity=severity,
                blind_verdict=blind_verdict,
                dynamic_verdict=dynamic_verdict,
                discovered_by_count=len(set(tools)),
                cwe_id=finding.cwe_id,
            )
            finding.runtime_verification = decision.runtime_verification.value
            if decision.confidence is not None:
                finding.confidence = decision.confidence.value
            service.transition(finding, decision.status)
            if decision.warning_code is not None:
                self._add_warning(
                    coverage,
                    decision.warning_code,
                    tool=f"{VERIFY_TOOL_NAME}:{finding.category}",
                    task_id=audit_run.id,
                )
            if decision.enters_human_queue:
                service.enter_human_queue(finding)
            audit_run.warning_count = len(coverage.coverage_warnings)
            self.session.commit()

        self._conclude_intents(audit_run)
        audit_run.warning_count = len(coverage.coverage_warnings)
        audit_run.progress = 90
        self.session.commit()
        AuditRunService(self.session).transition(
            audit_run.id,
            AuditRunStatus.HUMAN_REVIEW,
        )

    def _dynamic_verdict(self, finding: Finding) -> VerificationVerdict:
        """The strongest dynamic verdict on record, defaulting to inconclusive.

        Read back rather than assumed, so 6b's real runtime verdicts flow into
        the decision without this stage changing.
        """

        verdicts = {
            verification.verdict
            for verification in finding.verifications
            if verification.method == VerificationMethod.DYNAMIC_POC.value
        }
        if VerificationVerdict.CONFIRMED.value in verdicts:
            return VerificationVerdict.CONFIRMED
        if VerificationVerdict.REJECTED.value in verdicts:
            return VerificationVerdict.REJECTED
        return VerificationVerdict.INCONCLUSIVE

    def _discovered_by_fingerprint(self, audit_run: AuditRun) -> dict[str, list[str]]:
        """The authoritative tool list per candidate.

        ``Finding.discovered_by`` is a display string bounded to 255 characters;
        the corroboration count and the independence check both key on the full
        list, which lives on the candidate fact.
        """

        mapping: dict[str, list[str]] = {}
        for fact in self.session.scalars(
            select(AuditFact).where(
                AuditFact.audit_run_id == audit_run.id,
                AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
            )
        ):
            candidate = fact.structured_payload.get("candidate")
            if not isinstance(candidate, dict):
                continue
            tools = candidate.get("discovered_by")
            if isinstance(tools, list) and tools:
                mapping[str(candidate.get("fingerprint"))] = [
                    str(tool) for tool in tools
                ]
        return mapping

    def _review_finding(
        self,
        audit_run: AuditRun,
        finding: Finding,
        coverage: AuditCoverage,
        service: FindingService,
        budget: VerificationBudget,
        tools: list[str],
    ) -> VerificationVerdict:
        """Run one blind review and record its verdict.

        Never returns ``REJECTED`` for anything that went wrong. A failed task,
        a refusal, an unparseable answer and a missing verdict all become
        ``INCONCLUSIVE``, so a reviewer that could not do its job cannot delete
        a candidate.
        """

        task, result, artifacts = self._execute_independent_review(
            audit_run,
            finding,
            budget,
        )
        if result is None or result.verdict is None:
            reason = (
                (result.reason_code if result is not None else None)
                or task.error_code
                or "VERIFY_REVIEW_FAILED"
            )
            self._add_warning(
                coverage,
                reason,
                tool=f"{VERIFY_TOOL_NAME}:{finding.category}",
                task_id=task.id,
            )
            service.record_verification(
                finding,
                method=VerificationMethod.INDEPENDENT_AGENT,
                verdict=VerificationVerdict.INCONCLUSIVE,
                verifier=VERIFY_TOOL_NAME,
                reasoning=(
                    "The independent review did not conclude "
                    f"({reason}). An unusable review yields inconclusive, "
                    "never a rejection."
                ),
                discovered_by=tools,
            )
            return VerificationVerdict.INCONCLUSIVE

        evidence_ids: list[UUID] = []
        for artifact in artifacts:
            evidence = service.record_evidence(
                finding,
                evidence_type=EvidenceType.TOOL_RESULT,
                summary="Independent blind review transcript and verdict.",
                produced_by_task_id=task.id,
                artifact_id=artifact.id,
                sha256=artifact.sha256,
            )
            self.session.flush()
            evidence_ids.append(evidence.id)
        service.record_verification(
            finding,
            method=VerificationMethod.INDEPENDENT_AGENT,
            verdict=VerificationVerdict(result.verdict.verdict),
            verifier=VERIFY_TOOL_NAME,
            reasoning=result.verdict.reasoning,
            evidence_ids=evidence_ids,
            discovered_by=tools,
        )
        # The reviewer downgrades its own unsupported claims (a confirmation
        # with no rebuilt chain, a rejection naming no control). Those are
        # coverage facts, not internal details.
        for warning in result.warnings:
            reason_code = warning.get("reason_code")
            if isinstance(reason_code, str) and reason_code:
                self._add_warning(
                    coverage,
                    reason_code,
                    tool=f"{VERIFY_TOOL_NAME}:{finding.category}",
                    task_id=task.id,
                )
        return VerificationVerdict(result.verdict.verdict)

    def _execute_independent_review(
        self,
        audit_run: AuditRun,
        finding: Finding,
        budget: VerificationBudget,
    ) -> tuple[AuditTask, VerifyResult | None, list[Artifact]]:
        task = get_or_create_verify_task(self.session, audit_run, finding)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        root_cause_key = self._root_cause_key(audit_run, finding)
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
            AuditTaskStatus.SKIPPED.value,
        }:
            artifacts = self._task_artifacts(task)
            if not artifacts:
                return task, None, []
            try:
                result = SandboxArtifactRegistrar(
                    self.session,
                    self.artifact_store,
                ).load_verify_result(
                    artifacts[-1],
                    expected_root_cause_key=root_cause_key,
                )
            except OrchestratorError:
                return task, None, artifacts
            return task, result, artifacts

        task.status = AuditTaskStatus.RUNNING.value
        # A distinct worker identity from the semantic stage: §6.10 forbids the
        # discovering worker from reviewing its own finding, and an identity
        # shared with the discoverer would make that unenforceable.
        task.worker_name = f"{self.settings.orchestrator_worker_name}:independent-verifier"
        task.attempt += 1
        task.started_at = task.started_at or datetime.now(UTC)
        task.finished_at = None
        task.error_code = None
        task.error_detail = None
        self.session.commit()

        snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
        if snapshot is None:
            raise OrchestratorError(
                "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                "AuditTask Snapshot is unavailable",
            )
        try:
            request = SandboxCreateRequest(
                template=SandboxTemplateName.SEMANTIC,
                operation=SandboxOperation.INDEPENDENT_VERIFY,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(timeout_seconds=task.timeout_seconds),
                semantic=SemanticSandboxSpec(
                    grant_token=self._mint_grant(audit_run, task, budget),
                    gateway_url=self.settings.llm_gateway_url,
                    candidate=self._verify_candidate(finding, root_cause_key),
                ),
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return task, None, []

        sandbox_record = self._drive_model_sandbox(
            audit_run,
            task,
            request,
            missing_result_code="VERIFY_RESULT_MISSING",
        )
        if sandbox_record is None:
            return task, None, []

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task,
                sandbox_record.artifacts[0],
                kind=ArtifactKind.SCAN_RESULT,
            )
            result = registrar.load_verify_result(
                artifact,
                expected_root_cause_key=root_cause_key,
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return task, None, self._task_artifacts(task)

        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if result.status is ToolStatus.COMPLETED:
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = result.reason_code
        self.session.commit()
        return task, result, self._task_artifacts(task)

    def _root_cause_key(self, audit_run: AuditRun, finding: Finding) -> str:
        for fact in self.session.scalars(
            select(AuditFact).where(
                AuditFact.audit_run_id == audit_run.id,
                AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
            )
        ):
            candidate = fact.structured_payload.get("candidate")
            if (
                isinstance(candidate, dict)
                and str(candidate.get("fingerprint")) == finding.fingerprint
            ):
                return str(candidate.get("root_cause_key") or finding.fingerprint)
        return finding.fingerprint

    def _verify_candidate(
        self,
        finding: Finding,
        root_cause_key: str,
    ) -> VerifyCandidateSpec:
        """Build the blind assignment.

        Only fields this spec declares are readable, and it declares none of the
        reporting worker's prose — so this method could not leak the original's
        reasoning even by accident.
        """

        module = (
            PurePosixPath(finding.locations[0].file_path).parts[0]
            if finding.locations
            else "."
        )
        return VerifyCandidateSpec(
            root_cause_key=root_cause_key,
            module=module or ".",
            category=finding.category,
            cwe_ids=[finding.cwe_id],
            sink=None,
            locations=[
                VerifyLocationSpec(
                    path=location.file_path,
                    start_line=location.start_line,
                    end_line=location.end_line,
                    symbol=location.symbol,
                    role=location.role,
                )
                for location in finding.locations[:MAX_VERIFY_LOCATIONS]
            ],
        )

    def _conclude_intents(self, audit_run: AuditRun) -> None:
        """Close the intents the semantic stage opened (§6.14).

        An intent left `pending` after machine review would read as work still
        owed. Nothing downstream re-derives the plan, so concluding them here is
        what makes the graph an accurate record of what was decided.
        """

        now = datetime.now(UTC)
        for intent in self.session.scalars(
            select(AuditIntent).where(
                AuditIntent.audit_run_id == audit_run.id,
                AuditIntent.status == AuditIntentStatus.PENDING.value,
            )
        ):
            intent.status = AuditIntentStatus.CONCLUDED.value
            intent.concluded_at = now

    def _semantic_policy(self, audit_run: AuditRun) -> object:
        policy = getattr(audit_run, "policy", None)
        return getattr(policy, "semantic_budget", None)

    def _inventory_payload(self, audit_run: AuditRun) -> dict[str, object]:
        """Reassemble the index the way `plan_semantic_reviews` expects it.

        `_persist_inventory` splits one InventoryResult across four AuditFact
        kinds; the planner wants them back together, and reading the facts
        avoids re-downloading and re-parsing the inventory Artifact.
        """

        facts = {
            fact.kind: fact.structured_payload
            for fact in self.session.scalars(
                select(AuditFact).where(AuditFact.audit_run_id == audit_run.id)
            )
        }
        architecture = facts.get(AuditFactKind.ARCHITECTURE.value) or {}
        entrypoints = facts.get(AuditFactKind.ENTRYPOINT.value) or {}
        sinks = facts.get(AuditFactKind.SINK.value) or {}
        return {
            "modules": architecture.get("modules", []),
            "permissions": architecture.get("permissions", []),
            "entrypoints": entrypoints.get("items", []),
            "sinks": sinks.get("items", []),
        }

    def _persist_semantic_result(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        scope: ReviewScope,
        result: SemanticReviewResult,
        artifacts: list[Artifact],
    ) -> None:
        facts = self._persist_candidates(
            audit_run,
            task,
            [candidate.model_dump(mode="json") for candidate in result.candidates],
            artifacts,
        )
        self._record_intent(audit_run, task, scope, facts)

    def _record_intent(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        scope: ReviewScope,
        facts: list[AuditFact],
    ) -> None:
        """Record what this scope concluded, for dynamic verification to claim.

        One intent per scope, whether or not it produced candidates: "this
        surface was reviewed for this category and nothing was found" is itself
        a result the later stages need, and it is what stops verification from
        re-deriving the plan.
        """

        existing = self.session.scalar(
            select(AuditIntent).where(
                AuditIntent.audit_run_id == audit_run.id,
                AuditIntent.created_by_task_id == task.id,
            )
        )
        if existing is None:
            existing = AuditIntent(
                audit_run_id=audit_run.id,
                category=scope.category[:255],
                scope=scope.model_dump(mode="json"),
                required_capabilities=[f"verify:{scope.category}"],
                status=AuditIntentStatus.PENDING.value,
                created_by_task_id=task.id,
            )
            self.session.add(existing)
            self.session.flush()
        linked = {
            link.audit_fact_id
            for link in self.session.scalars(
                select(AuditIntentSource).where(
                    AuditIntentSource.audit_intent_id == existing.id
                )
            )
        }
        for fact in facts:
            if fact.id is None:
                self.session.flush()
            if fact.id in linked:
                continue
            self.session.add(
                AuditIntentSource(
                    audit_intent_id=existing.id,
                    audit_fact_id=fact.id,
                )
            )
            linked.add(fact.id)

    def _mint_grant(self, audit_run: AuditRun, task: AuditTask, budget) -> str:
        """Issue the short-lived model grant for exactly one review task.

        The Orchestrator holds the grant SIGNING key and never the model API
        key (§5.1): this token authorises a bounded number of requests against
        one model for one task, and expires with the task's own timeout. It is
        returned to the caller and never logged, persisted or written to an
        AuditTask column.
        """

        key = self._grant_key()
        expires_at = datetime.now(UTC) + timedelta(
            seconds=task.timeout_seconds + self.settings.llm_grant_ttl_margin_seconds
        )
        return mint_grant(
            ModelGrant(
                audit_run_id=str(audit_run.id),
                task_id=str(task.id),
                worker=self.settings.orchestrator_worker_name,
                model=SEMANTIC_MODEL,
                expires_at=expires_at,
                # Each turn is one request; the ceiling has to cover the tool
                # loop plus the final structured answer.
                max_requests=budget.max_turns_per_task + 2,
                max_output_tokens=budget.max_output_tokens_per_task
                * (budget.max_turns_per_task + 2),
            ),
            key,
        )

    def _grant_key(self) -> bytes:
        path = self.settings.llm_grant_key_file
        if path is None:
            raise OrchestratorError(
                "SEMANTIC_GRANT_KEY_UNAVAILABLE",
                "The Orchestrator has no LLM grant signing key configured",
            )
        try:
            return read_key_file(path)
        except (OSError, ValueError) as exc:
            raise OrchestratorError(
                "SEMANTIC_GRANT_KEY_UNAVAILABLE",
                "The LLM grant signing key cannot be read",
            ) from exc

    def _execute_semantic_scope(
        self,
        audit_run: AuditRun,
        scope: ReviewScope,
        budget,
    ) -> tuple[AuditTask, SemanticReviewResult | None, list[Artifact]]:
        task = get_or_create_semantic_task(self.session, audit_run, scope)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
            AuditTaskStatus.SKIPPED.value,
        }:
            # Already settled on an earlier pass; recover the result rather
            # than paying for the conversation again.
            artifacts = self._task_artifacts(task)
            if not artifacts:
                return task, None, []
            try:
                result = SandboxArtifactRegistrar(
                    self.session,
                    self.artifact_store,
                ).load_semantic_result(
                    artifacts[-1],
                    expected_scope_key=scope.scope_key,
                )
            except OrchestratorError:
                return task, None, artifacts
            return task, result, artifacts

        task.status = AuditTaskStatus.RUNNING.value
        task.worker_name = self.settings.orchestrator_worker_name
        task.attempt += 1
        task.started_at = task.started_at or datetime.now(UTC)
        task.finished_at = None
        task.error_code = None
        task.error_detail = None
        self.session.commit()

        snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
        if snapshot is None:
            raise OrchestratorError(
                "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                "AuditTask Snapshot is unavailable",
            )
        try:
            request = SandboxCreateRequest(
                template=SandboxTemplateName.SEMANTIC,
                operation=SandboxOperation.SEMANTIC,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(timeout_seconds=task.timeout_seconds),
                semantic=SemanticSandboxSpec(
                    grant_token=self._mint_grant(audit_run, task, budget),
                    gateway_url=self.settings.llm_gateway_url,
                    scope=SemanticScopeSpec(
                        module=scope.module,
                        attack_surface=scope.attack_surface,
                        category=scope.category,
                        scope_key=scope.scope_key,
                        entrypoint_paths=list(scope.entrypoint_paths),
                    ),
                ),
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return task, None, []

        sandbox_record = self._drive_model_sandbox(
            audit_run,
            task,
            request,
            missing_result_code="SEMANTIC_RESULT_MISSING",
        )
        if sandbox_record is None:
            return task, None, []

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task,
                sandbox_record.artifacts[0],
                kind=ArtifactKind.SCAN_RESULT,
            )
            result = registrar.load_semantic_result(
                artifact,
                expected_scope_key=scope.scope_key,
            )
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, False)
            return task, None, self._task_artifacts(task)

        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if result.status is ToolStatus.COMPLETED:
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        elif result.status is ToolStatus.SKIPPED:
            task.status = AuditTaskStatus.SKIPPED.value
            task.error_code = result.reason_code
        else:
            # A refusal or an unavailable model is a settled outcome for this
            # scope, not a run failure.
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = result.reason_code
        self.session.commit()
        return task, result, self._task_artifacts(task)

    def _drive_model_sandbox(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        request: SandboxCreateRequest,
        *,
        missing_result_code: str,
    ) -> SandboxRecord | None:
        """Create, start, await and tear down one model-backed sandbox.

        Shared by the Semantic Reviewer and the Independent Reviewer: both run
        one conversation in one container and produce exactly one output
        Artifact, and the failure handling — queue-or-fail the task, destroy on
        every exit path, honour a cancellation request mid-wait — has to be
        identical or one of them will leak a container.

        Returns ``None`` after settling the task when anything went wrong, so
        the caller reads a ``None`` as "already recorded, move on".
        """

        try:
            sandbox_record = self.sandbox.create(request)
        except OrchestratorError as exc:
            self._queue_or_fail_task(task, exc.error_code, exc.retryable)
            return None
        task.sandbox_id = sandbox_record.id
        self.session.commit()
        try:
            sandbox_record = self.sandbox.start(sandbox_record.id)
        except OrchestratorError as exc:
            try:
                self.sandbox.destroy(sandbox_record.id)
            except OrchestratorError:
                pass
            self._queue_or_fail_task(task, exc.error_code, exc.retryable)
            return None

        while sandbox_record.status in ACTIVE_SANDBOX_STATUSES:
            if self._cancellation_requested(audit_run.id):
                sandbox_record = self.sandbox.cancel(sandbox_record.id)
                task.status = AuditTaskStatus.CANCELLED.value
                task.error_code = "AUDIT_RUN_CANCELLED"
                task.finished_at = datetime.now(UTC)
                self.session.commit()
                self._cancel_run(self._run(audit_run.id))
                raise _RunCancelled
            sandbox_record = self.sandbox.wait(
                sandbox_record.id,
                self.settings.orchestrator_wait_seconds,
            )

        if sandbox_record.status is not SandboxStatus.SUCCEEDED:
            error_code = sandbox_record.failure_code or (
                f"SANDBOX_{sandbox_record.status.value.upper()}"
            )
            self._queue_or_fail_task(task, error_code, False)
            try:
                self.sandbox.destroy(sandbox_record.id)
            except OrchestratorError:
                pass
            return None

        if not sandbox_record.resources_destroyed:
            sandbox_record = self.sandbox.destroy(sandbox_record.id)
        if len(sandbox_record.artifacts) != 1:
            self._queue_or_fail_task(task, missing_result_code, False)
            return None
        return sandbox_record

    def _execute_profile(
        self,
        audit_run: AuditRun,
        operation: AnalysisOperation,
    ) -> tuple[AuditTask, AnalysisManifest | None, list[Artifact]]:
        task = get_or_create_task(self.session, audit_run, operation)
        self.session.commit()
        task = self.session.get(AuditTask, task.id)
        assert task is not None
        existing_artifacts = self._task_artifacts(task)
        if task.status in {
            AuditTaskStatus.SUCCEEDED.value,
            AuditTaskStatus.FAILED.value,
        }:
            if not existing_artifacts:
                return task, None, []
            try:
                manifest = SandboxArtifactRegistrar(
                    self.session,
                    self.artifact_store,
                ).load_manifest(
                    existing_artifacts[-1],
                    expected_operation=operation,
                )
            except OrchestratorError:
                if task.status == AuditTaskStatus.FAILED.value:
                    return task, None, existing_artifacts
                raise
            return task, manifest, existing_artifacts
        if task.status == AuditTaskStatus.SKIPPED.value:
            return task, None, existing_artifacts

        spec = TASK_SPECS[operation]
        if task.status == AuditTaskStatus.RUNNING.value and task.sandbox_id is not None:
            sandbox_record = self.sandbox.get(task.sandbox_id)
        else:
            task.status = AuditTaskStatus.RUNNING.value
            task.worker_name = self.settings.orchestrator_worker_name
            task.attempt += 1
            task.started_at = task.started_at or datetime.now(UTC)
            task.finished_at = None
            task.error_code = None
            task.error_detail = None
            self.session.commit()
            snapshot = self.session.get(SourceSnapshot, audit_run.snapshot_id)
            if snapshot is None:
                raise OrchestratorError(
                    "ORCHESTRATOR_SNAPSHOT_REQUIRED",
                    "AuditTask Snapshot is unavailable",
                )
            request = SandboxCreateRequest(
                template=spec.template,
                operation=operation.value,
                snapshot=SnapshotArtifact(
                    storage_key=snapshot.artifact.storage_key,
                    sha256=snapshot.artifact.sha256,
                    size_bytes=snapshot.artifact.size_bytes,
                ),
                task_id=task.id,
                limits=SandboxLimitsOverride(
                    timeout_seconds=task.timeout_seconds,
                ),
            )
            try:
                sandbox_record = self.sandbox.create(request)
            except OrchestratorError as exc:
                self._queue_or_fail_task(task, exc.error_code, exc.retryable)
                raise
            task.sandbox_id = sandbox_record.id
            self.session.commit()
            try:
                sandbox_record = self.sandbox.start(sandbox_record.id)
            except OrchestratorError as exc:
                try:
                    self.sandbox.destroy(sandbox_record.id)
                except OrchestratorError:
                    pass
                self._queue_or_fail_task(task, exc.error_code, exc.retryable)
                raise

        while sandbox_record.status in ACTIVE_SANDBOX_STATUSES:
            if self._cancellation_requested(audit_run.id):
                sandbox_record = self.sandbox.cancel(sandbox_record.id)
                task.status = AuditTaskStatus.CANCELLED.value
                task.error_code = "AUDIT_RUN_CANCELLED"
                task.finished_at = datetime.now(UTC)
                self.session.commit()
                self._cancel_run(self._run(audit_run.id))
                raise _RunCancelled
            sandbox_record = self.sandbox.wait(
                sandbox_record.id,
                self.settings.orchestrator_wait_seconds,
            )

        if sandbox_record.status is not SandboxStatus.SUCCEEDED:
            error_code = sandbox_record.failure_code or (
                f"SANDBOX_{sandbox_record.status.value.upper()}"
            )
            retryable = sandbox_record.status in {
                SandboxStatus.FAILED,
                SandboxStatus.TIMED_OUT,
            }
            self._queue_or_fail_task(task, error_code, retryable)
            try:
                self.sandbox.destroy(sandbox_record.id)
            except OrchestratorError:
                pass
            if task.status == AuditTaskStatus.QUEUED.value:
                raise OrchestratorError(
                    error_code,
                    "Sandbox execution failed and will be retried",
                    retryable=True,
                )
            return task, None, []

        if not sandbox_record.resources_destroyed:
            sandbox_record = self.sandbox.destroy(sandbox_record.id)
        if len(sandbox_record.artifacts) != 1:
            self._queue_or_fail_task(task, "ANALYSIS_OUTPUT_MISSING", False)
            return task, None, []

        registrar = SandboxArtifactRegistrar(self.session, self.artifact_store)
        try:
            artifact = registrar.register(
                task,
                sandbox_record.artifacts[0],
                kind=(
                    ArtifactKind.BUILD_LOG
                    if operation is AnalysisOperation.BUILD
                    else ArtifactKind.SCAN_RESULT
                ),
            )
            manifest = registrar.load_manifest(
                artifact,
                expected_operation=operation,
            )
        except OrchestratorError as exc:
            retryable = exc.retryable or exc.error_code in _RETRYABLE_OUTPUT_CODES
            self._queue_or_fail_task(task, exc.error_code, retryable)
            artifacts = self._task_artifacts(task)
            if task.status == AuditTaskStatus.QUEUED.value:
                raise OrchestratorError(
                    exc.error_code,
                    "Analysis output failed validation and will be retried",
                    retryable=True,
                ) from exc
            return task, None, artifacts
        if (
            manifest.status is ToolStatus.FAILED
            and manifest.reason_code in _RETRYABLE_MANIFEST_CODES
            and task.attempt < task.max_attempts
        ):
            self._queue_or_fail_task(
                task,
                manifest.reason_code,
                retryable=True,
            )
            raise OrchestratorError(
                manifest.reason_code,
                "Deterministic tool failed transiently and will be retried",
                retryable=True,
            )
        task.finished_at = datetime.now(UTC)
        task.sandbox_id = sandbox_record.id
        if manifest.status is ToolStatus.COMPLETED:
            task.status = AuditTaskStatus.SUCCEEDED.value
            task.error_code = None
        elif manifest.status is ToolStatus.SKIPPED:
            task.status = AuditTaskStatus.SKIPPED.value
            task.error_code = manifest.reason_code
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.error_code = manifest.reason_code
        return task, manifest, [artifact]

    def _persist_inventory(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        manifest: AnalysisManifest,
        artifacts: list[Artifact],
    ) -> None:
        assert manifest.inventory is not None
        inventory = manifest.inventory.model_dump(mode="json")
        evidence_ids = [str(artifact.id) for artifact in artifacts]
        payloads = {
            AuditFactKind.ARCHITECTURE: {
                "build_system": inventory["build_system"],
                "java_versions": inventory["java_versions"],
                "modules": inventory["modules"],
                "module_dependencies": inventory["module_dependencies"],
                "build_plan": inventory["build_plan"],
                # The runtime environment §7.7 needs, distinct from the build
                # command sequence above.
                "runtime_plan": inventory.get("runtime_plan", {}),
                "symbols": inventory["symbols"],
                "permissions": inventory["permissions"],
                "classified_paths": inventory["classified_paths"],
            },
            AuditFactKind.ENTRYPOINT: {"items": inventory["entrypoints"]},
            AuditFactKind.SOURCE: {"items": inventory["sources"]},
            AuditFactKind.SINK: {"items": inventory["sinks"]},
        }
        for kind, payload in payloads.items():
            fact = self.session.scalar(
                select(AuditFact).where(
                    AuditFact.audit_run_id == audit_run.id,
                    AuditFact.created_by_task_id == task.id,
                    AuditFact.kind == kind.value,
                )
            )
            if fact is None:
                fact = AuditFact(
                    audit_run_id=audit_run.id,
                    kind=kind.value,
                    structured_payload=payload,
                    evidence_ids=evidence_ids,
                    created_by_task_id=task.id,
                )
                self.session.add(fact)
            else:
                fact.structured_payload = payload
                fact.evidence_ids = evidence_ids

    def _persist_candidates(
        self,
        audit_run: AuditRun,
        task: AuditTask,
        candidates: list[dict[str, object]],
        artifacts: list[Artifact],
    ) -> list[AuditFact]:
        """Merge candidates into the run's candidate facts by root cause.

        Tool-agnostic on purpose: a scanner candidate and a semantic candidate
        for one weakness share a `root_cause_key`, so they converge here
        without either side knowing about the other. Returns the facts touched,
        which is what lets the semantic stage link an AuditIntent to the
        evidence that motivated it.
        """

        raw_artifact_ids = sorted(str(artifact.id) for artifact in artifacts)
        existing = list(
            self.session.scalars(
                select(AuditFact).where(
                    AuditFact.audit_run_id == audit_run.id,
                    AuditFact.kind == AuditFactKind.CANDIDATE_FINDING.value,
                )
            )
        )
        by_root = {
            str(fact.structured_payload.get("candidate", {}).get("root_cause_key")): fact
            for fact in existing
            if isinstance(fact.structured_payload.get("candidate"), dict)
        }
        touched: list[AuditFact] = []
        for candidate in candidates:
            root_key = candidate["root_cause_key"]
            fact = by_root.get(root_key)
            if fact is None:
                fact = AuditFact(
                    audit_run_id=audit_run.id,
                    kind=AuditFactKind.CANDIDATE_FINDING.value,
                    structured_payload={
                        "candidate": candidate,
                        "raw_artifact_ids": raw_artifact_ids,
                    },
                    evidence_ids=raw_artifact_ids,
                    created_by_task_id=task.id,
                )
                self.session.add(fact)
                by_root[root_key] = fact
                touched.append(fact)
                continue
            current = fact.structured_payload["candidate"]
            merged = merge_candidates([current, candidate])[0]
            evidence = sorted(set(fact.evidence_ids) | set(raw_artifact_ids))
            fact.structured_payload = {
                "candidate": merged,
                "raw_artifact_ids": evidence,
            }
            fact.evidence_ids = evidence
            touched.append(fact)
        return touched

    def _coverage(self, audit_run: AuditRun) -> AuditCoverage:
        coverage = self.session.get(AuditCoverage, audit_run.id)
        if coverage is not None:
            return coverage
        coverage = AuditCoverage(
            audit_run_id=audit_run.id,
            modules_total=0,
            modules_analyzed=0,
            java_files_total=0,
            java_files_analyzed=0,
            entrypoints_total=0,
            entrypoints_analyzed=0,
            sensitive_sinks_total=0,
            sensitive_sinks_analyzed=0,
            build_status=BuildStatus.FAILED.value,
            static_tools_completed={},
            skipped_paths=[],
            unsupported_components=[],
            coverage_warnings=[],
        )
        self.session.add(coverage)
        self.session.flush()
        return coverage

    def _add_warning(
        self,
        coverage: AuditCoverage,
        reason_code: str,
        *,
        tool: str,
        task_id: UUID,
    ) -> None:
        warnings = list(coverage.coverage_warnings)
        key = (reason_code, tool)
        if not any(
            (item.get("reason_code"), item.get("tool")) == key for item in warnings
        ):
            warnings.append(
                {
                    "reason_code": reason_code,
                    "tool": tool,
                    "task_id": str(task_id),
                }
            )
            coverage.coverage_warnings = warnings

    @staticmethod
    def _tool_coverage(
        task: AuditTask,
        *,
        status: ToolStatus,
        version: str | None,
        artifact_ids: list[UUID],
        reason_code: str | None,
        candidate_count: int,
    ) -> dict[str, object]:
        return {
            "status": status.value,
            "version": version,
            "task_id": str(task.id),
            "artifact_ids": [str(identifier) for identifier in artifact_ids],
            "reason_code": reason_code,
            "candidate_count": candidate_count,
        }

    def _queue_or_fail_task(
        self,
        task: AuditTask,
        error_code: str,
        retryable: bool,
    ) -> None:
        task.error_code = error_code
        task.sandbox_id = None
        if retryable and task.attempt < task.max_attempts:
            task.status = AuditTaskStatus.QUEUED.value
            task.finished_at = None
        else:
            task.status = AuditTaskStatus.FAILED.value
            task.finished_at = datetime.now(UTC)
        self.session.commit()

    def _task_artifacts(self, task: AuditTask) -> list[Artifact]:
        return list(
            self.session.scalars(
                select(Artifact)
                .where(Artifact.produced_by_task_id == task.id)
                .order_by(Artifact.created_at, Artifact.id)
            )
        )

    def _cancellation_requested(self, run_id: UUID) -> bool:
        audit_run = self.session.get(AuditRun, run_id)
        assert audit_run is not None
        self.session.refresh(audit_run, attribute_names=["status"])
        return audit_run.status == AuditRunStatus.CANCELLING.value

    def _cancel_run(self, audit_run: AuditRun) -> None:
        if audit_run.status == AuditRunStatus.CANCELLING.value:
            AuditRunService(self.session).transition(
                audit_run.id,
                AuditRunStatus.CANCELLED,
            )

    def _fail_run(self, run_id: UUID, error: OrchestratorError) -> None:
        audit_run = self._run(run_id)
        if audit_run.status in {
            AuditRunStatus.COMPLETED.value,
            AuditRunStatus.COMPLETED_WITH_WARNINGS.value,
            AuditRunStatus.CANCELLED.value,
            AuditRunStatus.FAILED.value,
        }:
            return
        audit_run.failure_code = error.error_code
        audit_run.failure_reason = error.message
        AuditRunService(self.session).transition(
            run_id,
            AuditRunStatus.FAILED,
        )

    def _run(self, run_id: UUID) -> AuditRun:
        audit_run = self.session.get(AuditRun, run_id)
        if audit_run is None:
            raise OrchestratorError(
                "AUDIT_RUN_NOT_FOUND",
                "AuditRun does not exist",
            )
        return audit_run
