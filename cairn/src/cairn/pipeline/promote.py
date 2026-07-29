"""Promote candidate facts into formal Findings (§6.14, §7.6).

The spec is explicit that a ``candidate_finding`` becomes a ``Finding`` only
after passing "the Finding Pipeline's data contract, location validation and
deduplication". This module is that gate, and it is deliberately strict in one
direction: a candidate that cannot be substantiated is rejected whole, never
promoted with the unsubstantiated parts quietly dropped.

Two rules carry most of the weight.

**Every location is re-resolved against immutable evidence.** Source locations
are checked against the Snapshot Artifact the report will cite, and their
snippet is stored alongside ``snapshot_sha``. Bytecode locations are checked
against the ``ProgramIndexV2`` derived from that Snapshot. Archive members are
never treated as source text and absent source lines stay absent.

**A candidate with no CWE cannot become a Finding.** ``Finding.cwe_id`` is
mandatory and the API validates it as ``CWE-<n>``. Inventing one to satisfy the
column would put a weakness class into a report that no tool actually claimed,
so the candidate is rejected and the rejection is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from itertools import chain
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from cairn.analysis.contracts import (
    CallChainStep,
    CandidateFinding,
    CandidateLocation,
    CodeCallChainStepV2,
    CodeLocationV2,
    ProgramIndexV2,
)
from cairn.pipeline.catalogue import category_label, owasp_for, remediation_for
from cairn.pipeline.snippets import FileText, SnippetUnavailable, read_files
from cairn.server.domain.enums import (
    FindingConfidence,
    FindingSeverity,
    LocationRole,
)
from cairn.server.schemas.findings import (
    CandidateFindingCommand,
    CandidateLocation as CommandLocation,
)

REASON_NO_CWE = "PIPELINE_NO_CWE"
REASON_CONTRACT_INVALID = "PIPELINE_CANDIDATE_INVALID"
REASON_PATH_MISSING = "PIPELINE_LOCATION_NOT_IN_SNAPSHOT"
REASON_PROGRAM_INDEX_REQUIRED = "PIPELINE_PROGRAM_INDEX_REQUIRED"
REASON_LOCATION_NOT_IN_PROGRAM_INDEX = "PIPELINE_LOCATION_NOT_IN_PROGRAM_INDEX"

MAX_TITLE_CHARS = 500
MAX_LOCATIONS = 64
MAX_DEFENSE_NOTES = 8
MAX_DISCOVERED_BY_CHARS = 255

# Tokens that read wrong when merely capitalised.
_ACRONYMS = {
    "api": "API",
    "csrf": "CSRF",
    "el": "EL",
    "http": "HTTP",
    "idor": "IDOR",
    "jwt": "JWT",
    "ldap": "LDAP",
    "ognl": "OGNL",
    "rce": "RCE",
    "spel": "SpEL",
    "sql": "SQL",
    "ssrf": "SSRF",
    "url": "URL",
    "xml": "XML",
    "xss": "XSS",
    "xxe": "XXE",
}

_UNKNOWN_PRECONDITIONS = (
    "尚未确认。该候选由 {tools} 产出，未附带攻击前提说明，"
    "因此在据此行动之前，仍需确认其可达性以及所需的认证状态。"
)
_UNKNOWN_IMPACT = (
    "尚未确认。该候选由 {tools} 产出，未附带影响说明；"
    "成功利用后的后果尚未评估。"
)


class PipelineRejected(Exception):
    """A candidate that does not satisfy the Finding contract."""

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class PromotionRejection:
    """A discarded candidate, recorded so discards stay auditable."""

    root_cause_key: str
    reason_code: str
    detail: str


@dataclass(frozen=True, slots=True)
class PromotionResult:
    commands: tuple[CandidateFindingCommand, ...]
    rejections: tuple[PromotionRejection, ...]


_V1Location = CandidateLocation | CallChainStep
_V2Location = CodeLocationV2 | CodeCallChainStepV2
_CandidateLocation = _V1Location | _V2Location
_ClassKey = tuple[str, str | None, str, str]
_MethodKey = tuple[str, str | None, str, str, str, str]
_OffsetKey = tuple[str, str | None, str, str, str, str, int]


@dataclass(frozen=True, slots=True)
class _ProgramIndexLocations:
    """The subset of an index needed to substantiate this promotion batch."""

    classes: frozenset[_ClassKey]
    methods: dict[_MethodKey, frozenset[tuple[int | None, int | None]]]
    offsets: dict[_OffsetKey, frozenset[int | None]]

    @classmethod
    def resolve(
        cls,
        index: ProgramIndexV2,
        candidates: list[CandidateFinding],
    ) -> "_ProgramIndexLocations":
        class_wanted: set[_ClassKey] = set()
        method_wanted: set[_MethodKey] = set()
        offset_wanted: set[_OffsetKey] = set()
        for candidate in candidates:
            for location in (*candidate.call_chain, *candidate.locations):
                if not _is_binary_location(location):
                    continue
                class_key = _class_key(location)
                class_wanted.add(class_key)
                method_key = _method_key(location)
                if method_key is None:
                    continue
                method_wanted.add(method_key)
                if location.bytecode_offset is not None:
                    offset_wanted.add((*method_key, location.bytecode_offset))

        classes: set[_ClassKey] = set()
        if class_wanted:
            for record in index.classes:
                key = (
                    record.logical_path,
                    record.container_path,
                    record.entry_path,
                    record.class_name,
                )
                if key in class_wanted:
                    classes.add(key)

        methods: dict[_MethodKey, set[tuple[int | None, int | None]]] = {}
        if method_wanted:
            for record in index.methods:
                key = (
                    record.logical_path,
                    record.container_path,
                    record.entry_path,
                    record.class_name,
                    record.method_name,
                    record.method_descriptor,
                )
                if key in method_wanted:
                    methods.setdefault(key, set()).add(
                        (record.start_line, record.end_line)
                    )

        offsets: dict[_OffsetKey, set[int | None]] = {}
        if offset_wanted:
            for record in chain(index.calls, index.field_accesses):
                key = (
                    record.logical_path,
                    record.container_path,
                    record.entry_path,
                    record.class_name,
                    record.method_name,
                    record.method_descriptor,
                    record.bytecode_offset,
                )
                if key in offset_wanted:
                    offsets.setdefault(key, set()).add(record.source_line)

        return cls(
            classes=frozenset(classes),
            methods={key: frozenset(lines) for key, lines in methods.items()},
            offsets={key: frozenset(lines) for key, lines in offsets.items()},
        )

    def validate(self, location: _V2Location) -> None:
        class_key = _class_key(location)
        if class_key not in self.classes:
            raise _index_rejection(location, "class identity")

        method_key = _method_key(location)
        if method_key is None:
            if location.start_line is not None:
                raise _index_rejection(location, "class-level source lines")
            return
        method_lines = self.methods.get(method_key)
        if method_lines is None:
            raise _index_rejection(location, "method identity")

        if location.bytecode_offset is not None:
            offset_key = (*method_key, location.bytecode_offset)
            instruction_lines = self.offsets.get(offset_key)
            if instruction_lines is None:
                raise _index_rejection(location, "bytecode offset")
            _validate_source_lines(
                location,
                instruction_lines,
                evidence="indexed instruction",
            )
            return

        if location.start_line is not None:
            claimed = (location.start_line, location.end_line)
            if claimed not in method_lines:
                raise _index_rejection(location, "indexed method source lines")


def promote_candidates(
    candidates: list[dict[str, object]],
    *,
    audit_run_id: UUID,
    archive_path: Path,
    snapshot_sha256: str,
    program_index: ProgramIndexV2 | None = None,
) -> PromotionResult:
    """Turn merged candidate payloads into Finding creation commands.

    Ordered by fingerprint so two runs over one Snapshot promote in the same
    order, which is what makes a partially-applied promotion resumable: the
    unique constraint on ``(audit_run_id, fingerprint)`` skips what already
    landed.
    """

    parsed: list[CandidateFinding] = []
    rejections: list[PromotionRejection] = []
    for payload in candidates:
        key = str(payload.get("root_cause_key") or "")
        try:
            parsed.append(CandidateFinding.model_validate(payload))
        except ValidationError as exc:
            rejections.append(
                PromotionRejection(key, REASON_CONTRACT_INVALID, _detail(exc))
            )
    parsed.sort(key=lambda candidate: candidate.fingerprint)

    index_locations = (
        _ProgramIndexLocations.resolve(program_index, parsed)
        if program_index is not None
        else None
    )

    wanted: set[str] = set()
    for candidate in parsed:
        for location in (*candidate.call_chain, *candidate.locations):
            source_path = _snapshot_source_path(location)
            if source_path is not None:
                wanted.add(source_path)
    try:
        files = read_files(archive_path, wanted)
    except SnippetUnavailable as exc:
        # The Snapshot itself is unreadable, so nothing can be substantiated.
        # Every candidate is rejected with the same cause rather than the run
        # failing, which keeps the earlier stages' results intact.
        return PromotionResult(
            (),
            tuple(
                PromotionRejection(
                    candidate.root_cause_key,
                    exc.reason_code,
                    exc.detail,
                )
                for candidate in parsed
            ),
        )

    commands: list[CandidateFindingCommand] = []
    for candidate in parsed:
        try:
            commands.append(
                _command(
                    candidate,
                    audit_run_id=audit_run_id,
                    files=files,
                    snapshot_sha256=snapshot_sha256,
                    index_locations=index_locations,
                )
            )
        except (PipelineRejected, SnippetUnavailable) as exc:
            rejections.append(
                PromotionRejection(
                    candidate.root_cause_key,
                    exc.reason_code,
                    exc.detail,
                )
            )
        except ValidationError as exc:
            rejections.append(
                PromotionRejection(
                    candidate.root_cause_key,
                    REASON_CONTRACT_INVALID,
                    _detail(exc),
                )
            )
    return PromotionResult(tuple(commands), tuple(rejections))


def _command(
    candidate: CandidateFinding,
    *,
    audit_run_id: UUID,
    files: dict[str, FileText],
    snapshot_sha256: str,
    index_locations: _ProgramIndexLocations | None,
) -> CandidateFindingCommand:
    if not candidate.cwe_ids:
        raise PipelineRejected(
            REASON_NO_CWE,
            "candidate names no CWE, so it cannot satisfy the Finding contract",
        )
    locations, dropped = _locations(
        candidate,
        files=files,
        snapshot_sha256=snapshot_sha256,
        index_locations=index_locations,
    )
    cwe_id = candidate.cwe_ids[0]
    tools = ", ".join(candidate.discovered_by)
    return CandidateFindingCommand(
        audit_run_id=audit_run_id,
        fingerprint=candidate.fingerprint,
        title=_title(candidate),
        description=_description(candidate, dropped_locations=dropped),
        category=candidate.category,
        cwe_id=cwe_id,
        owasp_category=owasp_for(cwe_id),
        severity=FindingSeverity(candidate.severity.value),
        confidence=FindingConfidence(candidate.confidence.value),
        attack_preconditions=(
            candidate.attack_preconditions
            or _UNKNOWN_PRECONDITIONS.format(tools=tools)
        ),
        impact=candidate.impact or _UNKNOWN_IMPACT.format(tools=tools),
        remediation=remediation_for(cwe_id, candidate.category),
        discovered_by=_discovered_by(candidate),
        locations=locations,
    )


def _locations(
    candidate: CandidateFinding,
    *,
    files: dict[str, FileText],
    snapshot_sha256: str,
    index_locations: _ProgramIndexLocations | None,
) -> tuple[list[CommandLocation], int]:
    """Render the call chain first, then any location it does not already cover.

    The chain runs entrypoint to sink, so leading with it means the location
    list reads as the path an attacker takes rather than as an unordered set.
    Scanner candidates carry no chain and fall back to their locations alone.

    Returns the rendered locations and how many were dropped by the cap, so the
    caller can say so instead of presenting a truncated list as complete.
    """

    ordered: list[_CandidateLocation] = []
    seen: set[tuple[object, ...]] = set()
    for step in candidate.call_chain:
        key = _location_key(step)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(step)
    for location in candidate.locations:
        key = _location_key(location)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(location)

    # Validate the complete binary evidence list before applying the display
    # cap. A bad 65th location must still reject the whole candidate.
    for location in ordered:
        if not _is_binary_location(location):
            continue
        if index_locations is None:
            raise PipelineRejected(
                REASON_PROGRAM_INDEX_REQUIRED,
                f"{_location_identity(location)} requires ProgramIndexV2 evidence",
            )
        index_locations.validate(location)

    rendered: list[CommandLocation] = []
    for ordinal, location in enumerate(ordered[:MAX_LOCATIONS]):
        rendered.append(
            _render_location(
                location,
                files=files,
                snapshot_sha256=snapshot_sha256,
                ordinal=ordinal,
                index_locations=index_locations,
            )
        )
    return rendered, max(0, len(ordered) - len(rendered))


def _render_location(
    location: _CandidateLocation,
    *,
    files: dict[str, FileText],
    snapshot_sha256: str,
    ordinal: int,
    index_locations: _ProgramIndexLocations | None,
) -> CommandLocation:
    if not isinstance(location, CodeLocationV2):
        return _render_source_location(
            role=location.role,
            path=location.path,
            start_line=location.start_line,
            end_line=location.end_line,
            symbol=location.symbol,
            files=files,
            snapshot_sha256=snapshot_sha256,
            ordinal=ordinal,
        )

    if _is_binary_location(location):
        if index_locations is None:
            raise PipelineRejected(
                REASON_PROGRAM_INDEX_REQUIRED,
                f"{_location_identity(location)} requires ProgramIndexV2 evidence",
            )
        index_locations.validate(location)
        return _render_v2_location(
            location,
            code_snippet=None,
            snapshot_sha=snapshot_sha256,
            ordinal=ordinal,
        )

    if location.source_path is not None and location.start_line is not None:
        text = files.get(location.source_path)
        if text is None:
            raise PipelineRejected(
                REASON_PATH_MISSING,
                f"Snapshot does not contain {location.source_path}",
            )
        return _render_v2_location(
            location,
            code_snippet=text.snippet(location.start_line, location.end_line),
            snapshot_sha=snapshot_sha256,
            ordinal=ordinal,
        )

    # Archive-backed config locations carry no source line or snippet. Their
    # normalized path is already enforced by CodeLocationV2's contract.
    return _render_v2_location(
        location,
        code_snippet=None,
        snapshot_sha=snapshot_sha256,
        ordinal=ordinal,
    )


def _render_v2_location(
    location: _V2Location,
    *,
    code_snippet: str | None,
    snapshot_sha: str,
    ordinal: int,
) -> CommandLocation:
    return CommandLocation(
        role=LocationRole(location.role),
        origin_kind=location.origin_kind,
        file_path=location.source_path,
        source_path=location.source_path,
        start_line=location.start_line,
        end_line=location.end_line,
        symbol=location.symbol,
        code_snippet=code_snippet,
        container_path=location.container_path,
        entry_path=location.entry_path,
        class_name=location.class_name,
        method_name=location.method_name,
        method_descriptor=location.method_descriptor,
        bytecode_offset=location.bytecode_offset,
        decompiled_artifact_id=location.decompiled_artifact_id,
        decompiled_start_line=location.decompiled_start_line,
        decompiled_end_line=location.decompiled_end_line,
        snapshot_sha=snapshot_sha,
        ordinal=ordinal,
    )


def _render_source_location(
    *,
    role: str,
    path: str,
    start_line: int,
    end_line: int,
    symbol: str | None,
    files: dict[str, FileText],
    snapshot_sha256: str,
    ordinal: int,
) -> CommandLocation:
    text = files.get(path)
    if text is None:
        raise PipelineRejected(
            REASON_PATH_MISSING,
            f"Snapshot does not contain {path}",
        )
    return CommandLocation(
        role=LocationRole(role),
        file_path=path,
        source_path=path,
        start_line=start_line,
        end_line=end_line,
        symbol=symbol,
        code_snippet=text.snippet(start_line, end_line),
        snapshot_sha=snapshot_sha256,
        ordinal=ordinal,
    )


def _is_binary_location(location: _CandidateLocation) -> bool:
    return isinstance(location, CodeLocationV2) and location.origin_kind in {
        "bytecode",
        "decompiled",
    }


def _snapshot_source_path(location: _CandidateLocation) -> str | None:
    if not isinstance(location, CodeLocationV2):
        return location.path
    if location.origin_kind == "source":
        return location.source_path
    if (
        location.origin_kind == "config"
        and location.source_path is not None
        and location.start_line is not None
    ):
        return location.source_path
    return None


def _logical_path(location: _V2Location) -> str:
    assert location.entry_path is not None  # enforced for binary V2 locations
    if location.container_path is None:
        return location.entry_path
    return f"{location.container_path}!/{location.entry_path}"


def _class_key(location: _V2Location) -> _ClassKey:
    assert location.entry_path is not None  # enforced for binary V2 locations
    assert location.class_name is not None  # enforced for binary V2 locations
    return (
        _logical_path(location),
        location.container_path,
        location.entry_path,
        location.class_name,
    )


def _method_key(location: _V2Location) -> _MethodKey | None:
    if location.method_name is None:
        return None
    assert location.method_descriptor is not None  # contract keeps the pair whole
    return (*_class_key(location), location.method_name, location.method_descriptor)


def _validate_source_lines(
    location: _V2Location,
    indexed_lines: frozenset[int | None],
    *,
    evidence: str,
) -> None:
    if location.start_line is None:
        return
    if (
        location.start_line != location.end_line
        or location.start_line not in indexed_lines
    ):
        raise _index_rejection(location, f"{evidence} source line")


def _index_rejection(location: _V2Location, mismatch: str) -> PipelineRejected:
    return PipelineRejected(
        REASON_LOCATION_NOT_IN_PROGRAM_INDEX,
        (
            f"{_location_identity(location)} does not match its {mismatch} "
            "in ProgramIndexV2"
        ),
    )


def _location_identity(location: _V2Location) -> str:
    identity = f"{_logical_path(location)}::{location.class_name}"
    if location.method_name is not None:
        identity += f".{location.method_name}{location.method_descriptor}"
    if location.bytecode_offset is not None:
        identity += f"@{location.bytecode_offset}"
    return identity


def _location_key(location: _CandidateLocation) -> tuple[object, ...]:
    if not isinstance(location, CodeLocationV2):
        return (
            "source",
            location.role,
            location.path,
            location.start_line,
            location.end_line,
        )
    if location.origin_kind == "source":
        return (
            "source",
            location.role,
            location.source_path,
            location.start_line,
            location.end_line,
        )
    return (
        location.origin_kind,
        location.role,
        location.container_path,
        location.entry_path,
        location.class_name,
        location.method_name,
        location.method_descriptor,
        location.bytecode_offset,
        location.source_path,
        location.start_line,
        location.end_line,
        location.decompiled_artifact_id,
        location.decompiled_start_line,
        location.decompiled_end_line,
    )


def _title(candidate: CandidateFinding) -> str:
    primary = next(
        (location for location in candidate.locations if location.role == "sink"),
        candidate.locations[0],
    )
    subject = primary.symbol or _title_subject(primary)
    label = category_label(candidate.category, _humanize(candidate.category))
    return f"{label}：{subject}"[:MAX_TITLE_CHARS]


def _title_subject(location: CandidateLocation | CodeLocationV2) -> str:
    if not isinstance(location, CodeLocationV2):
        return location.path
    if location.class_name is not None:
        if location.method_name is not None:
            return f"{location.class_name}.{location.method_name}"
        return location.class_name
    return location.source_path or location.entry_path or "unknown location"


def _description(candidate: CandidateFinding, *, dropped_locations: int) -> str:
    """Assemble the Finding narrative from the candidate's own evidence.

    Every label the platform adds is Chinese, matching the rest of the
    workbench. ``candidate.message`` is passed through untouched: for a
    semantic candidate it is already Chinese, and for a scanner candidate it is
    that tool's own rule message — evidence a reader can trace back to the raw
    output, which a translation would no longer be.
    """

    parts = [candidate.message]
    if candidate.controllability:
        parts.append(f"可控性：{candidate.controllability}")
    if candidate.call_chain:
        first, last = candidate.call_chain[0], candidate.call_chain[-1]
        parts.append(
            f"调用链：{_location_subject(first)}"
            f"（{_location_anchor(first)}）经 {len(candidate.call_chain)} 步"
            f"到达 {_location_subject(last)}（{_location_anchor(last)}）。"
        )
    for defense in candidate.existing_defenses[:MAX_DEFENSE_NOTES]:
        verdict = "有效" if defense.effective else "未生效"
        parts.append(
            f"已有防护（{verdict}）：{defense.mechanism} —— {defense.reasoning}"
        )
    if candidate.recommended_verification:
        parts.append(f"建议验证方式：{candidate.recommended_verification}")
    if dropped_locations:
        parts.append(
            f"另有 {dropped_locations} 处位置记录在候选上但未列入此处，本列表并不完整。"
        )
    parts.append(f"发现来源：{', '.join(candidate.discovered_by)}。")
    return "\n\n".join(parts)


def _location_subject(location: _CandidateLocation) -> str:
    if location.symbol:
        return location.symbol
    if isinstance(location, CodeLocationV2) and location.class_name is not None:
        if location.method_name is not None:
            return f"{location.class_name}.{location.method_name}"
        return location.class_name
    return _location_anchor(location)


def _location_anchor(location: _CandidateLocation) -> str:
    if not isinstance(location, CodeLocationV2):
        return f"{location.path}:{location.start_line}"
    if location.origin_kind in {"bytecode", "decompiled"}:
        anchor = _logical_path(location)
        if location.bytecode_offset is not None:
            anchor += f"@{location.bytecode_offset}"
        return anchor
    if location.source_path is not None:
        if location.start_line is not None:
            return f"{location.source_path}:{location.start_line}"
        return location.source_path
    return location.entry_path or "unknown location"


def _discovered_by(candidate: CandidateFinding) -> str:
    """Join the discovering tools, bounded to the column width.

    The authoritative list stays on the candidate ``AuditFact``; this string is
    for display, so truncating it loses nothing the independence check in
    :mod:`cairn.pipeline.decide` relies on.
    """

    joined = ", ".join(candidate.discovered_by)
    if len(joined) <= MAX_DISCOVERED_BY_CHARS:
        return joined
    return joined[: MAX_DISCOVERED_BY_CHARS - 1] + "…"


def _humanize(category: str) -> str:
    """Render a category slug readably, for slugs Cairn has no label for.

    Only reached when a scanner emitted a category outside the platform's own
    vocabulary (:data:`cairn.pipeline.catalogue.CATEGORY_LABELS`). Leaving that
    slug in its original English is the honest outcome: the platform has no
    Chinese name for it that it could stand behind.
    """

    words = [word for word in str(category).replace("_", "-").split("-") if word]
    if not words:
        return "安全弱点"
    rendered = [_ACRONYMS.get(words[0].lower(), words[0].capitalize())]
    rendered.extend(_ACRONYMS.get(word.lower(), word.lower()) for word in words[1:])
    return " ".join(rendered)


def _detail(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = str(first.get("msg", "invalid"))
    return (f"{location}: {message}" if location else message)[:512]
