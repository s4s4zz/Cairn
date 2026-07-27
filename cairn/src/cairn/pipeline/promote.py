"""Promote candidate facts into formal Findings (§6.14, §7.6).

The spec is explicit that a ``candidate_finding`` becomes a ``Finding`` only
after passing "the Finding Pipeline's data contract, location validation and
deduplication". This module is that gate, and it is deliberately strict in one
direction: a candidate that cannot be substantiated is rejected whole, never
promoted with the unsubstantiated parts quietly dropped.

Two rules carry most of the weight.

**Every location is re-resolved against the Snapshot.** A candidate's line
numbers were computed inside a sandbox against an extracted copy; here they are
checked against the Snapshot Artifact the report will cite, and the extracted
snippet is stored alongside ``snapshot_sha``. A location the Snapshot cannot
support fails its candidate rather than producing a Finding that points at a
line nobody can show.

**A candidate with no CWE cannot become a Finding.** ``Finding.cwe_id`` is
mandatory and the API validates it as ``CWE-<n>``. Inventing one to satisfy the
column would put a weakness class into a report that no tool actually claimed,
so the candidate is rejected and the rejection is recorded.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from pydantic import ValidationError

from cairn.analysis.contracts import CandidateFinding
from cairn.pipeline.catalogue import owasp_for, remediation_for
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
    "Not established. This candidate was produced by {tools} without an "
    "attack-precondition statement, so reachability and the required "
    "authentication state still have to be determined before acting on it."
)
_UNKNOWN_IMPACT = (
    "Not established. This candidate was produced by {tools} without an impact "
    "statement; the consequence of successful exploitation has not been "
    "assessed."
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


def promote_candidates(
    candidates: list[dict[str, object]],
    *,
    audit_run_id: UUID,
    archive_path: Path,
    snapshot_sha256: str,
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

    wanted: set[str] = set()
    for candidate in parsed:
        wanted.update(location.path for location in candidate.locations)
        wanted.update(step.path for step in candidate.call_chain)
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
) -> tuple[list[CommandLocation], int]:
    """Render the call chain first, then any location it does not already cover.

    The chain runs entrypoint to sink, so leading with it means the location
    list reads as the path an attacker takes rather than as an unordered set.
    Scanner candidates carry no chain and fall back to their locations alone.

    Returns the rendered locations and how many were dropped by the cap, so the
    caller can say so instead of presenting a truncated list as complete.
    """

    ordered: list[tuple[str, str, int, int, str | None]] = []
    seen: set[tuple[str, str, int, int]] = set()
    for step in candidate.call_chain:
        key = (step.role, step.path, step.start_line, step.end_line)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(
            (step.role, step.path, step.start_line, step.end_line, step.symbol)
        )
    for location in candidate.locations:
        key = (location.role, location.path, location.start_line, location.end_line)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(
            (
                location.role,
                location.path,
                location.start_line,
                location.end_line,
                location.symbol,
            )
        )

    rendered: list[CommandLocation] = []
    for ordinal, (role, path, start_line, end_line, symbol) in enumerate(
        ordered[:MAX_LOCATIONS]
    ):
        text = files.get(path)
        if text is None:
            raise PipelineRejected(
                REASON_PATH_MISSING,
                f"Snapshot does not contain {path}",
            )
        rendered.append(
            CommandLocation(
                role=LocationRole(role),
                file_path=path,
                start_line=start_line,
                end_line=end_line,
                symbol=symbol,
                code_snippet=text.snippet(start_line, end_line),
                snapshot_sha=snapshot_sha256,
                ordinal=ordinal,
            )
        )
    return rendered, max(0, len(ordered) - len(rendered))


def _title(candidate: CandidateFinding) -> str:
    primary = next(
        (location for location in candidate.locations if location.role == "sink"),
        candidate.locations[0],
    )
    subject = primary.symbol or primary.path
    return f"{_humanize(candidate.category)} in {subject}"[:MAX_TITLE_CHARS]


def _description(candidate: CandidateFinding, *, dropped_locations: int) -> str:
    parts = [candidate.message]
    if candidate.controllability:
        parts.append(f"Controllability: {candidate.controllability}")
    if candidate.call_chain:
        first, last = candidate.call_chain[0], candidate.call_chain[-1]
        parts.append(
            f"Call chain: {first.symbol} ({first.path}:{first.start_line}) reaches "
            f"{last.symbol} ({last.path}:{last.start_line}) in "
            f"{len(candidate.call_chain)} steps."
        )
    for defense in candidate.existing_defenses[:MAX_DEFENSE_NOTES]:
        verdict = "holds" if defense.effective else "does not hold"
        parts.append(
            f"Existing defence ({verdict}): {defense.mechanism} — {defense.reasoning}"
        )
    if candidate.recommended_verification:
        parts.append(f"Recommended verification: {candidate.recommended_verification}")
    if dropped_locations:
        parts.append(
            f"{dropped_locations} further location(s) were recorded on the "
            "candidate but omitted here; this list is not exhaustive."
        )
    parts.append(f"Discovered by: {', '.join(candidate.discovered_by)}.")
    return "\n\n".join(parts)


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
    words = [word for word in str(category).replace("_", "-").split("-") if word]
    if not words:
        return "Security weakness"
    rendered = [_ACRONYMS.get(words[0].lower(), words[0].capitalize())]
    rendered.extend(_ACRONYMS.get(word.lower(), word.lower()) for word in words[1:])
    return " ".join(rendered)


def _detail(error: ValidationError) -> str:
    first = error.errors()[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = str(first.get("msg", "invalid"))
    return (f"{location}: {message}" if location else message)[:512]
