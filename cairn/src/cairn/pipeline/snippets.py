"""Read code snippets out of a Snapshot archive (§6.7).

Every ``FindingLocation`` carries a ``code_snippet`` and a ``snapshot_sha``,
because a report that points at a line without showing it — or that shows a
line from a different revision — is worse than no report at all. The snippets
therefore come from the Snapshot Artifact itself rather than from a working
copy, and the whole read is bounded the same way
``cairn.orchestrator.artifacts`` bounds sandbox output: a Snapshot is
repository-controlled data, and it stays untrusted here even though the
platform produced the archive.

The Orchestrator is the right process for this. It already clones repositories
and builds Snapshots (`DeterministicOrchestrator._resolve_snapshot`), so
reading one back adds no access it did not have. The alternative — another
sandbox round-trip per finding — would buy nothing.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path, PurePosixPath
import tarfile

MAX_ARCHIVE_ENTRIES = 100_000
# A source file larger than this yields no meaningful snippet, and reading it
# would be the only unbounded allocation on this path.
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_SNIPPET_LINES = 40
MAX_SNIPPET_LINE_CHARS = 400
TRUNCATION_MARKER = "… (snippet truncated)"
BLANK_MARKER = "(blank line)"


class SnippetUnavailable(Exception):
    """The Snapshot does not support the claimed location.

    Raised rather than returning a placeholder: a location the Snapshot cannot
    substantiate must fail its candidate, not decorate a Finding with an
    apology.
    """

    def __init__(self, reason_code: str, detail: str) -> None:
        super().__init__(detail)
        self.reason_code = reason_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class FileText:
    """One Snapshot file, decoded and split into lines."""

    lines: tuple[str, ...]

    @property
    def line_count(self) -> int:
        return len(self.lines)

    def snippet(self, start_line: int, end_line: int) -> str:
        """Render lines ``start_line``..``end_line`` inclusive, 1-indexed."""

        if start_line < 1 or end_line < start_line:
            raise SnippetUnavailable(
                "PIPELINE_LOCATION_INVALID",
                "location line range is not ordered",
            )
        if end_line > self.line_count:
            raise SnippetUnavailable(
                "PIPELINE_LOCATION_OUT_OF_RANGE",
                (
                    f"location ends at line {end_line} but the Snapshot file has "
                    f"{self.line_count}"
                ),
            )
        selected = list(self.lines[start_line - 1 : end_line])
        truncated = len(selected) > MAX_SNIPPET_LINES
        if truncated:
            selected = selected[:MAX_SNIPPET_LINES]
        rendered = [_clamp(line) for line in selected]
        if truncated:
            rendered.append(TRUNCATION_MARKER)
        text = "\n".join(rendered)
        # `CandidateLocation.code_snippet` requires at least one character, and
        # a one-line location can legitimately land on a blank line.
        return text or BLANK_MARKER


def _clamp(line: str) -> str:
    stripped = line.rstrip("\r")
    if len(stripped) <= MAX_SNIPPET_LINE_CHARS:
        return stripped
    return stripped[:MAX_SNIPPET_LINE_CHARS] + "…"


def read_files(archive_path: Path, paths: set[str]) -> dict[str, FileText]:
    """Read the requested Snapshot-relative paths in a single archive pass.

    Missing paths are simply absent from the result; the caller decides what a
    missing path means for the candidate that claimed it. Members that are not
    regular files, that escape the archive root, or that exceed
    ``MAX_FILE_BYTES`` are skipped for the same reason — the caller's "this
    path is not in the Snapshot" branch is the correct handling for all of
    them.
    """

    if not paths:
        return {}
    wanted = {
        normalized
        for normalized in (_normalize(path) for path in paths)
        if normalized is not None
    }
    if not wanted:
        return {}
    found: dict[str, FileText] = {}
    try:
        with tarfile.open(archive_path, mode="r:") as archive:
            entries = 0
            for member in archive:
                entries += 1
                if entries > MAX_ARCHIVE_ENTRIES:
                    raise SnippetUnavailable(
                        "PIPELINE_SNAPSHOT_INVALID",
                        "Snapshot archive has too many entries",
                    )
                if not member.isfile():
                    continue
                name = _normalize(member.name)
                if name is None or name not in wanted or name in found:
                    continue
                if member.size > MAX_FILE_BYTES:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    continue
                raw = stream.read(MAX_FILE_BYTES + 1)
                if len(raw) > MAX_FILE_BYTES:
                    continue
                found[name] = FileText(
                    tuple(raw.decode("utf-8", errors="replace").splitlines())
                )
                if len(found) == len(wanted):
                    break
    except SnippetUnavailable:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise SnippetUnavailable(
            "PIPELINE_SNAPSHOT_INVALID",
            "Snapshot archive could not be read",
        ) from exc
    return found


def _normalize(value: str) -> str | None:
    """Reduce an archive member name to a Snapshot-relative POSIX path."""

    rendered = str(value).replace("\\", "/").strip()
    if not rendered or rendered.startswith("/"):
        return None
    path = PurePosixPath(rendered)
    if path.is_absolute() or any(part in {"..", ""} for part in path.parts):
        return None
    return path.as_posix()
