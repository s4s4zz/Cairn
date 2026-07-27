"""Read-only Tool Broker for the AI Semantic Reviewer (§7.5, §9.6, §9.7).

This module is the *entire* surface the model gets on the source tree, which
makes it a security boundary rather than a convenience layer. Three properties
carry that weight:

* **Closed set.** :data:`TOOL_NAMES`, :meth:`ToolBroker.tool_definitions` and
  :meth:`ToolBroker.invoke` are checked against each other at import time, so a
  tool cannot exist in one of the three and be missing from the others. An
  unrecognised name is an error, never a fallthrough.
* **Every path argument is validated by someone else.** Path arguments are
  resolved only through :class:`~cairn.analysis.normalizers.SourceCatalog`,
  the same hardened normalizer that gates scanner- and AI-claimed locations
  elsewhere. Absolute paths, ``..`` traversal, backslashes, ``file:`` URLs,
  symlinked entries and paths absent from the Snapshot all raise. This module
  deliberately contains no second implementation of that logic.
* **Every result is bounded and says so.** A silently capped list reads to the
  model as "that is everything", which would let it conclude that a sink does
  not exist. Every list-shaped payload therefore carries explicit ``returned``,
  ``truncated`` and ``truncated_reason`` fields, and the read window cap is
  enforced by rejecting the call rather than by quietly shortening it.
* **``search`` is bounded in time, not only in size.** ``pattern`` is the one
  argument that buys the model arbitrary computation: Python's ``re`` engine
  backtracks, so a pattern as ordinary-looking as ``.*a.*b`` runs for hours
  against a few kilobytes of one line. Size limits do not help — the blowup is
  in the pattern, not the input — so the scan also carries a wall-clock ceiling
  and refuses the nested-quantifier forms outright.

The module imports nothing that could execute a command, open a socket, read
the environment or write a byte: no ``subprocess``, no ``socket``, no
``requests``, no ``os``. ``signal`` and ``threading`` are imported solely to
arm and disarm the regex watchdog described above; neither grants a capability.
Source bytes are decoded as UTF-8 with ``errors="replace"`` so that one
undecodable file cannot abort a review.

Bounds are expressed in the tool *descriptions*, not as JSON Schema keywords.
The Messages API's strict tool schema subset does not support ``minimum``,
``maximum``, ``minLength`` or ``maxLength``; stating a limit the model can read
before it calls is the only version of that constraint that exists.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
import fnmatch
from pathlib import Path, PurePosixPath
import re
import signal
import threading
import time
from urllib.parse import unquote

from cairn.analysis.indexer import MAX_SOURCE_BYTES, build_inventory
from cairn.analysis.normalizers import NormalizationError, SourceCatalog


# --- Output bounds ---------------------------------------------------------
# Every one of these appears verbatim in a tool description: the model needs to
# know the limit before it spends a turn discovering it.
MAX_READ_LINES = 400
MAX_READ_BYTES = 64 * 1024
MAX_PATTERN_LENGTH = 512
MAX_SEARCH_MATCHES = 200
MAX_MATCH_CONTEXT = 200
MAX_SEARCH_RESULT_BYTES = 64 * 1024
MAX_SEARCH_FILES = 5_000
MAX_SEARCH_LINE_BYTES = 4_096
MAX_REGEX_GROUPS = 20
# Each additional unbounded run in a chain like `.*a.*b` multiplies the
# backtracking work by the line length. Measured against one 4 KiB line, two
# runs already cost seconds and four exceed the deadline, so the chain is held
# to a length that stays interactive.
MAX_REGEX_QUANTIFIERS = 3
# Wall-clock ceiling for one `search` scan. Python's `re` backtracks, so the
# cost of a pattern is unbounded in the pattern rather than in the input: the
# static guards below stop the classic exponential shapes, and this stops
# everything else. Generous enough that an honest scan of a large Snapshot
# never trips it.
SEARCH_DEADLINE_SECONDS = 10.0
MAX_MODULES = 200
MAX_MODULE_DEPENDENCIES = 500
MAX_SYMBOL_MATCHES = 200
MAX_ENTRYPOINTS = 200
MAX_SINKS = 200
MAX_INVENTORY_MODULES = 100
MAX_INVENTORY_KINDS = 50
MAX_INVENTORY_CWE_IDS = 64
MAX_SKIPPED_PATHS = 50
MAX_PATH_LENGTH = 1024
MAX_PATH_GLOB_LENGTH = 256
MAX_MODULE_LENGTH = 1024
MAX_SYMBOL_QUERY_LENGTH = 512
MAX_TEXT_FIELD = 2_048
MAX_LIST_FIELD = 32
_MAX_ERROR_HINTS = 20

BROKER_ERROR_CODES = frozenset(
    {
        "TOOL_UNKNOWN",
        "TOOL_ARGUMENTS_INVALID",
        "TOOL_ARGUMENT_UNKNOWN",
        "TOOL_ARGUMENT_MISSING",
        "TOOL_ARGUMENT_INVALID",
        "SOURCE_ROOT_INVALID",
        "PATH_INVALID",
        "PATH_GLOB_INVALID",
        "READ_RANGE_INVALID",
        "READ_WINDOW_TOO_LARGE",
        "READ_FAILED",
        "SEARCH_PATTERN_INVALID",
        "SEARCH_TIMED_OUT",
        "MODULE_UNKNOWN",
    }
)


class BrokerError(Exception):
    """A refused tool call.

    The broker refuses rather than repairs. ``code`` is a stable machine token
    for the audit log and ``message`` is written for the model, which sees it as
    an ``is_error`` tool result and is expected to correct its next call.
    """

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


TOOL_NAMES: frozenset[str] = frozenset(
    {
        "find_symbol",
        "list_entrypoints",
        "list_modules",
        "list_sinks",
        "read_file",
        "read_inventory",
        "search",
    }
)


@dataclass(frozen=True)
class _Param:
    """One tool argument.

    ``required_argument`` is about :meth:`ToolBroker.invoke`, not about the JSON
    Schema: strict tool use requires *every* property to appear in ``required``,
    so optionality is expressed as a nullable type union and enforced here.
    """

    name: str
    schema: dict[str, object]
    required_argument: bool = True


@dataclass(frozen=True)
class _ToolSpec:
    name: str
    description: str
    parameters: tuple[_Param, ...]
    handler: str


_TOOL_SPECS: tuple[_ToolSpec, ...] = (
    _ToolSpec(
        name="read_inventory",
        description=(
            "Summarise the deterministic index of the Snapshot: build system, "
            "Java versions, module list with per-module entrypoint and sink "
            "counts, record counts, entrypoint and sink kind histograms, and "
            "files the indexer skipped. This is a summary, not the symbol "
            f"table: at most {MAX_INVENTORY_MODULES} modules and "
            f"{MAX_INVENTORY_KINDS} kinds per histogram are listed, and the "
            "payload reports whether it was truncated. Use find_symbol, "
            "list_entrypoints and list_sinks for the records themselves. Call "
            "this first to orient yourself."
        ),
        parameters=(),
        handler="_read_inventory",
    ),
    _ToolSpec(
        name="list_modules",
        description=(
            "List the build modules of the Snapshot and the dependency edges "
            "between them. Each module reports its Snapshot-relative path, "
            "name, build system, descriptor, parent module, Java versions and "
            f"detected frameworks. At most {MAX_MODULES} modules and "
            f"{MAX_MODULE_DEPENDENCIES} dependency edges are returned; the "
            "payload reports the true totals and whether it was truncated. "
            "Module paths from this tool are the only accepted values for the "
            "'module' argument of list_entrypoints and list_sinks."
        ),
        parameters=(),
        handler="_list_modules",
    ),
    _ToolSpec(
        name="read_file",
        description=(
            "Read a bounded window of one file from the Snapshot. 'path' must "
            "be a Snapshot-relative POSIX path exactly as the index gives it; "
            "absolute paths, '..' segments, backslashes, URLs and paths outside "
            "the Snapshot are refused. Lines are 1-based and inclusive. The "
            f"window may span at most {MAX_READ_LINES} lines: a wider request "
            "is refused outright rather than silently shortened, so split the "
            f"read. Output is also capped at {MAX_READ_BYTES // 1024} KiB, and "
            "when that cap or the end of the file cuts the window short the "
            "payload says so in 'truncated', 'truncated_reason', 'end_line' and "
            "'eof'. Invalid UTF-8 is replaced, never fatal."
        ),
        parameters=(
            _Param(
                name="path",
                schema={
                    "type": "string",
                    "description": (
                        "Snapshot-relative POSIX path, exactly as the index "
                        "gives it, e.g. 'web/src/main/java/dev/cairn/"
                        "UserController.java'."
                    ),
                },
            ),
            _Param(
                name="start_line",
                schema={
                    "type": "integer",
                    "description": (
                        "First line to return, 1-based and inclusive. Must be a "
                        "whole number of at least 1; a string is refused."
                    ),
                },
            ),
            _Param(
                name="end_line",
                schema={
                    "type": "integer",
                    "description": (
                        "Last line to return, inclusive. Must be at least "
                        f"start_line and at most start_line + "
                        f"{MAX_READ_LINES - 1}."
                    ),
                },
            ),
        ),
        handler="_read_file",
    ),
    _ToolSpec(
        name="search",
        description=(
            "Search the text of the Snapshot and return the path and line "
            "number of each match with a short excerpt. By default 'pattern' is "
            "a literal, case-sensitive substring; set 'regex' true to compile "
            "it as a Python regular expression instead, in which case a "
            "malformed pattern is refused. Patterns are limited to "
            f"{MAX_PATTERN_LENGTH} characters, matching is per line and only "
            f"the first {MAX_SEARCH_LINE_BYTES} bytes of a line are examined. "
            f"At most {MAX_SEARCH_MATCHES} matches, {MAX_MATCH_CONTEXT} "
            "characters of excerpt per match — centred on the match, with '…' "
            "marking where a long line was trimmed — and "
            f"{MAX_SEARCH_RESULT_BYTES // 1024} KiB in total are returned; when "
            "a cap is reached 'truncated' is true and there are more matches "
            "than you were shown, so narrow the pattern or the glob. A regex "
            "that nests one unbounded quantifier inside another, such as "
            "'(a+)+', is refused, and the whole scan is abandoned if it "
            f"exceeds {SEARCH_DEADLINE_SECONDS:.0f} seconds; prefer a literal "
            "substring, which is never subject to either limit."
        ),
        parameters=(
            _Param(
                name="pattern",
                schema={
                    "type": "string",
                    "description": (
                        "Literal substring to find, or a regular expression "
                        "when 'regex' is true. At most "
                        f"{MAX_PATTERN_LENGTH} characters."
                    ),
                },
            ),
            _Param(
                name="path_glob",
                schema={
                    "type": ["string", "null"],
                    "description": (
                        "Optional glob restricting the search, matched against "
                        "Snapshot-relative POSIX paths, e.g. "
                        "'core/**' or '*.java'. '*' also matches '/', so "
                        "'*.java' reaches nested files. Null searches every "
                        "file in the Snapshot. Absolute globs, '..' segments "
                        "and backslashes are refused."
                    ),
                },
                required_argument=False,
            ),
            _Param(
                name="regex",
                schema={
                    "type": ["boolean", "null"],
                    "description": (
                        "True to treat 'pattern' as a Python regular "
                        "expression. Null or false means literal substring, "
                        "which is what you usually want."
                    ),
                },
                required_argument=False,
            ),
        ),
        handler="_search",
    ),
    _ToolSpec(
        name="find_symbol",
        description=(
            "Find indexed Java symbols — packages, types, methods and "
            "annotations — whose name or fully qualified name contains 'name', "
            "case-insensitively. Each result gives the Snapshot-relative path, "
            "line, kind, name and declaring container, which is what you need "
            "to build a call chain. At most "
            f"{MAX_SYMBOL_MATCHES} results are returned; the payload reports "
            "the true total and whether it was truncated, so a truncated result "
            "is not evidence that nothing else matches."
        ),
        parameters=(
            _Param(
                name="name",
                schema={
                    "type": "string",
                    "description": (
                        "Symbol name or fragment, e.g. 'UserController', "
                        "'find' or 'dev.cairn.UserRepository'. At most "
                        f"{MAX_SYMBOL_QUERY_LENGTH} characters."
                    ),
                },
            ),
        ),
        handler="_find_symbol",
    ),
    _ToolSpec(
        name="list_entrypoints",
        description=(
            "List the externally reachable entrypoints the indexer found: HTTP "
            "controllers and routes, message consumers, scheduled tasks and "
            "similar, each with path, line, kind, symbol, route and "
            "annotations. Pass 'module' to restrict the result to one module "
            "path from list_modules, or null for the whole Snapshot. At most "
            f"{MAX_ENTRYPOINTS} entrypoints are returned; the payload reports "
            "the true total and whether it was truncated. The index is a "
            "starting point, not a proof of completeness: an entrypoint absent "
            "here may still exist in code."
        ),
        parameters=(
            _Param(
                name="module",
                schema={
                    "type": ["string", "null"],
                    "description": (
                        "Module path from list_modules, e.g. 'web'. Null, or "
                        "the root module '.', covers the whole Snapshot. An "
                        "unknown module is refused rather than returning an "
                        "empty list."
                    ),
                },
                required_argument=False,
            ),
        ),
        handler="_list_entrypoints",
    ),
    _ToolSpec(
        name="list_sinks",
        description=(
            "List the dangerous operations the indexer found — database "
            "queries, command execution, deserialization, file and network "
            "access — each with path, line, kind, symbol and associated CWE "
            "identifiers. Pass 'module' to restrict the result to one module "
            "path from list_modules, or null for the whole Snapshot. At most "
            f"{MAX_SINKS} sinks are returned; the payload reports the true "
            "total and whether it was truncated. The index is pattern-derived: "
            "absence here is not evidence that a sink does not exist, so "
            "confirm reachability by reading the code."
        ),
        parameters=(
            _Param(
                name="module",
                schema={
                    "type": ["string", "null"],
                    "description": (
                        "Module path from list_modules, e.g. 'core'. Null, or "
                        "the root module '.', covers the whole Snapshot. An "
                        "unknown module is refused rather than returning an "
                        "empty list."
                    ),
                },
                required_argument=False,
            ),
        ),
        handler="_list_sinks",
    ),
)


class _SearchTimeout(Exception):
    """Internal: the regex watchdog fired. Never escapes :meth:`_search`."""


_UNBOUNDED_RUN = re.compile(r"(?<!\\)(?:\.|\[[^\]]*\]|\\[wWsSdD])\s*[*+]")


def _has_nested_quantifier(pattern: str) -> bool:
    """True if an unbounded quantifier is applied to a group that can already
    match a variable number of characters — the ``(a+)+`` / ``(a|a)*`` shapes.

    This is a scan rather than a regex because the thing being detected is
    nesting, and a regex cannot count parentheses. It walks the pattern once,
    tracking escape state, character classes and group depth, and for each
    closing parenthesis asks two questions: does the group body contain an
    unbounded quantifier or a top-level alternation, and is the group itself
    repeated without bound. Both true is the exponential form.

    False positives are acceptable here and false negatives are not: refusing
    ``(foo|bar)*`` costs the model one retry with a literal search, while
    accepting ``(a|ab)*`` costs the review its wall clock.
    """

    starts: list[int] = []
    alternation: list[bool] = []
    index = 0
    length = len(pattern)
    in_class = False
    while index < length:
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
            index += 1
            continue
        if char == "(":
            starts.append(index)
            alternation.append(False)
            index += 1
            continue
        if char == "|" and alternation:
            alternation[-1] = True
            index += 1
            continue
        if char == ")" and starts:
            start = starts.pop()
            had_alternation = alternation.pop()
            body = pattern[start + 1 : index]
            follower = pattern[index + 1 : index + 2]
            repeated = follower in {"*", "+"} or (
                follower == "{"
                and re.match(r"\{\d*,\}", pattern[index + 1 :]) is not None
            )
            if repeated and (had_alternation or _quantifies_unbounded(body)):
                return True
            index += 1
            continue
        index += 1
    return False


def _quantifies_unbounded(body: str) -> bool:
    """True if ``body`` contains an unescaped ``*``, ``+`` or ``{n,}``."""

    index = 0
    in_class = False
    while index < len(body):
        char = body[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
            index += 1
            continue
        if char == "[":
            in_class = True
        elif char in {"*", "+"}:
            return True
        elif char == "{" and re.match(r"\{\d*,\}", body[index:]) is not None:
            return True
        index += 1
    return False


@contextmanager
def _deadline(seconds: float) -> Iterator[None]:
    """Interrupt a runaway regex scan after ``seconds``.

    CPython checks for signals between bytecode instructions *and* inside the
    ``re`` engine's backtracking loop, so ``SIGALRM`` is the one mechanism that
    can actually preempt a catastrophic match — verified empirically, not
    assumed. It is only available on the main thread of the main interpreter;
    off it, ``signal.setitimer`` raises and we fall back to the static pattern
    guards plus the size caps, which is why those are not optional.
    """

    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _fire(signum: int, frame: object) -> None:
        raise _SearchTimeout

    try:
        previous = signal.signal(signal.SIGALRM, _fire)
    except (AttributeError, ValueError):  # pragma: no cover - platform guard
        yield
        return
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def _text(value: object, *, limit: int = MAX_TEXT_FIELD) -> str | None:
    """Render an index field as bounded text, or ``None`` when absent."""

    if value is None:
        return None
    rendered = str(value)
    return rendered[:limit]


def _clamp_utf8(value: str, limit: int) -> str:
    """Trim ``value`` to at most ``limit`` UTF-8 bytes without splitting a char."""

    encoded = value.encode("utf-8")
    if len(encoded) <= limit:
        return value
    return encoded[:limit].decode("utf-8", errors="ignore")


def _excerpt(line: str, match_start: int) -> str:
    """Return at most ``MAX_MATCH_CONTEXT`` characters around the match.

    A fixed head slice would report matches that are not in the text it shows:
    on a long line the match can sit past the cut, which reads as a false
    positive. The window is centred on the match instead, and an elision marker
    makes the trim visible rather than implied.
    """

    stripped = line.strip()
    if len(stripped) <= MAX_MATCH_CONTEXT:
        return stripped
    offset = match_start - (len(line) - len(line.lstrip()))
    half = MAX_MATCH_CONTEXT // 2
    begin = max(0, min(offset - half, len(stripped) - MAX_MATCH_CONTEXT))
    end = begin + MAX_MATCH_CONTEXT
    window = stripped[begin:end]
    if begin > 0:
        window = f"…{window[1:]}"
    if end < len(stripped):
        window = f"{window[:-1]}…"
    return window


def _line_of(record: Mapping[str, object]) -> int:
    value = record.get("line")
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return value if value >= 0 else 0


def _string_list(
    value: object,
    *,
    limit: int = MAX_LIST_FIELD,
    item_limit: int = MAX_TEXT_FIELD,
) -> list[str]:
    if isinstance(value, str) or not isinstance(value, Sequence):
        return []
    return [str(item)[:item_limit] for item in value[:limit]]


def _as_mapping(item: object) -> dict[str, object] | None:
    """Accept either a plain index dict or a pydantic record."""

    dump = getattr(item, "model_dump", None)
    if callable(dump):
        try:
            item = dump(mode="json")
        except TypeError:
            item = dump()
    if isinstance(item, Mapping):
        return {str(key): value for key, value in item.items()}
    return None


def _sort_key(record: Mapping[str, object]) -> tuple[bytes, int]:
    return (str(record.get("path") or "").encode("utf-8"), _line_of(record))


def _bounded(
    records: list[dict[str, object]],
    *,
    limit: int,
    label: str,
    advice: str = "Narrow the query.",
) -> tuple[list[dict[str, object]], dict[str, object]]:
    """Cap a result list and describe the cap in the payload.

    A cap the model cannot see is worse than no result at all: it reads as a
    complete answer. The returned metadata always states the true total.
    """

    total = len(records)
    kept = records[:limit]
    truncated = total > limit
    meta: dict[str, object] = {
        "total": total,
        "returned": len(kept),
        "truncated": truncated,
        "truncated_reason": (
            f"{total} {label} matched; only the first {limit} are shown. "
            f"{advice}"
            if truncated
            else None
        ),
    }
    return kept, meta


class ToolBroker:
    """Dispatches the closed, read-only tool set against one Snapshot."""

    def __init__(
        self,
        source_root: Path,
        *,
        inventory: dict | None = None,
        catalog: SourceCatalog | None = None,
    ) -> None:
        root = Path(source_root)
        try:
            resolved_root = root.resolve()
            is_directory = resolved_root.is_dir()
        except OSError as exc:  # pragma: no cover - defensive
            raise BrokerError(
                "SOURCE_ROOT_INVALID",
                "source root could not be resolved",
            ) from exc
        if not is_directory:
            raise BrokerError(
                "SOURCE_ROOT_INVALID",
                "source root is not an existing directory",
            )
        self._source_root = resolved_root
        self._catalog = catalog
        self._inventory: dict[str, object] | None = (
            dict(inventory) if inventory is not None else None
        )
        self._call_count = 0

    # -- lifecycle ---------------------------------------------------------

    @property
    def catalog(self) -> SourceCatalog:
        if self._catalog is None:
            self._catalog = SourceCatalog(self._source_root)
        return self._catalog

    @property
    def source_root(self) -> Path:
        return self._source_root

    def call_count(self) -> int:
        """Total :meth:`invoke` calls, refusals included.

        Refused calls count: a budget that ignored them would let a loop of
        malformed calls run for free.
        """

        return self._call_count

    def _index(self) -> dict[str, object]:
        if self._inventory is None:
            self._inventory = dict(build_inventory(self._source_root))
        return self._inventory

    def _records(self, key: str) -> list[dict[str, object]]:
        raw = self._index().get(key)
        if isinstance(raw, str) or not isinstance(raw, Sequence):
            return []
        records: list[dict[str, object]] = []
        for item in raw:
            mapping = _as_mapping(item)
            if mapping is not None:
                records.append(mapping)
        return records

    # -- tool definitions --------------------------------------------------

    def tool_definitions(self) -> list[dict[str, object]]:
        """Anthropic tool definitions for the closed set.

        ``strict`` is a top-level field on each definition, and every
        ``input_schema`` sets ``additionalProperties: False`` with an explicit
        ``required`` naming every property — optional arguments are nullable
        unions, not omissions. Order is stable so the tool block stays a
        cacheable prefix.
        """

        definitions: list[dict[str, object]] = []
        for spec in _TOOL_SPECS:
            properties = {
                parameter.name: dict(parameter.schema)
                for parameter in spec.parameters
            }
            definitions.append(
                {
                    "name": spec.name,
                    "description": spec.description,
                    "strict": True,
                    "input_schema": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": properties,
                        "required": [
                            parameter.name for parameter in spec.parameters
                        ],
                    },
                }
            )
        return definitions

    # -- dispatch ----------------------------------------------------------

    def invoke(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        """The single entry point. Unknown names and unknown keys are refused."""

        self._call_count += 1
        if not isinstance(name, str) or name not in TOOL_NAMES:
            raise BrokerError(
                "TOOL_UNKNOWN",
                "no such tool; the available tools are "
                f"{', '.join(sorted(TOOL_NAMES))}",
            )
        spec = _SPECS_BY_NAME[name]
        if not isinstance(arguments, Mapping):
            raise BrokerError(
                "TOOL_ARGUMENTS_INVALID",
                f"arguments for {name} must be an object",
            )
        supplied = {str(key): value for key, value in arguments.items()}
        allowed = {parameter.name for parameter in spec.parameters}
        unknown = sorted(set(supplied) - allowed)
        if unknown:
            raise BrokerError(
                "TOOL_ARGUMENT_UNKNOWN",
                f"{name} does not accept the argument(s) "
                f"{', '.join(unknown)}; accepted arguments are "
                f"{', '.join(sorted(allowed)) or 'none'}",
            )
        missing = sorted(
            parameter.name
            for parameter in spec.parameters
            if parameter.required_argument and parameter.name not in supplied
        )
        if missing:
            raise BrokerError(
                "TOOL_ARGUMENT_MISSING",
                f"{name} requires the argument(s) {', '.join(missing)}",
            )
        handler = getattr(self, _HANDLERS[name])
        payload = dict(handler(supplied))
        # Written last so no handler can shadow the tool label its result is
        # attributed to.
        payload["tool"] = name
        return payload

    # -- argument helpers --------------------------------------------------

    @staticmethod
    def _string_argument(
        arguments: Mapping[str, object],
        field: str,
        *,
        limit: int,
    ) -> str:
        value = arguments.get(field)
        if not isinstance(value, str):
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                f"{field} must be a string",
            )
        if not value.strip():
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                f"{field} must not be blank",
            )
        if len(value) > limit:
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                f"{field} must be at most {limit} characters",
            )
        return value

    @staticmethod
    def _integer_argument(arguments: Mapping[str, object], field: str) -> int:
        value = arguments.get(field)
        # bool is an int in Python; a model that sends true for a line number
        # has made a mistake worth surfacing, not worth silently reading as 1.
        if isinstance(value, bool) or not isinstance(value, int):
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                f"{field} must be a whole number, not "
                f"{type(value).__name__}; nothing is coerced",
            )
        return value

    @staticmethod
    def _optional_boolean(
        arguments: Mapping[str, object],
        field: str,
        *,
        default: bool,
    ) -> bool:
        value = arguments.get(field)
        if value is None:
            return default
        if not isinstance(value, bool):
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                f"{field} must be true, false or null",
            )
        return value

    def _normalized_path(self, value: str) -> str:
        """Resolve a model-supplied path through the Snapshot catalog.

        The catalog is the only path validator in the platform; reimplementing
        its rules here would create a second, divergent one. The pre-check below
        is not a second validator but a narrower contract: the catalog tolerates
        backslashes, ``file:`` URLs and ``/work/source`` prefixes because real
        scanner output contains them, whereas the model is told to send Snapshot
        -relative POSIX paths and gets an error instead of a quiet rewrite when
        it does not. Everything that survives the pre-check is still resolved by
        the catalog, so membership and traversal remain its decision.
        """

        probed = unquote(str(value)).strip()
        if "\\" in probed:
            raise BrokerError(
                "PATH_INVALID",
                "path must use '/' separators, not backslashes",
            )
        if ":" in probed.split("/", 1)[0]:
            raise BrokerError(
                "PATH_INVALID",
                "path must be a Snapshot-relative path, not a URL",
            )
        try:
            # The raw value, not the probe: the catalog does its own unquoting
            # and decoding twice would change what it sees.
            return self.catalog.normalize_path(value)
        except NormalizationError as exc:
            raise BrokerError(
                "PATH_INVALID",
                f"{exc}; use a Snapshot-relative path exactly as the index "
                "gives it",
            ) from exc

    def _open_path(self, relative: str) -> Path:
        """Map a catalog-normalised path to a file, following no symlinks.

        :class:`SourceCatalog` already skips symlinks when it indexes the tree,
        so a symlinked entry never becomes a normalisable path. This re-checks
        at read time anyway: the guard is cheap, and it keeps the invariant true
        even if the catalog is ever replaced or the tree changes underneath us.
        """

        root = self.catalog.root
        candidate = root / PurePosixPath(relative)
        try:
            resolved = candidate.resolve()
            is_symlink = candidate.is_symlink()
            is_file = resolved.is_file()
        except OSError as exc:
            raise BrokerError(
                "READ_FAILED",
                "file could not be opened",
            ) from exc
        if is_symlink or resolved != candidate or not is_file:
            raise BrokerError(
                "PATH_INVALID",
                "path is not a regular file inside the Snapshot",
            )
        if not resolved.is_relative_to(root):
            raise BrokerError(
                "PATH_INVALID",
                "path escapes the Snapshot root",
            )
        return resolved

    @staticmethod
    def _normalized_glob(value: str) -> str:
        """Validate a search glob.

        A glob is not a path, so it cannot go through ``normalize_path`` — but
        it is refused on the same grounds, and it only ever filters paths the
        catalog already vouched for, so no glob can reach outside the Snapshot.
        """

        rendered = value.strip()
        if "\\" in rendered:
            raise BrokerError(
                "PATH_GLOB_INVALID",
                "path_glob must use '/' separators, not backslashes",
            )
        if rendered.startswith("file:"):
            raise BrokerError(
                "PATH_GLOB_INVALID",
                "path_glob must not be a URL",
            )
        for prefix in ("/work/source/", "work/source/"):
            if rendered.startswith(prefix):
                rendered = rendered[len(prefix) :]
                break
        if rendered.startswith("/"):
            raise BrokerError(
                "PATH_GLOB_INVALID",
                "path_glob must be Snapshot-relative, not absolute",
            )
        if rendered.startswith("./"):
            rendered = rendered[2:]
        if not rendered:
            raise BrokerError(
                "PATH_GLOB_INVALID",
                "path_glob must not be blank; pass null to search everything",
            )
        if any(part == ".." for part in PurePosixPath(rendered).parts):
            raise BrokerError(
                "PATH_GLOB_INVALID",
                "path_glob must not contain '..' segments",
            )
        return rendered

    def _module_predicate(
        self,
        arguments: Mapping[str, object],
    ) -> tuple[Callable[[Mapping[str, object]], bool] | None, str | None]:
        """Build the module filter for list_entrypoints / list_sinks.

        ``module`` names a directory, so the catalog (which indexes files) is
        the wrong validator. It is checked against the enumerated module paths
        instead, which is a closed set — an unknown module is refused rather
        than answered with an empty list the model would read as "no sinks".
        """

        value = arguments.get("module")
        if value is None:
            return None, None
        module = self._string_argument(arguments, "module", limit=MAX_MODULE_LENGTH)
        if "\\" in module:
            raise BrokerError(
                "TOOL_ARGUMENT_INVALID",
                "module must use '/' separators, not backslashes",
            )
        module = module.strip().rstrip("/")
        if module.startswith("./"):
            module = module[2:]
        if module in {"", ".", "/"}:
            return None, "."
        known = {
            str(record.get("path") or "")
            for record in self._records("modules")
        }
        if module not in known:
            hints = ", ".join(sorted(known)[:_MAX_ERROR_HINTS]) or "none"
            raise BrokerError(
                "MODULE_UNKNOWN",
                f"module '{module}' is not in the index; known module paths "
                f"are {hints}. Call list_modules first.",
            )

        prefix = f"{module}/"

        def predicate(record: Mapping[str, object]) -> bool:
            path = str(record.get("path") or "")
            return path == module or path.startswith(prefix)

        return predicate, module

    # -- tools -------------------------------------------------------------

    def _read_inventory(self, arguments: Mapping[str, object]) -> dict[str, object]:
        index = self._index()
        modules = sorted(self._records("modules"), key=_sort_key)
        entrypoints = self._records("entrypoints")
        sinks = self._records("sinks")
        sources = self._records("sources")
        permissions = self._records("permissions")
        symbols = self._records("symbols")
        dependencies = self._records("module_dependencies")

        def counts_for(module_path: str, records: list[dict[str, object]]) -> int:
            if module_path in {"", "."}:
                return len(records)
            prefix = f"{module_path}/"
            return sum(
                1
                for record in records
                if str(record.get("path") or "") == module_path
                or str(record.get("path") or "").startswith(prefix)
            )

        module_summaries = [
            {
                "path": _text(record.get("path"), limit=MAX_PATH_LENGTH),
                "name": _text(record.get("name")),
                "build_system": _text(record.get("build_system")),
                "entrypoint_count": counts_for(
                    str(record.get("path") or ""), entrypoints
                ),
                "sink_count": counts_for(str(record.get("path") or ""), sinks),
            }
            for record in modules
        ]
        kept_modules, module_meta = _bounded(
            module_summaries,
            limit=MAX_INVENTORY_MODULES,
            label="modules",
            advice="Call list_modules for the rest.",
        )
        entrypoint_kinds = self._histogram(entrypoints)
        sink_kinds = self._histogram(sinks)
        cwe_ids: set[str] = set()
        for record in sinks:
            cwe_ids.update(_string_list(record.get("cwe_ids"), limit=MAX_LIST_FIELD))
        skipped = sorted(
            str(item)[:MAX_PATH_LENGTH]
            for item in _string_list(index.get("skipped_paths"), limit=1024)
        )
        unsupported = self._records("unsupported_components")
        java_files_total = index.get("java_files_total")
        return {
            "build_system": _text(index.get("build_system")) or "unknown",
            "java_versions": _string_list(index.get("java_versions")),
            "modules": kept_modules,
            "modules_meta": module_meta,
            "counts": {
                "modules": len(modules),
                "module_dependencies": len(dependencies),
                "symbols": len(symbols),
                "entrypoints": len(entrypoints),
                "sources": len(sources),
                "sinks": len(sinks),
                "permissions": len(permissions),
                "java_files": (
                    java_files_total
                    if isinstance(java_files_total, int)
                    and not isinstance(java_files_total, bool)
                    else 0
                ),
                "snapshot_files": len(self.catalog.paths),
                "unsupported_components": len(unsupported),
            },
            "entrypoint_kinds": entrypoint_kinds[0],
            "entrypoint_kinds_truncated": entrypoint_kinds[1],
            "sink_kinds": sink_kinds[0],
            "sink_kinds_truncated": sink_kinds[1],
            "sink_cwe_ids": sorted(cwe_ids)[:MAX_INVENTORY_CWE_IDS],
            "skipped_paths": skipped[:MAX_SKIPPED_PATHS],
            "skipped_paths_truncated": len(skipped) > MAX_SKIPPED_PATHS,
            "truncated": bool(
                module_meta["truncated"]
                or entrypoint_kinds[1]
                or sink_kinds[1]
                or len(skipped) > MAX_SKIPPED_PATHS
            ),
            "notes": (
                "Summary only. The symbol table is not included here: use "
                "find_symbol for symbols, list_entrypoints and list_sinks for "
                "records, read_file for source. The index is pattern-derived, "
                "so absence from it is not proof of absence in the code."
            ),
        }

    @staticmethod
    def _histogram(
        records: list[dict[str, object]],
    ) -> tuple[dict[str, int], bool]:
        tally: dict[str, int] = {}
        for record in records:
            kind = _text(record.get("kind"), limit=128) or "unknown"
            tally[kind] = tally.get(kind, 0) + 1
        ordered = sorted(tally.items(), key=lambda item: (-item[1], item[0]))
        return dict(ordered[:MAX_INVENTORY_KINDS]), len(ordered) > MAX_INVENTORY_KINDS

    def _list_modules(self, arguments: Mapping[str, object]) -> dict[str, object]:
        index = self._index()
        modules = [
            {
                "path": _text(record.get("path"), limit=MAX_PATH_LENGTH),
                "name": _text(record.get("name")),
                "build_system": _text(record.get("build_system")),
                "descriptor": _text(record.get("descriptor"), limit=MAX_PATH_LENGTH),
                "parent_path": _text(
                    record.get("parent_path"), limit=MAX_PATH_LENGTH
                ),
                "java_versions": _string_list(record.get("java_versions")),
                "frameworks": _string_list(record.get("frameworks")),
            }
            for record in sorted(self._records("modules"), key=_sort_key)
        ]
        dependencies = [
            {
                "source": _text(record.get("source"), limit=MAX_PATH_LENGTH),
                "target": _text(record.get("target"), limit=MAX_PATH_LENGTH),
                "kind": _text(record.get("kind"), limit=128),
            }
            for record in self._records("module_dependencies")
        ]
        dependencies.sort(
            key=lambda item: (
                str(item["source"] or ""),
                str(item["target"] or ""),
                str(item["kind"] or ""),
            )
        )
        kept_modules, module_meta = _bounded(
            modules,
            limit=MAX_MODULES,
            label="modules",
        )
        kept_dependencies, dependency_meta = _bounded(
            dependencies,
            limit=MAX_MODULE_DEPENDENCIES,
            label="module dependencies",
        )
        return {
            "build_system": _text(index.get("build_system")) or "unknown",
            "java_versions": _string_list(index.get("java_versions")),
            "modules": kept_modules,
            "modules_meta": module_meta,
            "module_dependencies": kept_dependencies,
            "module_dependencies_meta": dependency_meta,
            "truncated": bool(
                module_meta["truncated"] or dependency_meta["truncated"]
            ),
        }

    def _read_file(self, arguments: Mapping[str, object]) -> dict[str, object]:
        raw_path = self._string_argument(arguments, "path", limit=MAX_PATH_LENGTH)
        start = self._integer_argument(arguments, "start_line")
        end = self._integer_argument(arguments, "end_line")
        path = self._normalized_path(raw_path)
        if start < 1:
            raise BrokerError(
                "READ_RANGE_INVALID",
                "start_line must be at least 1; lines are 1-based",
            )
        if end < start:
            raise BrokerError(
                "READ_RANGE_INVALID",
                "end_line must not precede start_line",
            )
        window = end - start + 1
        if window > MAX_READ_LINES:
            raise BrokerError(
                "READ_WINDOW_TOO_LARGE",
                f"read_file returns at most {MAX_READ_LINES} lines per call and "
                f"{window} were requested; this call is refused rather than "
                "truncated, so issue consecutive narrower reads",
            )
        target = self._open_path(path)
        lines: list[str] = []
        # Bytes are counted after decoding, not before: one undecodable byte
        # becomes a three-byte replacement character, so a raw-byte budget would
        # let the payload grow to three times the stated cap.
        payload_bytes = 0
        truncated = False
        truncated_reason: str | None = None
        cap_reason = (
            f"output reached the {MAX_READ_BYTES // 1024} KiB cap before the "
            "requested end_line; continue from the reported end_line"
        )
        first_line: int | None = None
        last_line = start - 1
        reached_end = True
        index = 0
        try:
            with target.open("rb") as stream:
                for raw_line in stream:
                    index += 1
                    if index < start:
                        continue
                    if index > end:
                        reached_end = False
                        break
                    decoded = raw_line.decode("utf-8", errors="replace")
                    text_line = decoded.rstrip("\n").rstrip("\r")
                    size = len(text_line.encode("utf-8")) + (1 if lines else 0)
                    if payload_bytes + size > MAX_READ_BYTES:
                        truncated = True
                        reached_end = False
                        truncated_reason = cap_reason
                        if not lines:
                            # One line longer than the whole cap still yields a
                            # prefix: an empty payload would read as an empty
                            # file.
                            text_line = _clamp_utf8(text_line, MAX_READ_BYTES)
                            lines.append(text_line)
                            payload_bytes = len(text_line.encode("utf-8"))
                            first_line = index
                            last_line = index
                        break
                    payload_bytes += size
                    lines.append(text_line)
                    if first_line is None:
                        first_line = index
                    last_line = index
        except OSError as exc:
            raise BrokerError(
                "READ_FAILED",
                "file could not be read from the Snapshot",
            ) from exc
        notice: str | None = None
        if not lines:
            notice = (
                f"the file has {index} line(s); the requested window starts "
                "past the end of the file"
            )
        return {
            "path": path,
            "requested_start_line": start,
            "requested_end_line": end,
            "start_line": first_line if first_line is not None else start,
            "end_line": last_line,
            "line_count": len(lines),
            "file_line_count": index if reached_end else None,
            "eof": reached_end,
            "bytes": payload_bytes,
            "truncated": truncated,
            "truncated_reason": truncated_reason,
            "notice": notice,
            "encoding": "utf-8 with invalid sequences replaced",
            "text": "\n".join(lines),
        }

    def _search(self, arguments: Mapping[str, object]) -> dict[str, object]:
        pattern = self._string_argument(
            arguments,
            "pattern",
            limit=MAX_PATTERN_LENGTH,
        )
        use_regex = self._optional_boolean(arguments, "regex", default=False)
        raw_glob = arguments.get("path_glob")
        glob: str | None = None
        if raw_glob is not None:
            glob = self._normalized_glob(
                self._string_argument(
                    arguments,
                    "path_glob",
                    limit=MAX_PATH_GLOB_LENGTH,
                )
            )
        matcher = self._compile(pattern, use_regex=use_regex)
        candidates = sorted(
            path
            for path in self.catalog.paths
            if glob is None or fnmatch.fnmatchcase(path, glob)
        )
        matches: list[dict[str, object]] = []
        skipped: list[dict[str, object]] = []
        files_scanned = 0
        result_bytes = 0
        truncated = False
        truncated_reason: str | None = None
        started = time.monotonic()
        try:
            with _deadline(SEARCH_DEADLINE_SECONDS):
                (
                    files_scanned,
                    result_bytes,
                    truncated,
                    truncated_reason,
                ) = self._scan(
                    candidates,
                    matcher,
                    matches=matches,
                    skipped=skipped,
                )
        except _SearchTimeout as exc:
            raise BrokerError(
                "SEARCH_TIMED_OUT",
                f"search exceeded its {SEARCH_DEADLINE_SECONDS:.0f} second "
                "budget and was stopped; the pattern is too expensive to "
                "match. Use a literal substring, a narrower path_glob, or a "
                "pattern without chained '.*' runs",
            ) from exc
        return {
            "pattern": pattern,
            "regex": use_regex,
            "path_glob": glob,
            "files_scanned": files_scanned,
            "files_available": len(candidates),
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "matches": matches,
            "returned": len(matches),
            "truncated": truncated,
            "truncated_reason": truncated_reason,
            "skipped_files": skipped[:MAX_SKIPPED_PATHS],
            "skipped_file_count": len(skipped),
            "notes": (
                "Match count is not a total: results stop at the caps stated "
                "in the tool description."
            ),
        }

    def _scan(
        self,
        candidates: list[str],
        matcher: re.Pattern[str],
        *,
        matches: list[dict[str, object]],
        skipped: list[dict[str, object]],
    ) -> tuple[int, int, bool, str | None]:
        """Walk the candidate files. Mutates ``matches``/``skipped`` in place.

        The caller owns the lists so that a watchdog interrupt mid-scan leaves
        them inspectable rather than lost inside an abandoned frame.
        """

        files_scanned = 0
        result_bytes = 0
        truncated = False
        truncated_reason: str | None = None
        for relative in candidates:
            if files_scanned >= MAX_SEARCH_FILES:
                truncated = True
                truncated_reason = (
                    f"stopped after scanning {MAX_SEARCH_FILES} files; narrow "
                    "path_glob"
                )
                break
            try:
                target = self._open_path(relative)
                size = target.stat().st_size
            except (BrokerError, OSError):
                skipped.append({"path": relative, "reason": "unreadable"})
                continue
            if size > MAX_SOURCE_BYTES:
                skipped.append({"path": relative, "reason": "file-too-large"})
                continue
            files_scanned += 1
            try:
                with target.open("rb") as stream:
                    for number, raw_line in enumerate(stream, start=1):
                        probe = raw_line[:MAX_SEARCH_LINE_BYTES]
                        decoded = probe.decode("utf-8", errors="replace")
                        found = matcher.search(decoded)
                        if found is None:
                            continue
                        excerpt = _excerpt(decoded, found.start())
                        entry = {
                            "path": relative,
                            "line": number,
                            "text": excerpt,
                            "line_truncated": len(raw_line) > len(probe),
                        }
                        entry_bytes = len(excerpt.encode("utf-8")) + len(
                            relative.encode("utf-8")
                        )
                        if (
                            len(matches) >= MAX_SEARCH_MATCHES
                            or result_bytes + entry_bytes > MAX_SEARCH_RESULT_BYTES
                        ):
                            truncated = True
                            truncated_reason = (
                                "more matches exist than are shown: the cap of "
                                f"{MAX_SEARCH_MATCHES} matches or "
                                f"{MAX_SEARCH_RESULT_BYTES // 1024} KiB was "
                                "reached. Narrow the pattern or path_glob."
                            )
                            break
                        result_bytes += entry_bytes
                        matches.append(entry)
            except OSError:
                skipped.append({"path": relative, "reason": "unreadable"})
                continue
            if truncated:
                break
        return files_scanned, result_bytes, truncated, truncated_reason

    @staticmethod
    def _compile(pattern: str, *, use_regex: bool) -> re.Pattern[str]:
        if not use_regex:
            return re.compile(re.escape(pattern))
        # Guards before compilation. Bounding the *input* is not enough: `re`
        # backtracks, so cost is a property of the pattern. Measured on a single
        # 4 KiB line, `(a+)+$` does not terminate in any useful time and even
        # `.*a.*b` takes seconds — both well inside every size cap here. So the
        # exponential shapes are refused by name, the number of unbounded
        # quantifiers that can be chained is capped, and _search additionally
        # runs under a wall-clock deadline for whatever these two miss.
        if pattern.count("(") > MAX_REGEX_GROUPS:
            raise BrokerError(
                "SEARCH_PATTERN_INVALID",
                f"regex may contain at most {MAX_REGEX_GROUPS} groups",
            )
        if _has_nested_quantifier(pattern):
            raise BrokerError(
                "SEARCH_PATTERN_INVALID",
                "regex nests one unbounded quantifier inside another, such as "
                "'(a+)+' or '(a|a)*', which can take unbounded time to match. "
                "Rewrite it without the nesting, or search for a literal "
                "substring instead",
            )
        quantifiers = len(_UNBOUNDED_RUN.findall(pattern))
        if quantifiers > MAX_REGEX_QUANTIFIERS:
            raise BrokerError(
                "SEARCH_PATTERN_INVALID",
                f"regex chains {quantifiers} unbounded quantifiers such as "
                f"'.*' or '\\\\w+'; at most {MAX_REGEX_QUANTIFIERS} are allowed "
                "because each one multiplies the matching cost. Use a more "
                "specific pattern",
            )
        try:
            return re.compile(pattern)
        except re.error as exc:
            raise BrokerError(
                "SEARCH_PATTERN_INVALID",
                f"regex could not be compiled: {exc}",
            ) from exc
        except RecursionError as exc:  # pragma: no cover - defensive
            raise BrokerError(
                "SEARCH_PATTERN_INVALID",
                "regex is too complex to compile",
            ) from exc

    def _find_symbol(self, arguments: Mapping[str, object]) -> dict[str, object]:
        query = self._string_argument(
            arguments,
            "name",
            limit=MAX_SYMBOL_QUERY_LENGTH,
        )
        needle = query.strip().lower()
        results: list[dict[str, object]] = []
        for record in self._records("symbols"):
            name = _text(record.get("name")) or ""
            container = _text(record.get("container"))
            qualified = f"{container}.{name}" if container else name
            if needle in name.lower() or needle in qualified.lower():
                results.append(
                    {
                        "path": _text(record.get("path"), limit=MAX_PATH_LENGTH),
                        "line": _line_of(record),
                        "kind": _text(record.get("kind"), limit=128),
                        "name": name,
                        "container": container,
                    }
                )
        results.sort(key=_sort_key)
        kept, meta = _bounded(
            results,
            limit=MAX_SYMBOL_MATCHES,
            label="symbols",
            advice="Use a longer or more qualified name.",
        )
        return {
            "name": query,
            "symbols": kept,
            **meta,
            "notes": (
                "Matching is case-insensitive substring matching over the "
                "indexed symbol names. The index covers indexed Java sources "
                "only, so a miss is not proof that the symbol does not exist."
            ),
        }

    def _list_entrypoints(
        self,
        arguments: Mapping[str, object],
    ) -> dict[str, object]:
        predicate, module = self._module_predicate(arguments)
        results = [
            {
                "path": _text(record.get("path"), limit=MAX_PATH_LENGTH),
                "line": _line_of(record),
                "kind": _text(record.get("kind"), limit=128),
                "symbol": _text(record.get("symbol")),
                "route": _text(record.get("route")),
                "annotations": _string_list(record.get("annotations")),
            }
            for record in self._records("entrypoints")
            if predicate is None or predicate(record)
        ]
        results.sort(key=_sort_key)
        kept, meta = _bounded(
            results,
            limit=MAX_ENTRYPOINTS,
            label="entrypoints",
            advice="Pass 'module' to narrow the result.",
        )
        return {
            "module": module,
            "entrypoints": kept,
            **meta,
            "notes": (
                "Index-derived starting points, not a completeness proof: an "
                "entrypoint missing here may still exist in code."
            ),
        }

    def _list_sinks(self, arguments: Mapping[str, object]) -> dict[str, object]:
        predicate, module = self._module_predicate(arguments)
        results = [
            {
                "path": _text(record.get("path"), limit=MAX_PATH_LENGTH),
                "line": _line_of(record),
                "kind": _text(record.get("kind"), limit=128),
                "symbol": _text(record.get("symbol")),
                "cwe_ids": _string_list(record.get("cwe_ids")),
            }
            for record in self._records("sinks")
            if predicate is None or predicate(record)
        ]
        results.sort(key=_sort_key)
        kept, meta = _bounded(
            results,
            limit=MAX_SINKS,
            label="sinks",
            advice="Pass 'module' to narrow the result.",
        )
        return {
            "module": module,
            "sinks": kept,
            **meta,
            "notes": (
                "Pattern-derived sinks. Absence here is not evidence that a "
                "sink does not exist; confirm by reading the code."
            ),
        }


_SPECS_BY_NAME: dict[str, _ToolSpec] = {spec.name: spec for spec in _TOOL_SPECS}
_HANDLERS: dict[str, str] = {spec.name: spec.handler for spec in _TOOL_SPECS}

# The closed set is only closed if the declaration, the definitions handed to
# the model and the dispatch table cannot drift apart. Check that here, at
# import time, in the style of TemplateRegistry: a tool added to one of the
# three and forgotten in the others fails the process, not a review.
if TOOL_NAMES != frozenset(_SPECS_BY_NAME) or TOOL_NAMES != frozenset(_HANDLERS):
    raise RuntimeError("broker tool declaration, definitions and dispatch disagree")
if len(_TOOL_SPECS) != len(TOOL_NAMES):
    raise RuntimeError("broker tool definitions contain a duplicate name")
for _name, _handler in _HANDLERS.items():
    if not callable(getattr(ToolBroker, _handler, None)):
        raise RuntimeError(f"broker tool {_name} has no handler")
for _spec in _TOOL_SPECS:
    if len({parameter.name for parameter in _spec.parameters}) != len(
        _spec.parameters
    ):
        raise RuntimeError(f"broker tool {_spec.name} declares a duplicate argument")
del _name, _handler, _spec
