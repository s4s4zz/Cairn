"""Decide which semantic reviews an AuditRun should actually run (§7.5).

Each task here becomes one model conversation, so the split is driven by what
the deterministic index *found* rather than by a cartesian product of modules,
attack surfaces and categories. A module with no XML parser gets no XXE review;
a module with no entrypoints gets nothing at all. The alternative — asking the
model to look for a weakness in code that provably contains no sink of that
kind — spends a conversation to establish something the index already knows.

The evidence comes from `cairn.analysis.indexer`, which classifies entrypoints
by annotation and sinks by call pattern. Both vocabularies are closed, so the
mappings below are total: an unknown kind contributes no task rather than
silently falling into a default category.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import PurePosixPath

from cairn.semantic.findings import ReviewScope

# Sink kind (cairn/src/cairn/analysis/indexer.py) -> §7.5 audit category.
SINK_CATEGORIES: dict[str, str] = {
    "database-query": "sql-injection",
    "process-execution": "command-execution",
    "filesystem": "path-traversal",
    "outbound-http": "ssrf",
    "deserialization": "unsafe-deserialization",
    "expression-evaluation": "expression-injection",
    "template-render": "template-injection",
    "xml-parser": "xxe",
}

# Entrypoint kind -> attack surface. Several annotations describe one surface
# (a @RestController and a @GetMapping are both the HTTP surface), and merging
# them keeps one review per surface instead of one per annotation style.
SURFACE_GROUPS: dict[str, str] = {
    "http-controller": "http",
    "http-route": "http",
    "servlet": "http",
    "servlet-filter": "http",
    "websocket": "websocket",
    "message-consumer": "message-queue",
    "scheduled-job": "scheduled-job",
    "rpc-service": "rpc",
}

SURFACE_LABELS: dict[str, str] = {
    "http": "HTTP endpoint",
    "websocket": "WebSocket endpoint",
    "message-queue": "Message consumer",
    "scheduled-job": "Scheduled job",
    "rpc": "RPC service",
}

# Categories that are not sink-shaped. Authorization is a property of the
# surface and its permission annotations, not of any single dangerous call.
CATEGORY_AUTHORIZATION = "authorization"
CATEGORY_SPRING_SECURITY = "spring-security-misconfiguration"

SECURITY_CONFIGURATION_KIND = "security-configuration"

DEFAULT_MAX_TASKS = 24
DEFAULT_MAX_TURNS = 24
DEFAULT_MAX_OUTPUT_TOKENS = 16_000
MAX_ENTRYPOINT_HINTS = 32

TRUNCATION_REASON = "SEMANTIC_PLAN_TRUNCATED"


@dataclass(frozen=True, slots=True)
class SemanticBudget:
    """Per-run ceilings, read from `AuditPolicy.semantic_budget`."""

    max_tasks: int = DEFAULT_MAX_TASKS
    max_turns_per_task: int = DEFAULT_MAX_TURNS
    max_output_tokens_per_task: int = DEFAULT_MAX_OUTPUT_TOKENS
    categories: frozenset[str] | None = None

    @classmethod
    def from_policy(cls, payload: object) -> "SemanticBudget":
        """Read a budget from policy JSON, ignoring anything malformed.

        A policy row is operator-authored and may predate this field entirely,
        so every value falls back to its default rather than failing the run.
        """

        if not isinstance(payload, dict):
            return cls()
        categories = payload.get("categories")
        allowed: frozenset[str] | None = None
        if isinstance(categories, list):
            names = {str(name) for name in categories if str(name).strip()}
            if names:
                allowed = frozenset(names)
        return cls(
            max_tasks=_positive(payload.get("max_tasks"), DEFAULT_MAX_TASKS),
            max_turns_per_task=_positive(
                payload.get("max_turns_per_task"), DEFAULT_MAX_TURNS
            ),
            max_output_tokens_per_task=_positive(
                payload.get("max_output_tokens_per_task"), DEFAULT_MAX_OUTPUT_TOKENS
            ),
            categories=allowed,
        )


@dataclass(frozen=True, slots=True)
class SemanticPlan:
    scopes: tuple[ReviewScope, ...]
    budget: SemanticBudget
    dropped: int

    @property
    def truncated(self) -> bool:
        return self.dropped > 0


def _positive(value: object, default: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        return default
    return value


def _module_paths(inventory: dict[str, object]) -> list[str]:
    modules = inventory.get("modules")
    paths: list[str] = []
    if isinstance(modules, list):
        for module in modules:
            if isinstance(module, dict):
                path = str(module.get("path", "")).strip().strip("/")
                paths.append(path)
    # Longest first so `core/api` wins over `core` for a file under it.
    return sorted(set(paths), key=lambda item: (-len(item), item))


def _owning_module(path: str, module_paths: list[str]) -> str:
    """Attribute one indexed record to the deepest module containing it."""

    normalized = PurePosixPath(str(path)).as_posix()
    for module in module_paths:
        if not module:
            continue
        if normalized == module or normalized.startswith(f"{module}/"):
            return module
    # A single-module repository indexes its module as "" or "."; everything
    # that matches no prefix belongs to that root rather than to nothing.
    return ""


def _records(inventory: dict[str, object], key: str) -> list[dict[str, object]]:
    values = inventory.get(key)
    if not isinstance(values, list):
        return []
    return [value for value in values if isinstance(value, dict)]


def _scope_for(
    module: str,
    surface: str,
    category: str,
    entrypoint_paths: list[str],
) -> ReviewScope:
    return ReviewScope(
        module=module or ".",
        attack_surface=SURFACE_LABELS.get(surface, surface),
        category=category,
        entrypoint_paths=sorted(set(entrypoint_paths))[:MAX_ENTRYPOINT_HINTS],
    )


def plan_semantic_reviews(
    inventory: dict[str, object],
    *,
    budget: SemanticBudget | None = None,
) -> SemanticPlan:
    """Derive the review assignments an index actually justifies.

    Deterministic in both content and order: two runs over one Snapshot produce
    the same list, so `AuditTask.scope_key` idempotency holds and a truncated
    plan drops the same tail every time.
    """

    active = budget or SemanticBudget()
    module_paths = _module_paths(inventory)

    entrypoints_by_module: dict[str, dict[str, list[str]]] = {}
    for record in _records(inventory, "entrypoints"):
        surface = SURFACE_GROUPS.get(str(record.get("kind", "")))
        if surface is None:
            continue
        path = str(record.get("path", ""))
        module = _owning_module(path, module_paths)
        entrypoints_by_module.setdefault(module, {}).setdefault(surface, []).append(path)

    sinks_by_module: dict[str, set[str]] = {}
    for record in _records(inventory, "sinks"):
        kind = str(record.get("kind", ""))
        if kind not in SINK_CATEGORIES:
            continue
        module = _owning_module(str(record.get("path", "")), module_paths)
        sinks_by_module.setdefault(module, set()).add(kind)

    security_config_modules: set[str] = set()
    for record in _records(inventory, "permissions"):
        if str(record.get("kind", "")) != SECURITY_CONFIGURATION_KIND:
            continue
        security_config_modules.add(
            _owning_module(str(record.get("path", "")), module_paths)
        )

    candidates: list[ReviewScope] = []
    for module in sorted(entrypoints_by_module):
        surfaces = entrypoints_by_module[module]
        sink_kinds = sinks_by_module.get(module, set())
        for surface in sorted(surfaces):
            paths = surfaces[surface]
            # Sink-driven: only where this module holds the dangerous call.
            for kind in sorted(sink_kinds):
                candidates.append(
                    _scope_for(module, surface, SINK_CATEGORIES[kind], paths)
                )
            # Surface-driven: any reachable surface can be missing an
            # authorization check, whether or not it reaches a tainted sink.
            candidates.append(
                _scope_for(module, surface, CATEGORY_AUTHORIZATION, paths)
            )

    for module in sorted(security_config_modules):
        surfaces = entrypoints_by_module.get(module, {})
        paths = [path for group in surfaces.values() for path in group]
        candidates.append(
            _scope_for(module, "http", CATEGORY_SPRING_SECURITY, paths)
        )

    if active.categories is not None:
        candidates = [
            scope for scope in candidates if scope.category in active.categories
        ]

    # Deduplicate on the scope key, which is what the AuditTask unique
    # constraint keys on, then order by it so truncation is reproducible.
    unique: dict[str, ReviewScope] = {}
    for scope in candidates:
        unique.setdefault(scope.scope_key, scope)
    ordered = [unique[key] for key in sorted(unique)]

    kept = ordered[: active.max_tasks]
    return SemanticPlan(
        scopes=tuple(kept),
        budget=active,
        dropped=len(ordered) - len(kept),
    )
