"""The evidence-driven semantic task split (§7.5).

Each task here is one model conversation, so the property under test is not
"does it produce tasks" but "does it decline to produce the ones the index does
not justify". A cartesian product over modules, surfaces and the 14 categories
would be exhaustive and mostly spend money establishing that a module with no
XML parser has no XXE.
"""

from __future__ import annotations

import pytest

from cairn.orchestrator.semantic_tasks import (
    CATEGORY_AUTHORIZATION,
    CATEGORY_SPRING_SECURITY,
    SINK_CATEGORIES,
    SURFACE_GROUPS,
    SemanticBudget,
    plan_semantic_reviews,
)


def inventory(
    *,
    modules: list[str] | None = None,
    entrypoints: list[tuple[str, str]] | None = None,
    sinks: list[tuple[str, str]] | None = None,
    permissions: list[tuple[str, str]] | None = None,
) -> dict[str, object]:
    return {
        "modules": [{"path": path} for path in (modules or ["core", "web"])],
        "entrypoints": [
            {"path": path, "kind": kind, "line": 1, "symbol": "S"}
            for path, kind in (entrypoints or [])
        ],
        "sinks": [
            {"path": path, "kind": kind, "line": 1}
            for path, kind in (sinks or [])
        ],
        "permissions": [
            {"path": path, "kind": kind, "line": 1}
            for path, kind in (permissions or [])
        ],
    }


def categories_for(plan, module: str) -> set[str]:
    return {scope.category for scope in plan.scopes if scope.module == module}


def test_a_sink_and_a_surface_in_one_module_yields_that_category() -> None:
    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("core/src/A.java", "http-route")],
            sinks=[("core/src/B.java", "database-query")],
        )
    )

    assert "sql-injection" in categories_for(plan, "core")


def test_a_module_without_the_sink_gets_no_task_for_that_category() -> None:
    """The whole point of the split: no conversation is spent asking about a
    weakness whose sink kind the index did not find in that module."""

    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("core/src/A.java", "http-route")],
            sinks=[("core/src/B.java", "database-query")],
        )
    )

    assert "xxe" not in categories_for(plan, "core")
    assert "ssrf" not in categories_for(plan, "core")
    assert "command-execution" not in categories_for(plan, "core")


def test_a_module_without_entrypoints_gets_no_tasks_at_all() -> None:
    """A dangerous call nothing external can reach is not an attack surface."""

    plan = plan_semantic_reviews(
        inventory(
            modules=["lib"],
            sinks=[("lib/src/B.java", "database-query")],
        )
    )

    assert plan.scopes == ()


def test_a_sink_in_another_module_does_not_leak_across_the_boundary() -> None:
    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("web/src/A.java", "http-controller")],
            sinks=[("core/src/B.java", "database-query")],
        )
    )

    assert "sql-injection" not in categories_for(plan, "web")


def test_every_surface_gets_an_authorization_review() -> None:
    """Authorization is a property of the surface, not of any single call, so
    it is the one category that does not need a sink to justify it."""

    plan = plan_semantic_reviews(
        inventory(entrypoints=[("web/src/A.java", "http-controller")])
    )

    assert categories_for(plan, "web") == {CATEGORY_AUTHORIZATION}


def test_spring_security_configuration_yields_its_own_review() -> None:
    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("web/src/A.java", "http-controller")],
            permissions=[("web/src/SecurityConfig.java", "security-configuration")],
        )
    )

    assert CATEGORY_SPRING_SECURITY in categories_for(plan, "web")


@pytest.mark.parametrize(("sink_kind", "category"), sorted(SINK_CATEGORIES.items()))
def test_every_sink_kind_maps_to_a_category(sink_kind: str, category: str) -> None:
    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("core/src/A.java", "http-route")],
            sinks=[("core/src/B.java", sink_kind)],
        )
    )

    assert category in categories_for(plan, "core")


@pytest.mark.parametrize("entrypoint_kind", sorted(SURFACE_GROUPS))
def test_every_entrypoint_kind_is_a_recognised_surface(entrypoint_kind: str) -> None:
    plan = plan_semantic_reviews(
        inventory(entrypoints=[("core/src/A.java", entrypoint_kind)])
    )

    assert plan.scopes


def test_an_unknown_kind_contributes_nothing_rather_than_a_default() -> None:
    """Both vocabularies are closed. A kind this planner does not know is a
    signal the index changed, and guessing a category for it would attribute
    findings to a surface nobody defined."""

    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[("core/src/A.java", "quantum-entanglement-listener")],
            sinks=[("core/src/B.java", "telepathy")],
        )
    )

    assert plan.scopes == ()


def test_the_plan_is_byte_identical_across_two_runs() -> None:
    payload = inventory(
        entrypoints=[
            ("web/src/A.java", "http-controller"),
            ("core/src/B.java", "http-route"),
        ],
        sinks=[
            ("core/src/C.java", "database-query"),
            ("core/src/D.java", "filesystem"),
        ],
    )

    first = plan_semantic_reviews(payload)
    second = plan_semantic_reviews(payload)

    assert [scope.model_dump() for scope in first.scopes] == [
        scope.model_dump() for scope in second.scopes
    ]


def test_scope_keys_are_unique_so_task_creation_stays_idempotent() -> None:
    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[
                ("web/src/A.java", "http-controller"),
                ("web/src/B.java", "http-route"),
                ("core/src/C.java", "http-route"),
            ],
            sinks=[("core/src/D.java", "database-query")],
        )
    )

    keys = [scope.scope_key for scope in plan.scopes]

    assert len(keys) == len(set(keys))
    assert all(len(key) <= 128 for key in keys)


def test_two_annotation_styles_of_one_surface_do_not_double_the_reviews() -> None:
    """@RestController and @GetMapping describe the same HTTP surface."""

    plan = plan_semantic_reviews(
        inventory(
            entrypoints=[
                ("web/src/A.java", "http-controller"),
                ("web/src/A.java", "http-route"),
            ],
        )
    )

    assert len(plan.scopes) == 1


def test_truncation_is_a_deterministic_prefix_and_is_reported() -> None:
    """A silent cap reads as 'fully covered' when it is not."""

    payload = inventory(
        entrypoints=[
            ("web/src/A.java", "http-controller"),
            ("core/src/B.java", "http-route"),
        ],
        sinks=[
            ("core/src/C.java", "database-query"),
            ("core/src/D.java", "filesystem"),
            ("core/src/E.java", "outbound-http"),
        ],
    )
    full = plan_semantic_reviews(payload)
    capped = plan_semantic_reviews(payload, budget=SemanticBudget(max_tasks=2))

    assert len(full.scopes) > 2
    assert len(capped.scopes) == 2
    assert capped.dropped == len(full.scopes) - 2
    assert capped.truncated is True
    assert [scope.scope_key for scope in capped.scopes] == [
        scope.scope_key for scope in full.scopes
    ][:2]
    assert full.truncated is False


def test_a_category_allowlist_narrows_the_plan() -> None:
    payload = inventory(
        entrypoints=[("core/src/A.java", "http-route")],
        sinks=[("core/src/B.java", "database-query")],
    )

    plan = plan_semantic_reviews(
        payload,
        budget=SemanticBudget(categories=frozenset({"sql-injection"})),
    )

    assert {scope.category for scope in plan.scopes} == {"sql-injection"}


def test_a_single_module_repository_attributes_everything_to_its_root() -> None:
    plan = plan_semantic_reviews(
        inventory(
            modules=["."],
            entrypoints=[("src/main/java/A.java", "http-route")],
            sinks=[("src/main/java/B.java", "database-query")],
        )
    )

    assert {scope.module for scope in plan.scopes} == {"."}
    assert "sql-injection" in categories_for(plan, ".")


def test_a_nested_module_wins_over_its_parent() -> None:
    plan = plan_semantic_reviews(
        inventory(
            modules=["core", "core/api"],
            entrypoints=[("core/api/src/A.java", "http-route")],
            sinks=[("core/api/src/B.java", "database-query")],
        )
    )

    assert {scope.module for scope in plan.scopes} == {"core/api"}


class TestBudgetFromPolicy:
    def test_an_absent_policy_field_uses_the_defaults(self) -> None:
        assert SemanticBudget.from_policy(None) == SemanticBudget()

    def test_a_malformed_value_falls_back_rather_than_failing_the_run(self) -> None:
        budget = SemanticBudget.from_policy(
            {"max_tasks": -3, "max_turns_per_task": "many", "categories": []}
        )

        assert budget == SemanticBudget()

    def test_operator_values_are_honoured(self) -> None:
        budget = SemanticBudget.from_policy(
            {
                "max_tasks": 4,
                "max_turns_per_task": 6,
                "max_output_tokens_per_task": 2048,
                "categories": ["sql-injection", "ssrf"],
            }
        )

        assert budget.max_tasks == 4
        assert budget.max_turns_per_task == 6
        assert budget.max_output_tokens_per_task == 2048
        assert budget.categories == frozenset({"sql-injection", "ssrf"})

    def test_a_boolean_is_not_accepted_as_a_count(self) -> None:
        assert SemanticBudget.from_policy({"max_tasks": True}).max_tasks == (
            SemanticBudget().max_tasks
        )
