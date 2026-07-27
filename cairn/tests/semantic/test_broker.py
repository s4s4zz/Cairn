"""The read-only Tool Broker is the model's entire surface on the source tree.

These tests treat it as a security boundary (§9.7): the tool set is closed, every
path argument is refused rather than repaired, no result is silently short, and
the module holds no capability to execute, connect or write.
"""

from __future__ import annotations

import inspect
import shutil
import sys
import types
from pathlib import Path

import pytest

from cairn.semantic import broker as broker_module
from cairn.semantic.broker import (
    MAX_PATTERN_LENGTH,
    MAX_READ_BYTES,
    MAX_READ_LINES,
    MAX_SEARCH_MATCHES,
    TOOL_NAMES,
    BrokerError,
    ToolBroker,
)


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "injected-app"
CONTROLLER = "web/src/main/java/dev/cairn/shop/OrderController.java"
REPOSITORY = "core/src/main/java/dev/cairn/shop/OrderRepository.java"


@pytest.fixture
def fixture_broker() -> ToolBroker:
    return ToolBroker(FIXTURE_ROOT)


def copied_tree(tmp_path: Path) -> Path:
    """A writable copy of the fixture, for symlink and encoding cases."""

    destination = tmp_path / "snapshot"
    shutil.copytree(FIXTURE_ROOT, destination)
    return destination


def refusal(broker: ToolBroker, name: str, arguments: dict[str, object]) -> BrokerError:
    with pytest.raises(BrokerError) as raised:
        broker.invoke(name, arguments)
    return raised.value


# -- shape -------------------------------------------------------------------


def test_read_inventory_summarises_the_snapshot(fixture_broker: ToolBroker) -> None:
    payload = fixture_broker.invoke("read_inventory", {})

    assert payload["tool"] == "read_inventory"
    assert payload["build_system"] == "maven"
    assert payload["counts"]["entrypoints"] == 2
    assert payload["counts"]["sinks"] == 1
    assert payload["sink_cwe_ids"] == ["CWE-89"]
    assert payload["truncated"] is False
    assert {module["path"] for module in payload["modules"]} == {".", "core", "web"}


def test_list_modules_reports_modules_and_dependency_edges(
    fixture_broker: ToolBroker,
) -> None:
    payload = fixture_broker.invoke("list_modules", {})

    assert payload["tool"] == "list_modules"
    assert [module["path"] for module in payload["modules"]] == [".", "core", "web"]
    assert payload["module_dependencies"] == [
        {"source": "web", "target": "core", "kind": "maven"}
    ]
    assert payload["modules_meta"]["truncated"] is False


def test_list_entrypoints_filters_by_module(fixture_broker: ToolBroker) -> None:
    payload = fixture_broker.invoke("list_entrypoints", {"module": "web"})

    assert payload["module"] == "web"
    assert {entry["path"] for entry in payload["entrypoints"]} == {CONTROLLER}
    assert {entry["kind"] for entry in payload["entrypoints"]} == {
        "http-controller",
        "http-route",
    }
    assert payload["truncated"] is False


def test_list_sinks_reports_the_sql_sink_with_its_cwe(
    fixture_broker: ToolBroker,
) -> None:
    payload = fixture_broker.invoke("list_sinks", {"module": "core"})

    assert [sink["path"] for sink in payload["sinks"]] == [REPOSITORY]
    assert payload["sinks"][0]["kind"] == "database-query"
    assert payload["sinks"][0]["cwe_ids"] == ["CWE-89"]


def test_find_symbol_returns_both_declarations_of_the_method(
    fixture_broker: ToolBroker,
) -> None:
    payload = fixture_broker.invoke("find_symbol", {"name": "findByOwner"})

    containers = {symbol["container"] for symbol in payload["symbols"]}
    assert containers == {
        "dev.cairn.shop.OrderRepository",
        "dev.cairn.shop.OrderService",
    }
    assert payload["total"] == 2
    assert payload["truncated"] is False


def test_read_file_returns_the_requested_window(fixture_broker: ToolBroker) -> None:
    payload = fixture_broker.invoke(
        "read_file",
        {"path": REPOSITORY, "start_line": 13, "end_line": 16},
    )

    assert payload["path"] == REPOSITORY
    assert payload["start_line"] == 13
    assert payload["end_line"] == 16
    assert payload["line_count"] == 4
    assert payload["truncated"] is False
    assert "statement.execute" in payload["text"]


def test_search_reports_the_sink_line(fixture_broker: ToolBroker) -> None:
    payload = fixture_broker.invoke(
        "search",
        {"pattern": "statement.execute", "path_glob": "*.java"},
    )

    assert payload["matches"][0]["path"] == REPOSITORY
    assert payload["matches"][0]["line"] == 15
    assert payload["truncated"] is False
    assert payload["truncated_reason"] is None


def test_unknown_module_is_refused_rather_than_answered_empty(
    fixture_broker: ToolBroker,
) -> None:
    error = refusal(fixture_broker, "list_sinks", {"module": "docs"})

    assert error.code == "MODULE_UNKNOWN"


# -- path refusals -----------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "web/src/main/java/dev/cairn/shop/Absent.java",
        "/etc/passwd",
        "../../../etc/passwd",
        "core/../../etc/passwd",
        "core\\src\\main\\java\\dev\\cairn\\shop\\OrderRepository.java",
        "file:///etc/passwd",
        "file://core/src/main/java/dev/cairn/shop/OrderRepository.java",
        "%2e%2e/%2e%2e/etc/passwd",
    ],
)
def test_read_file_refuses_paths_outside_the_snapshot(
    fixture_broker: ToolBroker,
    path: str,
) -> None:
    error = refusal(
        fixture_broker,
        "read_file",
        {"path": path, "start_line": 1, "end_line": 2},
    )

    assert error.code == "PATH_INVALID"


def test_symlink_escaping_the_tree_is_not_readable(tmp_path: Path) -> None:
    outside = tmp_path / "outside.txt"
    outside.write_text("SECRET=hunter2\n", encoding="utf-8")
    root = copied_tree(tmp_path)
    (root / "web" / "Escape.java").symlink_to(outside)
    broker = ToolBroker(root)

    error = refusal(
        broker,
        "read_file",
        {"path": "web/Escape.java", "start_line": 1, "end_line": 1},
    )

    assert error.code == "PATH_INVALID"
    assert "web/Escape.java" not in broker.catalog.paths


def test_symlink_pointing_back_inside_the_tree_is_also_refused(
    tmp_path: Path,
) -> None:
    root = copied_tree(tmp_path)
    (root / "web" / "Alias.java").symlink_to(root / REPOSITORY)
    broker = ToolBroker(root)

    error = refusal(
        broker,
        "read_file",
        {"path": "web/Alias.java", "start_line": 1, "end_line": 1},
    )

    assert error.code == "PATH_INVALID"


def test_search_refuses_an_absolute_or_traversing_glob(
    fixture_broker: ToolBroker,
) -> None:
    for glob in ("/etc/*", "../*", "core\\*"):
        error = refusal(
            fixture_broker,
            "search",
            {"pattern": "execute", "path_glob": glob},
        )
        assert error.code == "PATH_GLOB_INVALID"


# -- bounds ------------------------------------------------------------------


def test_read_file_refuses_a_window_wider_than_the_line_cap(
    fixture_broker: ToolBroker,
) -> None:
    error = refusal(
        fixture_broker,
        "read_file",
        {"path": REPOSITORY, "start_line": 1, "end_line": MAX_READ_LINES + 1},
    )

    assert error.code == "READ_WINDOW_TOO_LARGE"
    assert str(MAX_READ_LINES) in error.message


def test_read_file_marks_a_byte_capped_window_as_truncated(tmp_path: Path) -> None:
    root = copied_tree(tmp_path)
    wide = root / "core" / "src" / "main" / "java" / "dev" / "cairn" / "shop" / "Wide.java"
    wide.write_text("\n".join("// " + "x" * 1_000 for _ in range(200)), encoding="utf-8")
    broker = ToolBroker(root)

    payload = broker.invoke(
        "read_file",
        {
            "path": "core/src/main/java/dev/cairn/shop/Wide.java",
            "start_line": 1,
            "end_line": 200,
        },
    )

    assert payload["bytes"] <= MAX_READ_BYTES
    assert payload["line_count"] < 200
    assert payload["truncated"] is True
    assert isinstance(payload["truncated_reason"], str) and payload["truncated_reason"]
    assert payload["eof"] is False
    assert payload["end_line"] == payload["line_count"]


def test_read_file_past_end_of_file_says_so_rather_than_returning_an_empty_file(
    fixture_broker: ToolBroker,
) -> None:
    payload = fixture_broker.invoke(
        "read_file",
        {"path": REPOSITORY, "start_line": 900, "end_line": 950},
    )

    assert payload["line_count"] == 0
    assert isinstance(payload["notice"], str)
    assert "past the end of the file" in payload["notice"]


def test_search_pattern_longer_than_the_cap_is_refused(
    fixture_broker: ToolBroker,
) -> None:
    error = refusal(
        fixture_broker,
        "search",
        {"pattern": "a" * (MAX_PATTERN_LENGTH + 1)},
    )

    assert error.code == "TOOL_ARGUMENT_INVALID"


def test_search_with_an_invalid_regex_is_refused(fixture_broker: ToolBroker) -> None:
    error = refusal(
        fixture_broker,
        "search",
        {"pattern": "(unclosed", "regex": True},
    )

    assert error.code == "SEARCH_PATTERN_INVALID"


def test_search_refuses_a_catastrophically_backtracking_regex(
    fixture_broker: ToolBroker,
) -> None:
    error = refusal(
        fixture_broker,
        "search",
        {"pattern": "(a+)+$", "regex": True},
    )

    assert error.code == "SEARCH_PATTERN_INVALID"


def test_search_matching_everything_is_bounded_and_reports_truncation(
    tmp_path: Path,
) -> None:
    root = copied_tree(tmp_path)
    noisy = root / "core" / "src" / "main" / "java" / "dev" / "cairn" / "shop" / "Noisy.java"
    noisy.write_text(
        "\n".join(f"    int field{index} = {index}; // e" for index in range(1_000)),
        encoding="utf-8",
    )
    broker = ToolBroker(root)

    payload = broker.invoke("search", {"pattern": "e", "regex": False})

    assert payload["returned"] == len(payload["matches"])
    assert payload["returned"] <= MAX_SEARCH_MATCHES
    assert payload["truncated"] is True
    assert isinstance(payload["truncated_reason"], str)
    assert "Narrow" in payload["truncated_reason"]


def test_search_excerpts_are_bounded_on_a_very_long_line(tmp_path: Path) -> None:
    root = copied_tree(tmp_path)
    wide = root / "core" / "src" / "main" / "java" / "dev" / "cairn" / "shop" / "Long.java"
    # The needle sits inside the scanned prefix of the line, so the match is
    # really found; the 20 KiB tail is what the excerpt has to clip away. Put
    # the needle past MAX_SEARCH_LINE_BYTES and this test passes vacuously over
    # an empty match list.
    wide.write_text(
        "// " + ("y" * 1_000) + "NEEDLE" + ("z" * 20_000) + "\n",
        encoding="utf-8",
    )
    broker = ToolBroker(root)

    payload = broker.invoke("search", {"pattern": "NEEDLE"})

    assert payload["returned"] == 1
    assert payload["returned"] <= MAX_SEARCH_MATCHES
    match = payload["matches"][0]
    assert len(match["text"]) <= broker_module.MAX_MATCH_CONTEXT
    assert "NEEDLE" in match["text"]
    assert match["line_truncated"] is True


def test_non_utf8_bytes_in_a_java_file_do_not_raise(tmp_path: Path) -> None:
    root = copied_tree(tmp_path)
    broken = root / "core" / "src" / "main" / "java" / "dev" / "cairn" / "shop" / "Broken.java"
    broken.write_bytes(b"package dev.cairn.shop;\n// \xff\xfe not utf-8\nclass Broken {}\n")
    broker = ToolBroker(root)

    payload = broker.invoke(
        "read_file",
        {
            "path": "core/src/main/java/dev/cairn/shop/Broken.java",
            "start_line": 1,
            "end_line": 3,
        },
    )
    searched = broker.invoke("search", {"pattern": "not utf-8"})

    assert payload["line_count"] == 3
    assert "�" in payload["text"]
    assert searched["returned"] >= 1


# -- dispatch ----------------------------------------------------------------


def test_unknown_tool_name_is_refused(fixture_broker: ToolBroker) -> None:
    error = refusal(fixture_broker, "read_secret_env", {"name": "ANTHROPIC_API_KEY"})

    assert error.code == "TOOL_UNKNOWN"


def test_unknown_argument_key_is_refused_not_ignored(
    fixture_broker: ToolBroker,
) -> None:
    error = refusal(
        fixture_broker,
        "read_file",
        {
            "path": REPOSITORY,
            "start_line": 1,
            "end_line": 2,
            "follow_symlinks": True,
        },
    )

    assert error.code == "TOOL_ARGUMENT_UNKNOWN"
    assert "follow_symlinks" in error.message


def test_missing_required_argument_is_refused(fixture_broker: ToolBroker) -> None:
    error = refusal(fixture_broker, "read_file", {"path": REPOSITORY})

    assert error.code == "TOOL_ARGUMENT_MISSING"


@pytest.mark.parametrize("start_line", ["13", 13.0, True, None, [13]])
def test_non_integer_start_line_is_refused_without_coercion(
    fixture_broker: ToolBroker,
    start_line: object,
) -> None:
    error = refusal(
        fixture_broker,
        "read_file",
        {"path": REPOSITORY, "start_line": start_line, "end_line": 16},
    )

    assert error.code == "TOOL_ARGUMENT_INVALID"
    assert "nothing is coerced" in error.message


def test_non_object_arguments_are_refused(fixture_broker: ToolBroker) -> None:
    with pytest.raises(BrokerError) as raised:
        fixture_broker.invoke("read_inventory", ["read_inventory"])  # type: ignore[arg-type]

    assert raised.value.code == "TOOL_ARGUMENTS_INVALID"


def test_call_count_includes_refused_calls(fixture_broker: ToolBroker) -> None:
    before = fixture_broker.call_count()
    fixture_broker.invoke("read_inventory", {})
    with pytest.raises(BrokerError):
        fixture_broker.invoke("no_such_tool", {})

    assert fixture_broker.call_count() == before + 2


# -- the closed set ----------------------------------------------------------


def test_declared_names_definitions_and_dispatch_agree(
    fixture_broker: ToolBroker,
) -> None:
    defined = {definition["name"] for definition in fixture_broker.tool_definitions()}

    assert defined == set(TOOL_NAMES)
    for name in sorted(TOOL_NAMES):
        # Every declared name dispatches: it may refuse for a missing argument,
        # but it must never come back as an unknown tool.
        try:
            payload = fixture_broker.invoke(name, {})
        except BrokerError as error:
            assert error.code != "TOOL_UNKNOWN"
        else:
            assert payload["tool"] == name


def test_every_tool_definition_is_strict_and_closed(
    fixture_broker: ToolBroker,
) -> None:
    definitions = fixture_broker.tool_definitions()

    assert definitions
    for definition in definitions:
        assert definition["strict"] is True
        schema = definition["input_schema"]
        assert schema["type"] == "object"
        assert schema["additionalProperties"] is False
        assert set(schema["required"]) == set(schema["properties"])
        assert isinstance(definition["description"], str)
        assert definition["description"].strip()


def test_tool_definitions_are_byte_stable_across_calls(
    fixture_broker: ToolBroker,
) -> None:
    first = fixture_broker.tool_definitions()
    second = ToolBroker(FIXTURE_ROOT).tool_definitions()

    assert first == second
    assert [definition["name"] for definition in first] == [
        definition["name"] for definition in second
    ]


def test_broker_module_imports_no_execution_or_network_capability() -> None:
    source = inspect.getsource(broker_module)

    for forbidden in ("subprocess", "socket", "requests", "httpx", "urllib.request"):
        assert f"import {forbidden}" not in source
        assert f"from {forbidden}" not in source
    bound_modules = {
        value.__name__
        for value in vars(broker_module).values()
        if isinstance(value, types.ModuleType)
    }
    assert bound_modules.isdisjoint({"subprocess", "socket", "os", "requests"})


def test_importing_the_broker_does_not_pull_in_the_anthropic_sdk() -> None:
    assert "anthropic" not in sys.modules
