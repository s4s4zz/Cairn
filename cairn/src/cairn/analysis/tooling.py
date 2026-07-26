from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import shlex
import shutil

from cairn.analysis.execution import (
    CommandExecutor,
    fixed_environment,
    prepare_writable_source,
    run_command,
)
from cairn.analysis.fingerprints import merge_candidates
from cairn.analysis.normalizers import NormalizationError, normalize_tool_result
from cairn.analysis.project import detect_project


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    binary: str
    version_argv: tuple[str, ...]
    raw_path: str
    required_asset: str | None = None


TOOL_SPECS = {
    "codeql": ToolSpec(
        "codeql",
        "codeql",
        ("codeql", "version", "--format=json"),
        "scanners/codeql.sarif",
        "/opt/cairn/rules/codeql/java-security-and-quality.qls",
    ),
    "semgrep": ToolSpec(
        "semgrep",
        "semgrep",
        ("semgrep", "--version"),
        "scanners/semgrep.json",
        "/opt/cairn/rules/semgrep",
    ),
    "findsecbugs": ToolSpec(
        "findsecbugs",
        "spotbugs",
        ("spotbugs", "-version"),
        "scanners/findsecbugs.xml",
        "/opt/cairn/tools/findsecbugs-plugin.jar",
    ),
    "dependency-check": ToolSpec(
        "dependency-check",
        "dependency-check.sh",
        ("dependency-check.sh", "--version"),
        "scanners/dependency-check.json",
        "/opt/cairn/data/dependency-check",
    ),
    "trivy": ToolSpec(
        "trivy",
        "trivy",
        ("trivy", "--version"),
        "scanners/trivy.json",
        "/opt/cairn/data/trivy",
    ),
    "gitleaks": ToolSpec(
        "gitleaks",
        "gitleaks",
        ("gitleaks", "version"),
        "scanners/gitleaks.json",
    ),
}


def _version(
    spec: ToolSpec,
    *,
    scratch_root: Path,
    output_root: Path,
    executor: CommandExecutor,
) -> tuple[str | None, str | None]:
    version_log = output_root / f"scanners/{spec.name}-version.txt"
    result = executor(
        list(spec.version_argv),
        scratch_root,
        version_log,
        fixed_environment(scratch_root),
        30,
    )
    if result.reason_code is not None or result.exit_code != 0:
        version_log.unlink(missing_ok=True)
        return None, result.reason_code or "SCANNER_VERSION_FAILED"
    try:
        rendered = " ".join(
            version_log.read_text(encoding="utf-8", errors="replace").split()
        )[:255]
    except OSError:
        return None, "SCANNER_VERSION_FAILED"
    return rendered or None, None


def _generic_command(
    operation: str,
    source_root: Path,
    scratch_root: Path,
    raw_path: Path,
) -> list[str]:
    if operation == "semgrep":
        return [
            "semgrep",
            "scan",
            "--disable-version-check",
            "--metrics=off",
            "--config",
            "/opt/cairn/rules/semgrep",
            "--json",
            "--output",
            str(raw_path),
            str(source_root),
        ]
    if operation == "gitleaks":
        return [
            "gitleaks",
            "detect",
            "--no-git",
            "--source",
            str(source_root),
            "--report-format",
            "json",
            "--report-path",
            str(raw_path),
            "--exit-code",
            "0",
        ]
    if operation == "trivy":
        return [
            "trivy",
            "fs",
            "--cache-dir",
            "/opt/cairn/data/trivy",
            "--skip-db-update",
            "--skip-java-db-update",
            "--format",
            "json",
            "--output",
            str(raw_path),
            str(source_root),
        ]
    if operation == "dependency-check":
        return [
            "dependency-check.sh",
            "--noupdate",
            "--data",
            "/opt/cairn/data/dependency-check",
            "--scan",
            str(source_root),
            "--format",
            "JSON",
            "--out",
            str(raw_path.parent),
            "--project",
            "cairn-snapshot",
        ]
    raise ValueError("scanner requires a specialized command")


def _adjust_build_argv(argv: list[str], scratch_root: Path) -> list[str]:
    if argv[0].endswith("mvn") or argv[0].endswith("mvnw"):
        return [
            *argv[:-1],
            f"-Dmaven.repo.local={scratch_root / 'm2'}",
            argv[-1],
        ]
    return [
        *argv[:-1],
        "--project-cache-dir",
        str(scratch_root / "gradle-project-cache"),
        argv[-1],
    ]


def _codeql_commands(
    source_root: Path,
    scratch_root: Path,
    raw_path: Path,
) -> tuple[Path, list[list[str]]]:
    writable_source = prepare_writable_source(source_root, scratch_root)
    build_plan = detect_project(writable_source)["build_plan"]
    if not build_plan:
        raise ValueError("CodeQL requires a supported build plan")
    step = build_plan[0]
    module_path = str(step["module_path"])
    cwd = writable_source if module_path == "." else writable_source / module_path
    build_argv = _adjust_build_argv(
        [str(value) for value in step["argv"]],
        scratch_root,
    )
    database = scratch_root / "codeql-database"
    return cwd, [
        [
            "codeql",
            "database",
            "create",
            str(database),
            "--language=java-kotlin",
            f"--source-root={writable_source}",
            "--overwrite",
            f"--command={shlex.join(build_argv)}",
        ],
        [
            "codeql",
            "database",
            "analyze",
            str(database),
            "/opt/cairn/rules/codeql/java-security-and-quality.qls",
            "--format=sarifv2.1.0",
            f"--output={raw_path}",
            "--threads=0",
        ],
    ]


def _findsecbugs_commands(
    source_root: Path,
    scratch_root: Path,
    raw_path: Path,
) -> tuple[Path, list[list[str]]]:
    writable_source = prepare_writable_source(source_root, scratch_root)
    build_plan = detect_project(writable_source)["build_plan"]
    if not build_plan:
        raise ValueError("FindSecBugs requires a supported build plan")
    step = build_plan[0]
    module_path = str(step["module_path"])
    cwd = writable_source if module_path == "." else writable_source / module_path
    build_argv = _adjust_build_argv(
        [str(value) for value in step["argv"]],
        scratch_root,
    )
    return cwd, [
        build_argv,
        [
            "spotbugs",
            "-textui",
            "-pluginList",
            "/opt/cairn/tools/findsecbugs-plugin.jar",
            "-xml:withMessages",
            "-output",
            str(raw_path),
            str(writable_source),
        ],
    ]


def run_external_scanner(
    operation: str,
    source_root: Path,
    scratch_root: Path,
    output_root: Path,
    *,
    snapshot_sha256: str,
    executor: CommandExecutor = run_command,
) -> dict[str, object]:
    spec = TOOL_SPECS[operation]
    environment = fixed_environment(scratch_root)
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    if shutil.which(spec.binary, path=environment["PATH"]) is None:
        return {
            "status": "unavailable",
            "tool_name": spec.name,
            "tool_version": None,
            "reason_code": "SCANNER_BINARY_UNAVAILABLE",
            "raw_result_paths": [],
            "candidates": [],
        }
    if spec.required_asset is not None and not Path(spec.required_asset).exists():
        return {
            "status": "unavailable",
            "tool_name": spec.name,
            "tool_version": None,
            "reason_code": "SCANNER_ASSET_UNAVAILABLE",
            "raw_result_paths": [],
            "candidates": [],
        }

    version, version_error = _version(
        spec,
        scratch_root=scratch_root,
        output_root=output_root,
        executor=executor,
    )
    if version_error is not None:
        return {
            "status": "failed",
            "tool_name": spec.name,
            "tool_version": None,
            "reason_code": version_error,
            "raw_result_paths": [],
            "candidates": [],
        }

    raw_path = output_root / spec.raw_path
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    scan_log = output_root / f"scanners/{operation}.log"
    try:
        if operation == "codeql":
            cwd, commands = _codeql_commands(
                source_root,
                scratch_root,
                raw_path,
            )
        elif operation == "findsecbugs":
            cwd, commands = _findsecbugs_commands(
                source_root,
                scratch_root,
                raw_path,
            )
        else:
            cwd = source_root
            commands = [
                _generic_command(operation, source_root, scratch_root, raw_path)
            ]
    except ValueError:
        return {
            "status": "failed",
            "tool_name": spec.name,
            "tool_version": version,
            "reason_code": "SCANNER_BUILD_PLAN_UNAVAILABLE",
            "raw_result_paths": [],
            "candidates": [],
        }

    for index, command in enumerate(commands):
        command_log = (
            scan_log
            if len(commands) == 1
            else output_root / f"scanners/{operation}-{index:02d}.log"
        )
        result = executor(command, cwd, command_log, environment, 1_200)
        if result.reason_code is not None or result.exit_code != 0:
            paths = sorted(
                path.relative_to(output_root).as_posix()
                for path in output_root.joinpath("scanners").glob(f"{operation}*")
                if path.is_file()
            )
            return {
                "status": "failed",
                "tool_name": spec.name,
                "tool_version": version,
                "reason_code": result.reason_code or "SCANNER_EXIT_NONZERO",
                "raw_result_paths": paths,
                "candidates": [],
            }

    dependency_generated = output_root / "scanners/dependency-check-report.json"
    if operation == "dependency-check" and dependency_generated.exists():
        dependency_generated.replace(raw_path)
    if not raw_path.is_file():
        return {
            "status": "failed",
            "tool_name": spec.name,
            "tool_version": version,
            "reason_code": "SCANNER_OUTPUT_MISSING",
            "raw_result_paths": [],
            "candidates": [],
        }
    try:
        candidates = normalize_tool_result(
            operation,
            raw_path,
            source_root=source_root,
            snapshot_sha256=snapshot_sha256,
        )
    except NormalizationError:
        return {
            "status": "failed",
            "tool_name": spec.name,
            "tool_version": version,
            "reason_code": "SCANNER_OUTPUT_INVALID",
            "raw_result_paths": [spec.raw_path],
            "candidates": [],
        }
    raw_paths = sorted(
        path.relative_to(output_root).as_posix()
        for path in output_root.joinpath("scanners").iterdir()
        if path.is_file()
    )
    return {
        "status": "completed",
        "tool_name": spec.name,
        "tool_version": version,
        "reason_code": None,
        "raw_result_paths": raw_paths,
        "candidates": merge_candidates(candidates),
    }
