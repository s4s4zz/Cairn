from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import stat
import subprocess
from typing import Callable

from cairn.analysis.project import detect_project


_COMMAND_TIMEOUT_SECONDS = 1_200
_MAX_COPY_FILES = 100_000
_MAX_COPY_BYTES = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CommandResult:
    exit_code: int | None
    reason_code: str | None = None


CommandExecutor = Callable[
    [list[str], Path, Path, dict[str, str], int],
    CommandResult,
]


def fixed_environment(scratch_root: Path) -> dict[str, str]:
    path = os.environ.get(
        "PATH",
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    )
    return {
        "PATH": path,
        "HOME": str(scratch_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "MAVEN_OPTS": "-Djava.awt.headless=true",
        "GRADLE_USER_HOME": str(scratch_root / "gradle-home"),
    }


def run_command(
    argv: list[str],
    cwd: Path,
    log_path: Path,
    environment: dict[str, str],
    timeout_seconds: int = _COMMAND_TIMEOUT_SECONDS,
) -> CommandResult:
    if not argv or any("\x00" in argument for argument in argv):
        return CommandResult(None, "ANALYSIS_COMMAND_INVALID")
    executable = argv[0]
    if "/" in executable:
        candidate = (cwd / executable).resolve() if not executable.startswith("/") else Path(executable)
        if (
            not candidate.is_relative_to(cwd.resolve())
            and not executable.startswith("/opt/cairn/")
        ):
            return CommandResult(None, "ANALYSIS_COMMAND_INVALID")
        if not candidate.is_file() or candidate.is_symlink():
            return CommandResult(None, "ANALYSIS_TOOL_UNAVAILABLE")
    elif shutil.which(executable, path=environment.get("PATH")) is None:
        return CommandResult(None, "ANALYSIS_TOOL_UNAVAILABLE")

    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("wb") as log:
            completed = subprocess.run(
                argv,
                cwd=cwd,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                timeout=timeout_seconds,
                check=False,
            )
        return CommandResult(completed.returncode)
    except subprocess.TimeoutExpired:
        return CommandResult(None, "ANALYSIS_COMMAND_TIMEOUT")
    except OSError:
        return CommandResult(None, "ANALYSIS_COMMAND_FAILED")


def copy_source_tree(source_root: Path, destination: Path) -> None:
    source_root = source_root.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    files = 0
    total_bytes = 0
    for directory, directory_names, file_names in os.walk(
        source_root,
        followlinks=False,
    ):
        directory_path = Path(directory)
        relative_directory = directory_path.relative_to(source_root)
        target_directory = destination / relative_directory
        target_directory.mkdir(parents=True, exist_ok=True)
        retained: list[str] = []
        for name in directory_names:
            source = directory_path / name
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("source copy contains an unsupported directory")
            retained.append(name)
        directory_names[:] = retained
        for name in file_names:
            source = directory_path / name
            metadata = source.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("source copy contains an unsupported file")
            files += 1
            total_bytes += metadata.st_size
            if files > _MAX_COPY_FILES or total_bytes > _MAX_COPY_BYTES:
                raise ValueError("source copy exceeds its fixed limit")
            target = target_directory / name
            with source.open("rb") as input_stream, target.open("xb") as output:
                shutil.copyfileobj(input_stream, output, length=1024 * 1024)
            os.chmod(target, 0o755 if metadata.st_mode & 0o111 else 0o644)


def prepare_writable_source(source_root: Path, scratch_root: Path) -> Path:
    work_source = scratch_root / "project"
    if work_source.exists():
        shutil.rmtree(work_source)
    copy_source_tree(source_root, work_source)
    return work_source


# The JDKs the build image carries, newest first. A version the image does not
# have falls back to the closest one at or above it, and finally to the default:
# refusing to build at all would turn a toolchain gap into a silent hole in the
# audit, where a failed compile is at least a recorded coverage gap.
_JDK_HOMES = {
    "8": Path("/opt/java/jdk-8"),
    "11": Path("/opt/java/jdk-11"),
    "17": Path("/opt/java/jdk-17"),
}
_DEFAULT_JDK = Path("/opt/java/openjdk")


def select_jdk(java_version: object) -> Path | None:
    """The JDK home a build step should run on, or None to keep the default."""

    if not isinstance(java_version, str) or not java_version.isdigit():
        return None
    exact = _JDK_HOMES.get(java_version)
    if exact is not None and exact.is_dir():
        return exact
    requested = int(java_version)
    candidates = sorted(
        (
            (int(version), home)
            for version, home in _JDK_HOMES.items()
            if int(version) >= requested and home.is_dir()
        ),
    )
    return candidates[0][1] if candidates else None


def _jdk_environment(environment: dict[str, str], java_version: object) -> dict[str, str]:
    home = select_jdk(java_version)
    if home is None:
        return environment
    resolved = dict(environment)
    resolved["JAVA_HOME"] = str(home)
    resolved["PATH"] = f"{home / 'bin'}:{environment.get('PATH', '')}".rstrip(":")
    return resolved


def _execution_argv(
    step: dict[str, object],
    scratch_root: Path,
) -> list[str]:
    argv = [str(value) for value in step["argv"]]
    if step["build_system"] == "maven":
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


def dependency_proxy() -> str:
    """The one endpoint a build sandbox may reach to resolve dependencies.

    The build template's network is `internal`, so the sandbox cannot reach a
    public repository at all: without this, Maven cannot fetch a parent POM and
    the build fails before compiling anything. The operator runs the proxy under
    this alias on the build network; pointing an existing Nexus or corporate
    proxy at the same alias is a `--network-alias` away.

    Empty disables every override below, which is what a deployment whose build
    network reaches a repository directly should configure.
    """

    return os.environ.get("CAIRN_DEPENDENCY_PROXY", "cairn-maven-proxy:3128").strip()


def write_maven_settings(scratch_root: Path, proxy: str) -> Path:
    """Write the settings file that sends Maven through the proxy.

    Maven reads neither `HTTP_PROXY` nor the JVM proxy properties for its own
    transport, so the proxy has to be declared in a settings file. Generated
    under the scratch root rather than baked into the image so the endpoint has
    one definition and nothing in the image or the source tree is mutated.
    """

    host, _, port = proxy.partition(":")
    port = port or "3128"
    conf_root = scratch_root / "dependency-proxy"
    conf_root.mkdir(parents=True, exist_ok=True)
    settings_path = conf_root / "maven-settings.xml"
    entries = "".join(
        f"    <proxy>\n"
        f"      <id>cairn-dependency-proxy-{protocol}</id>\n"
        f"      <active>true</active>\n"
        f"      <protocol>{protocol}</protocol>\n"
        f"      <host>{host}</host>\n"
        f"      <port>{port}</port>\n"
        f"    </proxy>\n"
        for protocol in ("http", "https")
    )
    settings_path.write_text(
        f"<settings>\n  <proxies>\n{entries}  </proxies>\n</settings>\n",
        encoding="utf-8",
    )
    return settings_path


def _proxy_environment(scratch_root: Path, proxy: str) -> dict[str, str]:
    """Point every route a build tool might take at the proxy.

    Three mechanisms because three tools read three different things: Maven
    reads a settings file, Gradle reads JVM system properties, and a wrapper
    script fetching its own distribution reads the environment.
    """

    if not proxy:
        return {}
    host, _, port = proxy.partition(":")
    port = port or "3128"
    url = f"http://{host}:{port}"
    jvm = (
        f"-Dhttp.proxyHost={host} -Dhttp.proxyPort={port} "
        f"-Dhttps.proxyHost={host} -Dhttps.proxyPort={port}"
    )
    return {
        "MAVEN_ARGS": f"-s {write_maven_settings(scratch_root, proxy)}",
        "GRADLE_OPTS": jvm,
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "NO_PROXY": "localhost,127.0.0.1",
        "no_proxy": "localhost,127.0.0.1",
    }


def execute_build(
    source_root: Path,
    scratch_root: Path,
    output_root: Path,
    *,
    executor: CommandExecutor = run_command,
) -> dict[str, object]:
    work_source = prepare_writable_source(source_root, scratch_root)
    project = detect_project(work_source)
    environment = fixed_environment(scratch_root)
    environment.update(_proxy_environment(scratch_root, dependency_proxy()))
    Path(environment["HOME"]).mkdir(parents=True, exist_ok=True)
    steps: list[dict[str, object]] = []
    for index, step in enumerate(project["build_plan"]):
        relative_log = f"build/{index:03d}-{step['build_system']}.log"
        log_path = output_root / relative_log
        module_path = str(step["module_path"])
        cwd = work_source if module_path == "." else work_source / module_path
        result = executor(
            _execution_argv(step, scratch_root),
            cwd,
            log_path,
            _jdk_environment(environment, step.get("java_version")),
            _COMMAND_TIMEOUT_SECONDS,
        )
        if result.reason_code == "ANALYSIS_TOOL_UNAVAILABLE":
            status = "unavailable"
        elif result.reason_code is not None:
            status = "failed"
        elif result.exit_code == 0:
            status = "completed"
        else:
            status = "failed"
        steps.append(
            {
                "module_path": module_path,
                "build_system": step["build_system"],
                "runner": step["runner"],
                "status": status,
                "exit_code": result.exit_code,
                "log_path": relative_log if log_path.exists() else None,
                "reason_code": result.reason_code
                or (None if result.exit_code == 0 else "PROJECT_BUILD_FAILED"),
                "java_version": step.get("java_version"),
            }
        )

    completed = sum(step["status"] == "completed" for step in steps)
    if steps and completed == len(steps):
        status = "success"
    elif completed:
        status = "partial"
    else:
        status = "failed"
    return {
        "status": status,
        "steps": steps,
        "runnable_artifacts": _collect_runnable_artifacts(
            work_source,
            output_root,
            project["build_plan"],
        ),
    }


# Archives a JVM can be handed to `java -jar`. Sources and javadoc jars are the
# usual false positives and are excluded by name.
_ARCHIVE_SUFFIXES = (".jar", ".war")
_EXCLUDED_ARCHIVE_MARKERS = ("-sources.", "-javadoc.", "-tests.", "-plain.")
_MAX_RUNNABLE_ARTIFACTS = 64
_MAX_RUNNABLE_BYTES = 512 * 1024 * 1024


def _collect_runnable_artifacts(
    work_source: Path,
    output_root: Path,
    build_plan: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Copy the archives each module produced into the collected output.

    The build runs in a writable copy under scratch, which is discarded with the
    sandbox; anything the dynamic verifier is going to run has to travel out
    through `/work/output` like every other piece of evidence.

    Gradle's Spring Boot plugin emits both an executable `bootJar` and a
    `-plain.jar`; the plain one has no main class and is excluded by name so the
    verifier is not handed an archive that cannot start.
    """

    destination = output_root / "artifacts"
    collected: list[dict[str, object]] = []
    total_bytes = 0
    for step in build_plan:
        module_path = str(step["module_path"])
        build_system = str(step["build_system"])
        module_root = work_source if module_path == "." else work_source / module_path
        search_root = (
            module_root / "target"
            if build_system == "maven"
            else module_root / "build" / "libs"
        )
        if not search_root.is_dir():
            continue
        for archive in sorted(search_root.iterdir()):
            if len(collected) >= _MAX_RUNNABLE_ARTIFACTS:
                return collected
            if not archive.is_file() or archive.is_symlink():
                continue
            if archive.suffix not in _ARCHIVE_SUFFIXES:
                continue
            if any(marker in archive.name for marker in _EXCLUDED_ARCHIVE_MARKERS):
                continue
            size = archive.stat().st_size
            if total_bytes + size > _MAX_RUNNABLE_BYTES:
                return collected
            relative = f"artifacts/{module_path.replace('/', '_')}_{archive.name}"
            target = output_root / relative
            try:
                destination.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(archive, target)
            except OSError:
                continue
            total_bytes += size
            collected.append(
                {
                    "module_path": module_path,
                    "path": relative,
                    "build_system": build_system,
                    "size_bytes": size,
                }
            )
    return collected
