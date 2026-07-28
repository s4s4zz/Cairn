from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
import re
import xml.etree.ElementTree as ElementTree


MAX_DESCRIPTOR_BYTES = 2 * 1024 * 1024
_MAVEN_FILES = {"pom.xml"}
_GRADLE_BUILD_FILES = {"build.gradle", "build.gradle.kts"}
_GRADLE_SETTINGS_FILES = {"settings.gradle", "settings.gradle.kts"}
_SKIPPED_PARTS = {
    ".git",
    ".gradle",
    ".idea",
    ".mvn/wrapper",
    ".settings",
    "build",
    "node_modules",
    "out",
    "target",
}
_FRAMEWORK_ARTIFACTS = {
    "spring-boot": "spring-boot",
    "spring-web": "spring-mvc",
    "spring-security": "spring-security",
    "mybatis": "mybatis",
    "hibernate": "hibernate",
    "struts": "struts",
    "grpc": "grpc",
}


class ProjectDetectionError(ValueError):
    pass


@dataclass(slots=True)
class _Module:
    path: str
    name: str
    build_system: str
    descriptor: str | None
    parent_path: str | None = None
    java_versions: set[str] = field(default_factory=set)
    frameworks: set[str] = field(default_factory=set)
    coordinates: tuple[str | None, str | None] = (None, None)
    dependency_coordinates: set[tuple[str, str]] = field(default_factory=set)
    project_dependencies: set[str] = field(default_factory=set)


def _relative(root: Path, path: Path) -> str:
    rendered = path.relative_to(root).as_posix()
    return rendered or "."


def _module_path(path: Path, root: Path) -> str:
    rendered = _relative(root, path)
    return "." if rendered == "." else rendered


def _read_text(path: Path, *, max_bytes: int = MAX_DESCRIPTOR_BYTES) -> str:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file():
        raise ProjectDetectionError(f"descriptor is not a regular file: {path.name}")
    if metadata.st_size > max_bytes:
        raise ProjectDetectionError(f"descriptor exceeds size limit: {path.name}")
    return path.read_text(encoding="utf-8", errors="replace")


def _safe_child(root: Path, parent: Path, value: str) -> Path | None:
    value = value.strip().replace("\\", "/")
    candidate_path = PurePosixPath(value)
    if (
        not value
        or candidate_path.is_absolute()
        or any(part in {"", ".", ".."} for part in candidate_path.parts)
    ):
        return None
    candidate = parent.joinpath(*candidate_path.parts).resolve()
    if not candidate.is_relative_to(root):
        return None
    return candidate


def _xml_local(element: ElementTree.Element, name: str) -> ElementTree.Element | None:
    for child in element:
        if child.tag.rsplit("}", 1)[-1] == name:
            return child
    return None


def _xml_text(element: ElementTree.Element, name: str) -> str | None:
    child = _xml_local(element, name)
    if child is None or child.text is None:
        return None
    value = child.text.strip()
    return value or None


def _xml_descendants(
    element: ElementTree.Element,
    name: str,
) -> list[ElementTree.Element]:
    return [
        descendant
        for descendant in element.iter()
        if descendant.tag.rsplit("}", 1)[-1] == name
    ]


def _normalize_java_version(value: str | None) -> str | None:
    if value is None:
        return None
    value = value.strip().strip("\"'")
    if not value or "${" in value:
        return None
    match = re.search(r"(?<!\d)(?:1\.)?(\d{1,2})(?!\d)", value)
    if match is None:
        return None
    number = int(match.group(1))
    if number < 5 or number > 99:
        return None
    return str(number)


def _parse_maven_module(root: Path, pom: Path) -> tuple[_Module, list[Path]]:
    text = _read_text(pom)
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
        raise ProjectDetectionError("Maven descriptor contains a forbidden DTD")
    try:
        project = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise ProjectDetectionError("Maven descriptor is invalid XML") from exc

    module_root = pom.parent
    artifact_id = _xml_text(project, "artifactId") or module_root.name or "root"
    group_id = _xml_text(project, "groupId")
    parent = _xml_local(project, "parent")
    if group_id is None and parent is not None:
        group_id = _xml_text(parent, "groupId")
    module = _Module(
        path=_module_path(module_root, root),
        name=artifact_id,
        build_system="maven",
        descriptor=_relative(root, pom),
        coordinates=(group_id, artifact_id),
    )

    properties = _xml_local(project, "properties")
    property_values: dict[str, str] = {}
    if properties is not None:
        for child in properties:
            if child.text:
                property_values[child.tag.rsplit("}", 1)[-1]] = child.text.strip()
    for key in (
        "maven.compiler.release",
        "maven.compiler.source",
        "maven.compiler.target",
        "java.version",
        "jdk.version",
    ):
        normalized = _normalize_java_version(property_values.get(key))
        if normalized:
            module.java_versions.add(normalized)
    for release in _xml_descendants(project, "release"):
        normalized = _normalize_java_version(release.text)
        if normalized:
            module.java_versions.add(normalized)
    for source in _xml_descendants(project, "source"):
        normalized = _normalize_java_version(source.text)
        if normalized:
            module.java_versions.add(normalized)
    for target in _xml_descendants(project, "target"):
        normalized = _normalize_java_version(target.text)
        if normalized:
            module.java_versions.add(normalized)

    for dependency in _xml_descendants(project, "dependency"):
        dependency_group = _xml_text(dependency, "groupId")
        dependency_artifact = _xml_text(dependency, "artifactId")
        if dependency_group and dependency_artifact:
            module.dependency_coordinates.add(
                (dependency_group, dependency_artifact)
            )
        coordinate = " ".join(
            part for part in (dependency_group, dependency_artifact) if part
        ).lower()
        for marker, framework in _FRAMEWORK_ARTIFACTS.items():
            if marker in coordinate:
                module.frameworks.add(framework)

    children: list[Path] = []
    modules_element = _xml_local(project, "modules")
    if modules_element is not None:
        for child in modules_element:
            if child.tag.rsplit("}", 1)[-1] != "module" or not child.text:
                continue
            child_root = _safe_child(root, module_root, child.text)
            if child_root is not None and (child_root / "pom.xml").is_file():
                children.append(child_root / "pom.xml")
    return module, children


_GRADLE_INCLUDE = re.compile(
    r"(?m)^\s*include\s*(?:\((?P<call>[^)]*)\)|(?P<plain>[^\n]+))"
)
_GRADLE_PROJECT_DIR = re.compile(
    r"""(?mx)
    project\s*\(\s*["'](?P<name>:[^"']+)["']\s*\)
    \s*\.\s*projectDir\s*=\s*
    (?:file\s*\(\s*)?["'](?P<path>[^"']+)["']
    """
)
_QUOTED_VALUE = re.compile(r"""["']([^"']+)["']""")
_GRADLE_PROJECT_DEPENDENCY = re.compile(
    r"""project\s*\(\s*["'](?P<name>:[^"']+)["']\s*\)"""
)
_GRADLE_VERSION_PATTERNS = (
    re.compile(r"JavaLanguageVersion\s*\.\s*of\s*\(\s*(\d{1,2})\s*\)"),
    re.compile(
        r"(?:sourceCompatibility|targetCompatibility)\s*=\s*"
        r"(?:JavaVersion\.VERSION_)?(?:1_)?(\d{1,2})"
    ),
    re.compile(r"jvmToolchain\s*\(\s*(\d{1,2})\s*\)"),
)


def _gradle_includes(settings_text: str) -> tuple[list[str], dict[str, str]]:
    names: list[str] = []
    for match in _GRADLE_INCLUDE.finditer(settings_text):
        arguments = match.group("call") or match.group("plain") or ""
        names.extend(value for value in _QUOTED_VALUE.findall(arguments))
    overrides = {
        match.group("name"): match.group("path")
        for match in _GRADLE_PROJECT_DIR.finditer(settings_text)
    }
    return names, overrides


def _parse_gradle_module(
    root: Path,
    module_root: Path,
    descriptor: Path | None,
    *,
    name: str | None = None,
) -> _Module:
    module = _Module(
        path=_module_path(module_root, root),
        name=name or module_root.name or "root",
        build_system="gradle",
        descriptor=_relative(root, descriptor) if descriptor else None,
    )
    if descriptor is None:
        return module
    text = _read_text(descriptor)
    for pattern in _GRADLE_VERSION_PATTERNS:
        for raw in pattern.findall(text):
            normalized = _normalize_java_version(raw)
            if normalized:
                module.java_versions.add(normalized)
    module.project_dependencies.update(
        match.group("name") for match in _GRADLE_PROJECT_DEPENDENCY.finditer(text)
    )
    lowered = text.lower()
    for marker, framework in _FRAMEWORK_ARTIFACTS.items():
        if marker in lowered:
            module.frameworks.add(framework)
    return module


def _java_version_files(root: Path) -> set[str]:
    versions: set[str] = set()
    for relative in (".java-version", ".sdkmanrc", ".mvn/jvm.config"):
        path = root / relative
        if not path.is_file() or path.is_symlink():
            continue
        text = _read_text(path, max_bytes=64 * 1024)
        normalized = _normalize_java_version(text)
        if normalized:
            versions.add(normalized)
    return versions


def _build_argv(module_root: Path, build_system: str) -> tuple[str, list[str]]:
    if build_system == "maven":
        wrapper = module_root / "mvnw"
        if wrapper.is_file() and not wrapper.is_symlink():
            return (
                "maven-wrapper",
                [
                    "./mvnw",
                    "--batch-mode",
                    "--no-transfer-progress",
                    "-DskipTests",
                    "package",
                ],
            )
        return (
            "maven",
            [
                "mvn",
                "--batch-mode",
                "--no-transfer-progress",
                "-DskipTests",
                "package",
            ],
        )
    wrapper = module_root / "gradlew"
    # `assemble` rather than `classes`: dynamic verification needs something it
    # can run, and `classes` stops at compiled output. `assemble` is the
    # standard lifecycle task for producing archives and picks up the Spring
    # Boot plugin's `bootJar` when it is applied, without this having to detect
    # the plugin.
    if wrapper.is_file() and not wrapper.is_symlink():
        return (
            "gradle-wrapper",
            ["./gradlew", "--no-daemon", "--console=plain", "assemble"],
        )
    return (
        "gradle",
        ["gradle", "--no-daemon", "--console=plain", "assemble"],
    )


def _top_level_modules(modules: list[_Module]) -> list[_Module]:
    return [module for module in modules if module.parent_path is None]


def detect_project(root: Path) -> dict[str, object]:
    root = root.resolve()
    if not root.is_dir():
        raise ProjectDetectionError("source root is unavailable")

    modules: dict[tuple[str, str], _Module] = {}
    maven_queue = sorted(root.rglob("pom.xml"))
    maven_parent_paths: dict[Path, str] = {}
    seen_poms: set[Path] = set()
    while maven_queue:
        pom = maven_queue.pop(0)
        if pom in seen_poms or any(part in _SKIPPED_PARTS for part in pom.parts):
            continue
        seen_poms.add(pom)
        try:
            module, children = _parse_maven_module(root, pom)
        except ProjectDetectionError:
            module = _Module(
                path=_module_path(pom.parent, root),
                name=pom.parent.name or "root",
                build_system="maven",
                descriptor=_relative(root, pom),
            )
            children = []
        module.parent_path = maven_parent_paths.get(pom)
        modules[(module.path, module.build_system)] = module
        for child in children:
            maven_parent_paths.setdefault(child, module.path)
            if child not in seen_poms:
                maven_queue.append(child)
        maven_queue.sort()
    for child_pom, parent_path in maven_parent_paths.items():
        child_module = modules.get(
            (_module_path(child_pom.parent, root), "maven")
        )
        if child_module is not None:
            child_module.parent_path = parent_path

    settings_files = sorted(
        path
        for name in _GRADLE_SETTINGS_FILES
        for path in root.rglob(name)
        if not any(part in _SKIPPED_PARTS for part in path.parts)
    )
    gradle_roots: set[Path] = set()
    for settings in settings_files:
        settings_root = settings.parent
        gradle_roots.add(settings_root)
        text = _read_text(settings)
        included, overrides = _gradle_includes(text)
        root_descriptor = next(
            (
                settings_root / name
                for name in sorted(_GRADLE_BUILD_FILES)
                if (settings_root / name).is_file()
            ),
            None,
        )
        root_module = _parse_gradle_module(
            root,
            settings_root,
            root_descriptor,
            name=settings_root.name or "root",
        )
        modules[(root_module.path, root_module.build_system)] = root_module
        for project_name in included:
            normalized_name = (
                project_name if project_name.startswith(":") else f":{project_name}"
            )
            relative = overrides.get(
                normalized_name,
                normalized_name.strip(":").replace(":", "/"),
            )
            module_root = _safe_child(root, settings_root, relative)
            if module_root is None:
                continue
            descriptor = next(
                (
                    module_root / filename
                    for filename in sorted(_GRADLE_BUILD_FILES)
                    if (module_root / filename).is_file()
                ),
                None,
            )
            child = _parse_gradle_module(
                root,
                module_root,
                descriptor,
                name=normalized_name.strip(":").split(":")[-1],
            )
            child.parent_path = root_module.path
            modules[(child.path, child.build_system)] = child

    for filename in _GRADLE_BUILD_FILES:
        for descriptor in sorted(root.rglob(filename)):
            if any(part in _SKIPPED_PARTS for part in descriptor.parts):
                continue
            module_root = descriptor.parent
            if any(
                module_root == existing_root
                or module_root.is_relative_to(existing_root)
                for existing_root in gradle_roots
            ):
                key = (_module_path(module_root, root), "gradle")
                modules.setdefault(
                    key,
                    _parse_gradle_module(root, module_root, descriptor),
                )
                continue
            module = _parse_gradle_module(root, module_root, descriptor)
            modules[(module.path, module.build_system)] = module

    if not modules:
        modules[(".", "unknown")] = _Module(
            path=".",
            name=root.name or "root",
            build_system="unknown",
            descriptor=None,
        )

    all_modules = sorted(
        modules.values(),
        key=lambda item: (item.path.encode("utf-8"), item.build_system),
    )
    global_versions = _java_version_files(root)
    for module in all_modules:
        module.java_versions.update(global_versions)

    coordinate_paths = {
        module.coordinates: module.path
        for module in all_modules
        if all(module.coordinates)
    }
    gradle_name_paths = {
        f":{module.name}": module.path
        for module in all_modules
        if module.build_system == "gradle"
    }
    dependencies: set[tuple[str, str, str]] = set()
    for module in all_modules:
        for coordinate in module.dependency_coordinates:
            target = coordinate_paths.get(coordinate)
            if target is not None and target != module.path:
                dependencies.add((module.path, target, "maven"))
        for project_name in module.project_dependencies:
            target = gradle_name_paths.get(project_name)
            if target is not None and target != module.path:
                dependencies.add((module.path, target, "gradle"))

    build_systems = {
        module.build_system
        for module in all_modules
        if module.build_system != "unknown"
    }
    if build_systems == {"maven"}:
        build_system = "maven"
    elif build_systems == {"gradle"}:
        build_system = "gradle"
    elif len(build_systems) > 1:
        build_system = "mixed"
    else:
        build_system = "unknown"

    build_plan: list[dict[str, object]] = []
    for module in _top_level_modules(
        [item for item in all_modules if item.build_system != "unknown"]
    ):
        module_root = root if module.path == "." else root / module.path
        runner, argv = _build_argv(module_root, module.build_system)
        build_plan.append(
            {
                "module_path": module.path,
                "build_system": module.build_system,
                "runner": runner,
                "argv": argv,
            }
        )

    return {
        "build_system": build_system,
        "java_versions": sorted(
            {version for module in all_modules for version in module.java_versions},
            key=int,
        ),
        "modules": [
            {
                "path": module.path,
                "name": module.name,
                "build_system": module.build_system,
                "descriptor": module.descriptor,
                "parent_path": module.parent_path,
                "java_versions": sorted(module.java_versions, key=int),
                "frameworks": sorted(module.frameworks),
            }
            for module in all_modules
        ],
        "module_dependencies": [
            {"source": source, "target": target, "kind": kind}
            for source, target, kind in sorted(dependencies)
        ],
        "build_plan": build_plan,
    }
