from __future__ import annotations

from pathlib import Path
import re


MAX_SOURCE_BYTES = 2 * 1024 * 1024
_IGNORED_DIRECTORIES = {
    ".git",
    ".gradle",
    ".idea",
    "build",
    "node_modules",
    "out",
    "target",
    "vendor",
}
_TYPE_PATTERN = re.compile(
    r"\b(?:class|interface|enum|record|@interface)\s+([A-Za-z_$][\w$]*)"
)
_METHOD_PATTERN = re.compile(
    r"""(?x)
    (?:public|protected|private|static|final|synchronized|abstract|native|
       default|strictfp|\s)+
    (?:<[^>{};]+>\s*)?
    [\w$<>\[\],.?]+\s+
    (?P<name>[A-Za-z_$][\w$]*)\s*
    \([^;{}]*\)\s*
    (?:throws\s+[^{;]+)?[{;]
    """
)
_ANNOTATION_PATTERN = re.compile(
    r"@(?P<name>[A-Za-z_$][\w$.]*)(?:\s*\((?P<args>[^)]*)\))?"
)
_ROUTE_VALUE = re.compile(
    r"""(?x)(?:value|path)?\s*=?\s*(?:\{\s*)?["']([^"']+)["']"""
)

_ENTRYPOINT_ANNOTATIONS = {
    "Controller": "http-controller",
    "RestController": "http-controller",
    "RequestMapping": "http-route",
    "GetMapping": "http-route",
    "PostMapping": "http-route",
    "PutMapping": "http-route",
    "PatchMapping": "http-route",
    "DeleteMapping": "http-route",
    "WebFilter": "servlet-filter",
    "WebServlet": "servlet",
    "ServerEndpoint": "websocket",
    "KafkaListener": "message-consumer",
    "RabbitListener": "message-consumer",
    "JmsListener": "message-consumer",
    "Scheduled": "scheduled-job",
    "GrpcService": "rpc-service",
}
_PERMISSION_ANNOTATIONS = {
    "PreAuthorize": "pre-authorize",
    "PostAuthorize": "post-authorize",
    "Secured": "secured",
    "RolesAllowed": "roles-allowed",
    "PermitAll": "permit-all",
    "DenyAll": "deny-all",
    "AuthenticationPrincipal": "authenticated-principal",
}
_SOURCE_ANNOTATIONS = {
    "RequestParam": "http-parameter",
    "PathVariable": "http-path",
    "RequestHeader": "http-header",
    "CookieValue": "http-cookie",
    "RequestBody": "http-body",
    "ModelAttribute": "http-model",
    "RequestPart": "http-upload",
}
_SINK_PATTERNS = (
    (
        re.compile(r"\b(?:Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder)\b"),
        "process-execution",
        ("CWE-78",),
    ),
    (
        re.compile(
            r"\b(?:execute|executeQuery|executeUpdate|queryForObject|"
            r"queryForList|createQuery|createNativeQuery)\s*\("
        ),
        "database-query",
        ("CWE-89",),
    ),
    (
        re.compile(
            r"\b(?:Files\.(?:read|write|copy|move|delete)|"
            r"FileInputStream|FileOutputStream|RandomAccessFile)\b"
        ),
        "filesystem",
        ("CWE-22",),
    ),
    (
        re.compile(
            r"\b(?:new\s+(?:[\w$]+\.)*URL|URI\.create|HttpClient|"
            r"RestTemplate|WebClient)\b"
        ),
        "outbound-http",
        ("CWE-918",),
    ),
    (
        re.compile(
            r"\b(?:ObjectInputStream|XMLDecoder|readObject\s*\(|"
            r"Yaml\.load\s*\()\b"
        ),
        "deserialization",
        ("CWE-502",),
    ),
    (
        re.compile(
            r"\b(?:SpelExpressionParser|Ognl\.|MVEL\.|ExpressionFactory)\b"
        ),
        "expression-evaluation",
        ("CWE-917",),
    ),
    (
        re.compile(
            r"\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|"
            r"TransformerFactory)\b"
        ),
        "xml-parser",
        ("CWE-611",),
    ),
    (
        re.compile(
            r"\b(?:TemplateEngine|FreeMarkerTemplateUtils|VelocityEngine|"
            r"PebbleEngine)\b"
        ),
        "template-render",
        ("CWE-1336",),
    ),
)
_CONFIG_NAMES = {
    "application.properties": "spring-config",
    "application.yml": "spring-config",
    "application.yaml": "spring-config",
    "dockerfile": "container-config",
}
_CONFIG_SUFFIXES = {
    ".tf": "terraform",
    ".tfvars": "terraform",
}


def _read_source(path: Path) -> str | None:
    metadata = path.lstat()
    if path.is_symlink() or not path.is_file() or metadata.st_size > MAX_SOURCE_BYTES:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _strip_comments_and_literals(text: str) -> str:
    output = list(text)
    index = 0
    state = "code"
    while index < len(text):
        current = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if state == "code":
            if current == "/" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "line-comment"
                continue
            if current == "/" and following == "*":
                output[index] = output[index + 1] = " "
                index += 2
                state = "block-comment"
                continue
            if text.startswith('"""', index):
                output[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "text-block"
                continue
            if current == '"':
                output[index] = " "
                index += 1
                state = "string"
                continue
            if current == "'":
                output[index] = " "
                index += 1
                state = "char"
                continue
        elif state == "line-comment":
            if current == "\n":
                state = "code"
            else:
                output[index] = " "
            index += 1
            continue
        elif state == "block-comment":
            if current == "*" and following == "/":
                output[index] = output[index + 1] = " "
                index += 2
                state = "code"
                continue
            if current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state == "text-block":
            if text.startswith('"""', index):
                output[index : index + 3] = [" ", " ", " "]
                index += 3
                state = "code"
                continue
            if current != "\n":
                output[index] = " "
            index += 1
            continue
        elif state in {"string", "char"}:
            terminator = '"' if state == "string" else "'"
            if current == "\\":
                output[index] = " "
                if index + 1 < len(text):
                    if text[index + 1] != "\n":
                        output[index + 1] = " "
                    index += 2
                    continue
            if current == terminator:
                output[index] = " "
                state = "code"
            elif current != "\n":
                output[index] = " "
            index += 1
            continue
        index += 1
    return "".join(output)


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _annotation_name(value: str) -> str:
    return value.rsplit(".", 1)[-1]


def _nearest_symbol(
    symbols: list[dict[str, object]],
    path: str,
    line: int,
) -> str | None:
    candidates = [
        item
        for item in symbols
        if item["path"] == path
        and item["line"] <= line
        and item["kind"] in {"type", "method"}
    ]
    if not candidates:
        return None
    return str(max(candidates, key=lambda item: int(item["line"]))["name"])


def _annotation_symbol(
    symbols: list[dict[str, object]],
    path: str,
    line: int,
) -> str | None:
    following = [
        item
        for item in symbols
        if item["path"] == path
        and item["kind"] in {"type", "method"}
        and line <= int(item["line"]) <= line + 10
    ]
    if following:
        return str(min(following, key=lambda item: int(item["line"]))["name"])
    return _nearest_symbol(symbols, path, line)


def _classify_path(relative: str) -> str | None:
    lowered = relative.lower()
    parts = lowered.split("/")
    basename = parts[-1]
    if "/src/test/" in f"/{lowered}" or basename.endswith("test.java"):
        return "test"
    if any(part in {"generated", "generated-sources"} for part in parts):
        return "generated"
    if any(part in {"vendor", "third_party", "third-party"} for part in parts):
        return "vendored"
    if basename in _CONFIG_NAMES:
        return _CONFIG_NAMES[basename]
    for suffix, kind in _CONFIG_SUFFIXES.items():
        if lowered.endswith(suffix):
            return kind
    if lowered.endswith((".yaml", ".yml")) and any(
        marker in lowered for marker in ("k8s", "kubernetes", "helm", "deploy")
    ):
        return "kubernetes"
    return None


def index_source(root: Path) -> dict[str, object]:
    root = root.resolve()
    symbols: list[dict[str, object]] = []
    entrypoints: list[dict[str, object]] = []
    permissions: list[dict[str, object]] = []
    sources: list[dict[str, object]] = []
    sinks: list[dict[str, object]] = []
    classified_paths: list[dict[str, object]] = []
    skipped_paths: set[str] = set()
    unsupported_components: list[dict[str, object]] = []
    java_files_total = 0

    paths = sorted(
        (
            path
            for path in root.rglob("*")
            if not any(part in _IGNORED_DIRECTORIES for part in path.parts)
        ),
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )
    for path in paths:
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        classification = _classify_path(relative)
        if classification:
            classified_paths.append({"path": relative, "kind": classification})
        if path.suffix.lower() != ".java":
            continue
        java_files_total += 1
        text = _read_source(path)
        if text is None:
            skipped_paths.add(relative)
            unsupported_components.append(
                {
                    "path": relative,
                    "kind": "oversized-java-source",
                    "reason_code": "JAVA_SOURCE_SIZE_LIMIT",
                }
            )
            continue
        stripped = _strip_comments_and_literals(text)
        package_match = re.search(
            r"(?m)^\s*package\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*;",
            stripped,
        )
        package_name = package_match.group(1) if package_match else None
        if package_match:
            symbols.append(
                {
                    "path": relative,
                    "line": _line(stripped, package_match.start()),
                    "kind": "package",
                    "name": package_name,
                    "container": None,
                }
            )

        types: list[tuple[int, str]] = []
        for match in _TYPE_PATTERN.finditer(stripped):
            name = match.group(1)
            line = _line(stripped, match.start())
            qualified = f"{package_name}.{name}" if package_name else name
            types.append((line, qualified))
            symbols.append(
                {
                    "path": relative,
                    "line": line,
                    "kind": "type",
                    "name": qualified,
                    "container": package_name,
                }
            )

        for match in _METHOD_PATTERN.finditer(stripped):
            name = match.group("name")
            line = _line(stripped, match.start())
            container = max(
                (type_name for type_line, type_name in types if type_line <= line),
                default=package_name,
                key=lambda value: len(value or ""),
            )
            symbols.append(
                {
                    "path": relative,
                    "line": line,
                    "kind": "method",
                    "name": name,
                    "container": container,
                }
            )

        annotations: list[tuple[int, str, str | None]] = []
        for match in _ANNOTATION_PATTERN.finditer(stripped):
            name = _annotation_name(match.group("name"))
            line = _line(stripped, match.start())
            arguments = (
                text[match.start("args") : match.end("args")]
                if match.group("args") is not None
                else None
            )
            annotations.append((line, name, arguments))
            symbols.append(
                {
                    "path": relative,
                    "line": line,
                    "kind": "annotation",
                    "name": name,
                    "container": _nearest_symbol(symbols, relative, line),
                }
            )

        for line, name, arguments in annotations:
            symbol = _annotation_symbol(symbols, relative, line) or relative
            if name in _ENTRYPOINT_ANNOTATIONS:
                route_match = _ROUTE_VALUE.search(arguments or "")
                entrypoints.append(
                    {
                        "path": relative,
                        "line": line,
                        "kind": _ENTRYPOINT_ANNOTATIONS[name],
                        "symbol": symbol,
                        "route": route_match.group(1) if route_match else None,
                        "annotations": [name],
                    }
                )
            if name in _PERMISSION_ANNOTATIONS:
                permissions.append(
                    {
                        "path": relative,
                        "line": line,
                        "kind": _PERMISSION_ANNOTATIONS[name],
                        "symbol": symbol,
                        "expression": (arguments or "").strip() or None,
                    }
                )
            if name in _SOURCE_ANNOTATIONS:
                sources.append(
                    {
                        "path": relative,
                        "line": line,
                        "kind": _SOURCE_ANNOTATIONS[name],
                        "symbol": symbol,
                        "cwe_ids": [],
                    }
                )

        for pattern, kind, cwe_ids in _SINK_PATTERNS:
            for match in pattern.finditer(stripped):
                line = _line(stripped, match.start())
                sinks.append(
                    {
                        "path": relative,
                        "line": line,
                        "kind": kind,
                        "symbol": _nearest_symbol(symbols, relative, line),
                        "cwe_ids": list(cwe_ids),
                    }
                )

        for match in re.finditer(
            r"\b(?:HttpServletRequest|ServerHttpRequest|MultipartFile)\b",
            stripped,
        ):
            line = _line(stripped, match.start())
            sources.append(
                {
                    "path": relative,
                    "line": line,
                    "kind": "request-object",
                    "symbol": _nearest_symbol(symbols, relative, line),
                    "cwe_ids": [],
                }
            )
        for match in re.finditer(
            r"\b(?:authorizeHttpRequests|requestMatchers|antMatchers)\b",
            stripped,
        ):
            line = _line(stripped, match.start())
            permissions.append(
                {
                    "path": relative,
                    "line": line,
                    "kind": "security-configuration",
                    "symbol": _nearest_symbol(symbols, relative, line),
                    "expression": None,
                }
            )

    key = lambda item: (  # noqa: E731
        str(item.get("path", "")).encode("utf-8"),
        int(item.get("line", 0)),
        str(item.get("kind", "")),
        str(item.get("name", item.get("symbol", ""))),
    )
    return {
        "symbols": sorted(symbols, key=key),
        "entrypoints": sorted(entrypoints, key=key),
        "permissions": sorted(permissions, key=key),
        "sources": sorted(sources, key=key),
        "sinks": sorted(sinks, key=key),
        "classified_paths": sorted(
            classified_paths,
            key=lambda item: (str(item["path"]).encode("utf-8"), str(item["kind"])),
        ),
        "java_files_total": java_files_total,
        "skipped_paths": sorted(skipped_paths),
        "unsupported_components": sorted(
            unsupported_components,
            key=lambda item: str(item["path"]).encode("utf-8"),
        ),
    }


def build_inventory(root: Path) -> dict[str, object]:
    from cairn.analysis.project import detect_project

    project = detect_project(root)
    index = index_source(root)
    return {**project, **index}
