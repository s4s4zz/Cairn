from __future__ import annotations

from pathlib import Path
import re

from cairn.analysis.normalizers import SourceCatalog, _candidate


RULESET_VERSION = "1.0.0"
_MAX_CONFIG_BYTES = 2 * 1024 * 1024


def _text(path: Path) -> str | None:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > _MAX_CONFIG_BYTES:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def scan_config(
    root: Path,
    *,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    root = root.resolve()
    catalog = SourceCatalog(root)
    candidates: list[dict[str, object]] = []
    rules = (
        (
            re.compile(
                r"(?im)^\s*(?:management\.endpoints\.web\.exposure\.include"
                r"|include)\s*[:=]\s*[\"']?\*[\"']?\s*$"
            ),
            {"application.properties", "application.yml", "application.yaml"},
            "CAIRN-SPRING-ACTUATOR-EXPOSE-ALL",
            "Spring management endpoints expose all actuator endpoints",
            "high",
            ["CWE-284"],
            "spring-config",
        ),
        (
            re.compile(
                r"(?im)^\s*(?:server\.error\.include-stacktrace"
                r"|include-stacktrace)\s*[:=]\s*always\s*$"
            ),
            {"application.properties", "application.yml", "application.yaml"},
            "CAIRN-SPRING-STACKTRACE-DISCLOSURE",
            "Spring error responses always include stack traces",
            "medium",
            ["CWE-209"],
            "spring-config",
        ),
        (
            re.compile(r"(?im)^\s*USER\s+(?:root|0)(?::0)?\s*$"),
            {"dockerfile"},
            "CAIRN-DOCKER-ROOT-USER",
            "Container explicitly runs as root",
            "medium",
            ["CWE-250"],
            "container-config",
        ),
        (
            re.compile(r"(?im)^\s*privileged\s*:\s*true\s*$"),
            {".yaml", ".yml"},
            "CAIRN-K8S-PRIVILEGED",
            "Kubernetes workload enables privileged mode",
            "high",
            ["CWE-250"],
            "kubernetes",
        ),
        (
            re.compile(r"(?im)^\s*host(?:Network|PID|IPC)\s*:\s*true\s*$"),
            {".yaml", ".yml"},
            "CAIRN-K8S-HOST-NAMESPACE",
            "Kubernetes workload joins a host namespace",
            "high",
            ["CWE-668"],
            "kubernetes",
        ),
        (
            re.compile(r"""(?i)["']0\.0\.0\.0/0["']"""),
            {".tf", ".tfvars"},
            "CAIRN-TERRAFORM-WORLD-OPEN",
            "Terraform network rule allows the entire IPv4 Internet",
            "high",
            ["CWE-284"],
            "terraform",
        ),
    )
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        content = _text(path)
        if content is None:
            continue
        relative = path.relative_to(root).as_posix()
        basename = path.name.lower()
        suffix = path.suffix.lower()
        for (
            pattern,
            names,
            rule_id,
            message,
            severity,
            cwes,
            category,
        ) in rules:
            if basename not in names and suffix not in names:
                continue
            for match in pattern.finditer(content):
                line = _line(content, match.start())
                location = catalog.location(
                    relative,
                    line,
                    line,
                    role="related",
                )
                candidates.append(
                    _candidate(
                        snapshot_sha256=snapshot_sha256,
                        catalog=catalog,
                        tool_name="config-rules",
                        rule_id=rule_id,
                        message=message,
                        locations=[location],
                        severity=severity,
                        confidence="high",
                        cwe_ids=cwes,
                        category=category,
                    )
                )
    return sorted(
        candidates,
        key=lambda item: (
            str(item["locations"][0]["path"]).encode("utf-8"),
            int(item["locations"][0]["start_line"]),
            str(item["rule_id"]),
        ),
    )
