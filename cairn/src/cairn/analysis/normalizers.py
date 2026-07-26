from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
import re
from typing import Callable
from urllib.parse import unquote, urlparse
import xml.etree.ElementTree as ElementTree

from cairn.analysis.fingerprints import (
    candidate_identity,
    normalize_confidence,
    normalize_cwe_ids,
    normalize_severity,
)


MAX_RAW_RESULT_BYTES = 64 * 1024 * 1024
MAX_CANDIDATES = 100_000
_CATEGORY_CWE = {
    "command-injection": ["CWE-78"],
    "config": ["CWE-16"],
    "deserialization": ["CWE-502"],
    "path-traversal": ["CWE-22"],
    "secret": ["CWE-798"],
    "sql-injection": ["CWE-89"],
    "ssrf": ["CWE-918"],
    "vulnerability": ["CWE-1104"],
    "xxe": ["CWE-611"],
}
_DEPENDENCY_DESCRIPTOR_NAMES = frozenset(
    {
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "pom.xml",
    }
)


class NormalizationError(ValueError):
    pass


class SourceCatalog:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self._line_counts: dict[str, int] = {}
        for path in sorted(self.root.rglob("*")):
            if path.is_symlink() or not path.is_file():
                continue
            relative = path.relative_to(self.root).as_posix()
            try:
                with path.open("rb") as stream:
                    count = 1
                    while chunk := stream.read(1024 * 1024):
                        count += chunk.count(b"\n")
            except OSError:
                continue
            self._line_counts[relative] = count

    @property
    def paths(self) -> set[str]:
        return set(self._line_counts)

    def normalize_path(self, value: object) -> str:
        rendered = unquote(str(value or "").strip()).replace("\\", "/")
        if rendered.startswith("file:"):
            parsed = urlparse(rendered)
            rendered = parsed.path
        had_allowed_absolute_prefix = False
        for prefix in (
            "/work/source/",
            "work/source/",
            "/work/scratch/project/",
            "work/scratch/project/",
        ):
            if rendered.startswith(prefix):
                rendered = rendered[len(prefix) :]
                had_allowed_absolute_prefix = prefix.startswith("/")
                break
        if rendered.startswith("/") and not had_allowed_absolute_prefix:
            raise NormalizationError("scanner location is outside the Snapshot")
        if rendered.startswith("./"):
            rendered = rendered[2:]
        path = PurePosixPath(rendered)
        if (
            not rendered
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
        ):
            raise NormalizationError("scanner location is not a relative path")
        normalized = path.as_posix()
        if normalized not in self._line_counts:
            suffix_matches = [
                candidate
                for candidate in self._line_counts
                if candidate.endswith(f"/{normalized}")
            ]
            if len(suffix_matches) != 1:
                raise NormalizationError("scanner location is outside the Snapshot")
            normalized = suffix_matches[0]
        return normalized

    def location(
        self,
        path: object,
        start_line: object,
        end_line: object | None = None,
        *,
        start_column: object | None = None,
        end_column: object | None = None,
        symbol: object | None = None,
        role: str = "related",
    ) -> dict[str, object]:
        normalized_path = self.normalize_path(path)
        start = _positive_int(start_line, default=1)
        end = _positive_int(end_line, default=start)
        if end < start or end > self._line_counts[normalized_path] + 1:
            raise NormalizationError("scanner location has an invalid line range")
        result: dict[str, object] = {
            "path": normalized_path,
            "start_line": start,
            "end_line": end,
            "start_column": _optional_positive_int(start_column),
            "end_column": _optional_positive_int(end_column),
            "symbol": _bounded_text(symbol, 1024) or None,
            "role": role,
        }
        return result

    def dependency_descriptor(self, value: object) -> str:
        """Locate an external dependency-cache result in the source tree."""
        rendered = unquote(str(value or "").strip()).replace("\\", "/")
        relative_hint: PurePosixPath | None = None
        for prefix in (
            "/work/source/",
            "work/source/",
            "/work/scratch/project/",
            "work/scratch/project/",
        ):
            if rendered.startswith(prefix):
                possible_hint = PurePosixPath(rendered[len(prefix) :])
                if not any(part in {"", ".", ".."} for part in possible_hint.parts):
                    relative_hint = possible_hint
                break

        descriptors = [
            PurePosixPath(path)
            for path in self._line_counts
            if PurePosixPath(path).name in _DEPENDENCY_DESCRIPTOR_NAMES
            or PurePosixPath(path).name.endswith(".lockfile")
        ]
        if not descriptors:
            raise NormalizationError(
                "dependency result cannot be located in the Snapshot"
            )

        if relative_hint is not None:
            ancestors = [
                descriptor
                for descriptor in descriptors
                if descriptor.parent == PurePosixPath(".")
                or relative_hint.is_relative_to(descriptor.parent)
            ]
            if ancestors:
                descriptors = ancestors
                deepest = max(len(descriptor.parent.parts) for descriptor in descriptors)
                descriptors = [
                    descriptor
                    for descriptor in descriptors
                    if len(descriptor.parent.parts) == deepest
                ]

        def priority(descriptor: PurePosixPath) -> tuple[int, int, str]:
            name = descriptor.name
            if descriptor.as_posix() == "pom.xml":
                kind = 0
            elif name == "gradle.lockfile" or name.endswith(".lockfile"):
                kind = 1
            elif name == "pom.xml":
                kind = 2
            else:
                kind = 3
            return kind, len(descriptor.parts), descriptor.as_posix()

        return min(descriptors, key=priority).as_posix()


def _positive_int(value: object, *, default: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except (TypeError, ValueError) as exc:
        raise NormalizationError("scanner location has a non-integer line") from exc
    if parsed < 1:
        raise NormalizationError("scanner location line must be positive")
    return parsed


def _optional_positive_int(value: object) -> int | None:
    if value is None:
        return None
    return _positive_int(value, default=1)


def _bounded_text(value: object, maximum: int) -> str:
    rendered = re.sub(r"\s+", " ", str(value or "")).strip()
    return rendered[:maximum]


def _category(value: object, fallback: str) -> str:
    rendered = re.sub(r"[^a-z0-9_.-]+", "-", str(value or "").strip().lower())
    return rendered.strip("-")[:255] or fallback


def _candidate(
    *,
    snapshot_sha256: str,
    catalog: SourceCatalog,
    tool_name: str,
    rule_id: object,
    message: object,
    locations: list[dict[str, object]],
    severity: object,
    confidence: object,
    cwe_ids: object,
    category: object,
    sink: object = None,
) -> dict[str, object]:
    if not locations:
        raise NormalizationError("scanner candidate has no valid location")
    normalized_rule = _bounded_text(rule_id, 512)
    if not normalized_rule:
        raise NormalizationError("scanner candidate has no rule identifier")
    normalized_message = _bounded_text(message, 16_384)
    if not normalized_message:
        normalized_message = normalized_rule
    normalized_category = _category(category, "security")
    normalized_cwes = normalize_cwe_ids(cwe_ids) or _CATEGORY_CWE.get(
        normalized_category,
        [],
    )
    normalized_sink = _bounded_text(sink, 1024) or None
    fingerprint, root_cause_key = candidate_identity(
        snapshot_sha256=snapshot_sha256,
        rule_id=normalized_rule,
        cwe_ids=normalized_cwes,
        category=normalized_category,
        primary_location=locations[0],
        sink=normalized_sink,
        tool_name=tool_name,
    )
    return {
        "rule_id": normalized_rule,
        "cwe_ids": normalized_cwes,
        "category": normalized_category,
        "severity": normalize_severity(severity),
        "confidence": normalize_confidence(confidence),
        "message": normalized_message,
        "locations": locations,
        "sink": normalized_sink,
        "fingerprint": fingerprint,
        "root_cause_key": root_cause_key,
        "discovered_by": [tool_name],
        "source_rules": [normalized_rule],
    }


def _load_json(path: Path) -> object:
    try:
        size = path.stat().st_size
        if path.is_symlink() or not path.is_file() or size > MAX_RAW_RESULT_BYTES:
            raise NormalizationError("scanner result exceeds the size limit")
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise NormalizationError("scanner result is not valid JSON") from exc


def normalize_semgrep(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise NormalizationError("Semgrep result has an invalid shape")
    candidates: list[dict[str, object]] = []
    for result in payload["results"][:MAX_CANDIDATES]:
        if not isinstance(result, dict):
            continue
        extra = result.get("extra") if isinstance(result.get("extra"), dict) else {}
        metadata = (
            extra.get("metadata") if isinstance(extra.get("metadata"), dict) else {}
        )
        start = result.get("start") if isinstance(result.get("start"), dict) else {}
        end = result.get("end") if isinstance(result.get("end"), dict) else {}
        location = catalog.location(
            result.get("path"),
            start.get("line"),
            end.get("line"),
            start_column=start.get("col"),
            end_column=end.get("col"),
            role="sink",
        )
        candidates.append(
            _candidate(
                snapshot_sha256=snapshot_sha256,
                catalog=catalog,
                tool_name="semgrep",
                rule_id=result.get("check_id"),
                message=extra.get("message"),
                locations=[location],
                severity=extra.get("severity"),
                confidence=metadata.get("confidence"),
                cwe_ids=metadata.get("cwe"),
                category=metadata.get("category") or "sast",
                sink=metadata.get("technology"),
            )
        )
    return candidates


def normalize_gitleaks(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    payload = _load_json(path)
    if not isinstance(payload, list):
        raise NormalizationError("gitleaks result has an invalid shape")
    candidates: list[dict[str, object]] = []
    for result in payload[:MAX_CANDIDATES]:
        if not isinstance(result, dict):
            continue
        location = catalog.location(
            result.get("File"),
            result.get("StartLine"),
            result.get("EndLine"),
            start_column=result.get("StartColumn"),
            end_column=result.get("EndColumn"),
            role="source",
        )
        candidates.append(
            _candidate(
                snapshot_sha256=snapshot_sha256,
                catalog=catalog,
                tool_name="gitleaks",
                rule_id=result.get("RuleID"),
                message=result.get("Description") or "Hard-coded secret",
                locations=[location],
                severity="high",
                confidence="high",
                cwe_ids=["CWE-798"],
                category="secret",
            )
        )
    return candidates


def _sarif_rule_metadata(run: dict[str, object]) -> dict[str, dict[str, object]]:
    tool = run.get("tool") if isinstance(run.get("tool"), dict) else {}
    driver = tool.get("driver") if isinstance(tool.get("driver"), dict) else {}
    rules = driver.get("rules") if isinstance(driver.get("rules"), list) else []
    return {
        str(rule.get("id")): rule
        for rule in rules
        if isinstance(rule, dict) and rule.get("id")
    }


def normalize_sarif(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
    tool_name: str = "codeql",
) -> list[dict[str, object]]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("runs"), list):
        raise NormalizationError("SARIF result has an invalid shape")
    candidates: list[dict[str, object]] = []
    for run in payload["runs"]:
        if not isinstance(run, dict):
            continue
        rules = _sarif_rule_metadata(run)
        results = run.get("results") if isinstance(run.get("results"), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "")
            rule = rules.get(rule_id, {})
            properties = (
                rule.get("properties")
                if isinstance(rule.get("properties"), dict)
                else {}
            )
            tags = properties.get("tags") if isinstance(properties.get("tags"), list) else []
            cwes = normalize_cwe_ids(tags)
            locations: list[dict[str, object]] = []
            raw_locations = (
                result.get("locations")
                if isinstance(result.get("locations"), list)
                else []
            )
            for raw_location in raw_locations[:128]:
                if not isinstance(raw_location, dict):
                    continue
                physical = raw_location.get("physicalLocation")
                if not isinstance(physical, dict):
                    continue
                artifact = physical.get("artifactLocation")
                region = physical.get("region")
                if not isinstance(artifact, dict):
                    continue
                if not isinstance(region, dict):
                    region = {}
                locations.append(
                    catalog.location(
                        artifact.get("uri"),
                        region.get("startLine"),
                        region.get("endLine"),
                        start_column=region.get("startColumn"),
                        end_column=region.get("endColumn"),
                        role="sink",
                    )
                )
            message_data = (
                result.get("message")
                if isinstance(result.get("message"), dict)
                else {}
            )
            candidates.append(
                _candidate(
                    snapshot_sha256=snapshot_sha256,
                    catalog=catalog,
                    tool_name=tool_name,
                    rule_id=rule_id,
                    message=message_data.get("text") or message_data.get("markdown"),
                    locations=locations,
                    severity=result.get("level") or properties.get("problem.severity"),
                    confidence=properties.get("precision"),
                    cwe_ids=cwes,
                    category=properties.get("tags", ["sast"])[0]
                    if properties.get("tags")
                    else "sast",
                )
            )
    return candidates


def normalize_findsecbugs(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    try:
        if path.stat().st_size > MAX_RAW_RESULT_BYTES:
            raise NormalizationError("FindSecBugs result exceeds the size limit")
        root = ElementTree.parse(path).getroot()
    except (OSError, ElementTree.ParseError) as exc:
        raise NormalizationError("FindSecBugs result is not valid XML") from exc
    candidates: list[dict[str, object]] = []
    for bug in list(root.iter("BugInstance"))[:MAX_CANDIDATES]:
        source_line = next(iter(bug.iter("SourceLine")), None)
        if source_line is None:
            continue
        raw_cwes = [
            element.attrib.get("id", "")
            for element in bug.iter()
            if element.tag.rsplit("}", 1)[-1] == "CWE"
        ]
        priority = bug.attrib.get("priority") or bug.attrib.get("rank")
        severity = {"1": "high", "2": "medium", "3": "low"}.get(
            str(priority),
            "medium",
        )
        location = catalog.location(
            source_line.attrib.get("sourcepath")
            or source_line.attrib.get("sourcefile"),
            source_line.attrib.get("start"),
            source_line.attrib.get("end"),
            role="sink",
        )
        message_element = next(iter(bug.iter("LongMessage")), None)
        message = (
            message_element.text
            if message_element is not None and message_element.text
            else bug.attrib.get("type")
        )
        candidates.append(
            _candidate(
                snapshot_sha256=snapshot_sha256,
                catalog=catalog,
                tool_name="findsecbugs",
                rule_id=bug.attrib.get("type"),
                message=message,
                locations=[location],
                severity=severity,
                confidence="high" if severity == "high" else "medium",
                cwe_ids=raw_cwes or bug.attrib.get("cweid"),
                category=bug.attrib.get("category") or "sast",
            )
        )
    return candidates


def normalize_dependency_check(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(
        payload.get("dependencies"),
        list,
    ):
        raise NormalizationError("Dependency-Check result has an invalid shape")
    candidates: list[dict[str, object]] = []
    for dependency in payload["dependencies"]:
        if not isinstance(dependency, dict):
            continue
        dependency_path = dependency.get("filePath") or dependency.get("fileName")
        vulnerabilities = (
            dependency.get("vulnerabilities")
            if isinstance(dependency.get("vulnerabilities"), list)
            else []
        )
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                continue
            try:
                location = catalog.location(
                    dependency_path,
                    1,
                    1,
                    role="related",
                )
            except NormalizationError:
                location = catalog.location(
                    catalog.dependency_descriptor(dependency_path),
                    1,
                    1,
                    role="related",
                )
            candidates.append(
                _candidate(
                    snapshot_sha256=snapshot_sha256,
                    catalog=catalog,
                    tool_name="dependency-check",
                    rule_id=vulnerability.get("name"),
                    message=vulnerability.get("description")
                    or vulnerability.get("name"),
                    locations=[location],
                    severity=vulnerability.get("severity"),
                    confidence="high",
                    cwe_ids=vulnerability.get("cwes"),
                    category="vulnerability",
                    sink=dependency.get("fileName"),
                )
            )
            if len(candidates) >= MAX_CANDIDATES:
                return candidates
    return candidates


def normalize_trivy(
    path: Path,
    *,
    catalog: SourceCatalog,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    payload = _load_json(path)
    if not isinstance(payload, dict) or not isinstance(payload.get("Results"), list):
        raise NormalizationError("Trivy result has an invalid shape")
    candidates: list[dict[str, object]] = []
    for result in payload["Results"]:
        if not isinstance(result, dict):
            continue
        target = result.get("Target")
        for vulnerability in result.get("Vulnerabilities") or []:
            if not isinstance(vulnerability, dict):
                continue
            location = catalog.location(target, 1, 1, role="related")
            candidates.append(
                _candidate(
                    snapshot_sha256=snapshot_sha256,
                    catalog=catalog,
                    tool_name="trivy",
                    rule_id=vulnerability.get("VulnerabilityID"),
                    message=vulnerability.get("Description")
                    or vulnerability.get("Title"),
                    locations=[location],
                    severity=vulnerability.get("Severity"),
                    confidence="high",
                    cwe_ids=vulnerability.get("CweIDs"),
                    category="vulnerability",
                    sink=vulnerability.get("PkgName"),
                )
            )
        for misconfiguration in result.get("Misconfigurations") or []:
            if not isinstance(misconfiguration, dict):
                continue
            cause = (
                misconfiguration.get("CauseMetadata")
                if isinstance(misconfiguration.get("CauseMetadata"), dict)
                else {}
            )
            location = catalog.location(
                target,
                cause.get("StartLine"),
                cause.get("EndLine"),
                role="related",
            )
            candidates.append(
                _candidate(
                    snapshot_sha256=snapshot_sha256,
                    catalog=catalog,
                    tool_name="trivy",
                    rule_id=misconfiguration.get("ID")
                    or misconfiguration.get("AVDID"),
                    message=misconfiguration.get("Message")
                    or misconfiguration.get("Description"),
                    locations=[location],
                    severity=misconfiguration.get("Severity"),
                    confidence="high",
                    cwe_ids=misconfiguration.get("CweIDs"),
                    category="config",
                )
            )
        for secret in result.get("Secrets") or []:
            if not isinstance(secret, dict):
                continue
            location = catalog.location(
                target,
                secret.get("StartLine"),
                secret.get("EndLine"),
                role="source",
            )
            candidates.append(
                _candidate(
                    snapshot_sha256=snapshot_sha256,
                    catalog=catalog,
                    tool_name="trivy",
                    rule_id=secret.get("RuleID"),
                    message=secret.get("Title") or "Hard-coded secret",
                    locations=[location],
                    severity=secret.get("Severity") or "high",
                    confidence="high",
                    cwe_ids=["CWE-798"],
                    category="secret",
                )
            )
        if len(candidates) >= MAX_CANDIDATES:
            return candidates[:MAX_CANDIDATES]
    return candidates


NORMALIZERS: dict[
    str,
    Callable[..., list[dict[str, object]]],
] = {
    "codeql": normalize_sarif,
    "semgrep": normalize_semgrep,
    "findsecbugs": normalize_findsecbugs,
    "dependency-check": normalize_dependency_check,
    "trivy": normalize_trivy,
    "gitleaks": normalize_gitleaks,
}


def normalize_tool_result(
    tool_name: str,
    path: Path,
    *,
    source_root: Path,
    snapshot_sha256: str,
) -> list[dict[str, object]]:
    try:
        normalizer = NORMALIZERS[tool_name]
    except KeyError as exc:
        raise NormalizationError("scanner does not have a registered normalizer") from exc
    return normalizer(
        path,
        catalog=SourceCatalog(source_root),
        snapshot_sha256=snapshot_sha256,
    )
