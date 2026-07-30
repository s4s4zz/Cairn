"""Deterministic authorization-topology facts from XML descriptors (图二).

Two things the annotation-only source index cannot see live in XML:

* ``web.xml`` ``<filter-mapping>`` — the classic Servlet way to bind a filter
  to a set of URL patterns and dispatcher types.
* XML Spring Security ``<intercept-url>`` — pattern-to-access rules, the form
  older enterprise platforms (the CP1 targets among them) use instead of the
  Java ``SecurityFilterChain`` DSL.

Both are pure configuration: they exist in the immutable Snapshot and need no
build, which is exactly why the authorization topology can be computed for a
source Snapshot whose build fails.

Untrusted input. The parser reads repository-controlled XML, so it bounds file
size and relies on the standard library's refusal to resolve external general
entities (no network fetch, no file read). It never executes or interprets the
descriptor — it only reports the mappings it contains.
"""

from __future__ import annotations

from pathlib import Path
import xml.etree.ElementTree as ElementTree


_MAX_XML_BYTES = 4 * 1024 * 1024
# Same conservative auth read as the source indexer; kept local to avoid an
# import cycle with `indexer.build_inventory`, which merges this module's output.
_AUTH_MARKERS = (
    "auth",
    "security",
    "login",
    "token",
    "jwt",
    "sso",
    "permission",
    "access",
    "session",
    "principal",
    "oauth",
    "saml",
    "credential",
    "guard",
    "shiro",
    "satoken",
)
_PERMIT_TOKENS = frozenset(
    {"permitall", "ispermitall", "isanonymous()", "none", "no_restriction"}
)


def _localname(tag: object) -> str:
    """Drop any XML namespace so `{jakarta...}filter` matches `filter`."""

    return str(tag).rsplit("}", 1)[-1]


def _enforces_auth(*text: str) -> bool:
    lowered = " ".join(text).lower()
    return any(marker in lowered for marker in _AUTH_MARKERS)


def parse_web_descriptors(root: Path) -> list[dict[str, object]]:
    """Return `InterceptorRecord`-shaped dicts from every XML descriptor.

    Deterministic in content and order: two runs over one Snapshot produce the
    same list.
    """

    root = root.resolve()
    records: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.xml")):
        if path.is_symlink() or not path.is_file():
            continue
        try:
            if path.stat().st_size > _MAX_XML_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            tree = ElementTree.fromstring(text)
        except (OSError, ElementTree.ParseError):
            continue
        relative = path.relative_to(root).as_posix()
        if path.name.lower() == "web.xml":
            records.extend(_parse_web_xml(tree, relative))
        else:
            records.extend(_parse_spring_security(tree, relative))
    return sorted(
        records,
        key=lambda record: (
            str(record["path"]).encode("utf-8"),
            str(record["kind"]),
            str(record["class_name"]),
        ),
    )


def parse_descriptor_content(
    content: str, logical_path: str
) -> list[dict[str, object]]:
    """Parse one XML descriptor's text into `InterceptorRecord`-shaped dicts.

    For the bytecode path (图二 v2), where web.xml / Spring Security XML arrive
    as text extracted from an archive rather than as files on disk.
    """

    try:
        tree = ElementTree.fromstring(content)
    except ElementTree.ParseError:
        return []
    name = logical_path.rsplit("/", 1)[-1].lower()
    if name == "web.xml":
        return _parse_web_xml(tree, logical_path)
    return _parse_spring_security(tree, logical_path)


def _parse_web_xml(tree: ElementTree.Element, relative: str) -> list[dict[str, object]]:
    filters: dict[str, str] = {}
    mappings: dict[str, tuple[list[str], list[str]]] = {}
    for element in tree.iter():
        tag = _localname(element.tag)
        if tag == "filter":
            name = klass = None
            for child in element:
                child_tag = _localname(child.tag)
                if child_tag == "filter-name":
                    name = (child.text or "").strip()
                elif child_tag == "filter-class":
                    klass = (child.text or "").strip()
            if name and klass:
                filters[name] = klass
        elif tag == "filter-mapping":
            name = None
            patterns: list[str] = []
            dispatchers: list[str] = []
            for child in element:
                child_tag = _localname(child.tag)
                if child_tag == "filter-name":
                    name = (child.text or "").strip()
                elif child_tag == "url-pattern" and (child.text or "").strip():
                    patterns.append(child.text.strip())
                elif child_tag == "dispatcher" and (child.text or "").strip():
                    dispatchers.append(child.text.strip())
            if name:
                existing = mappings.setdefault(name, ([], []))
                existing[0].extend(patterns)
                existing[1].extend(dispatchers)

    records: list[dict[str, object]] = []
    for name, klass in filters.items():
        patterns, dispatchers = mappings.get(name, ([], []))
        records.append(
            {
                "kind": "servlet-filter",
                "class_name": klass,
                "url_patterns": sorted(set(patterns)),
                "dispatcher_types": sorted(set(dispatchers)),
                "order": None,
                "enforces_auth": _enforces_auth(klass, name),
                "source": "web.xml",
                "path": relative,
                "line": 1,
            }
        )
    return records


def _parse_spring_security(
    tree: ElementTree.Element, relative: str
) -> list[dict[str, object]]:
    if not any(_localname(element.tag) == "intercept-url" for element in tree.iter()):
        return []
    records: list[dict[str, object]] = []
    for element in tree.iter():
        if _localname(element.tag) != "intercept-url":
            continue
        pattern = element.get("pattern") or element.get("path")
        if not pattern:
            continue
        access = (element.get("access") or "").strip()
        permit = not access or access.lower() in _PERMIT_TOKENS or "permitall" in access.lower()
        records.append(
            {
                "kind": "security-chain",
                "class_name": f"spring-security:{access or 'unspecified'}",
                "url_patterns": [pattern],
                "dispatcher_types": [],
                "order": None,
                # A permitAll rule is an explicit *pass* — it does not enforce
                # auth. The topology reads an unenforced rule over a sensitive
                # entrypoint as a structural bypass, exactly as intended.
                "enforces_auth": not permit,
                "source": "xml-config",
                "path": relative,
                "line": 1,
            }
        )
    return records
