from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
from zipfile import ZIP_STORED, ZipFile, ZipInfo


JAVA_SOURCES = (
    "AuthorizationGuard.java",
    "PlatformRequest.java",
    "PlatformSql.java",
    "SyntheticAction.java",
    "TenantGuard.java",
)
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def build_fixture_archives(fixture_root: Path, output_root: Path) -> dict[str, str]:
    """Compile and package the project-authored CP0 fixture deterministically."""

    fixture_root = fixture_root.resolve()
    output_root = output_root.resolve()
    javac = shutil.which("javac")
    if javac is None:
        raise RuntimeError("JDK 21 javac is required to build the closed-platform fixture")
    _require_jdk_21(javac)
    source_root = fixture_root / "src/org/cairn/fixture"
    sources = [source_root / name for name in JAVA_SOURCES]
    missing = [path.name for path in sources if not path.is_file()]
    if missing:
        raise RuntimeError(f"fixture sources are missing: {', '.join(missing)}")

    classes = output_root / "classes"
    classes.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment.update({"LC_ALL": "C", "SOURCE_DATE_EPOCH": "315532800"})
    subprocess.run(
        [
            javac,
            "--release",
            "17",
            "-encoding",
            "UTF-8",
            "-g:none",
            "-d",
            str(classes),
            *(str(path) for path in sources),
        ],
        check=True,
        cwd=fixture_root,
        env=environment,
        capture_output=True,
        timeout=30,
    )

    package = classes / "org/cairn/fixture"
    class_bytes = {
        name.removesuffix(".java") + ".class": (
            package / (name.removesuffix(".java") + ".class")
        ).read_bytes()
        for name in JAVA_SOURCES
    }
    for name, payload in class_bytes.items():
        if not payload.startswith(b"\xca\xfe\xba\xbe"):
            raise RuntimeError(f"javac did not produce a classfile for {name}")

    manifest = b"Manifest-Version: 1.0\r\nCreated-By: Cairn CP0 fixture builder\r\n\r\n"
    core_entries = {
        "META-INF/MANIFEST.MF": manifest,
        **{
            f"org/cairn/fixture/{name}": payload
            for name, payload in class_bytes.items()
            if name != "SyntheticAction.class"
        },
    }
    core_jar = output_root / "synthetic-core.jar"
    _write_archive(core_jar, core_entries)

    action_class = output_root / "SyntheticAction.class"
    action_class.write_bytes(class_bytes["SyntheticAction.class"])
    web_root = fixture_root / "web"
    war_entries = {
        "META-INF/MANIFEST.MF": manifest,
        "WEB-INF/classes/org/cairn/fixture/SyntheticAction.class": class_bytes[
            "SyntheticAction.class"
        ],
        "WEB-INF/lib/synthetic-core.jar": core_jar.read_bytes(),
        "WEB-INF/web.xml": (web_root / "WEB-INF/web.xml").read_bytes(),
        "WEB-INF/action-config.xml": (
            web_root / "WEB-INF/action-config.xml"
        ).read_bytes(),
        "views/lookup.jsp": (web_root / "views/lookup.jsp").read_bytes(),
    }
    web_war = output_root / "synthetic-web.war"
    _write_archive(web_war, war_entries)

    application_xml = b"""<?xml version="1.0" encoding="UTF-8"?>
<application xmlns="https://jakarta.ee/xml/ns/jakartaee" version="10">
  <display-name>Cairn synthetic enterprise fixture</display-name>
  <module><web><web-uri>synthetic-web.war</web-uri><context-root>/fixture</context-root></web></module>
</application>
"""
    enterprise_ear = output_root / "synthetic-enterprise.ear"
    _write_archive(
        enterprise_ear,
        {
            "META-INF/MANIFEST.MF": manifest,
            "META-INF/application.xml": application_xml,
            "lib/synthetic-core.jar": core_jar.read_bytes(),
            "synthetic-web.war": web_war.read_bytes(),
        },
    )

    return {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (action_class, core_jar, web_war, enterprise_ear)
    }


def _require_jdk_21(javac: str) -> None:
    result = subprocess.run(
        [javac, "-version"],
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
    )
    version = f"{result.stdout}\n{result.stderr}".strip()
    if re.search(r"\bjavac 21(?:\.|\s|$)", version) is None:
        raise RuntimeError(
            "JDK 21 javac is required for the reproducible closed-platform fixture"
        )


def _write_archive(path: Path, entries: dict[str, bytes]) -> None:
    with ZipFile(path, mode="w", compression=ZIP_STORED, strict_timestamps=True) as archive:
        for name in sorted(entries):
            info = ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
