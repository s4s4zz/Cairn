from __future__ import annotations

from io import BytesIO
from pathlib import Path
import subprocess
from zipfile import ZipFile

import pytest

from . import fixture_builder
from .fixture_builder import build_fixture_archives


FIXTURE_ROOT = Path(__file__).parent / "fixtures"


def test_fixture_archives_are_deterministic_and_have_the_declared_topology(
    tmp_path: Path,
) -> None:
    first_root = tmp_path / "first"
    second_root = tmp_path / "second"
    first = build_fixture_archives(FIXTURE_ROOT, first_root)
    second = build_fixture_archives(FIXTURE_ROOT, second_root)

    assert first == second
    assert set(first) == {
        "SyntheticAction.class",
        "synthetic-core.jar",
        "synthetic-web.war",
        "synthetic-enterprise.ear",
    }
    assert (first_root / "SyntheticAction.class").read_bytes().startswith(
        b"\xca\xfe\xba\xbe"
    )

    with ZipFile(first_root / "synthetic-enterprise.ear") as ear:
        assert set(ear.namelist()) == {
            "META-INF/MANIFEST.MF",
            "META-INF/application.xml",
            "lib/synthetic-core.jar",
            "synthetic-web.war",
        }
        with ZipFile(BytesIO(ear.read("synthetic-web.war"))) as war:
            assert {
                "WEB-INF/classes/org/cairn/fixture/SyntheticAction.class",
                "WEB-INF/lib/synthetic-core.jar",
                "WEB-INF/web.xml",
                "WEB-INF/action-config.xml",
                "views/lookup.jsp",
            } <= set(war.namelist())
            assert war.read(
                "WEB-INF/classes/org/cairn/fixture/SyntheticAction.class"
            ).startswith(b"\xca\xfe\xba\xbe")
            with ZipFile(BytesIO(war.read("WEB-INF/lib/synthetic-core.jar"))) as jar:
                assert "org/cairn/fixture/PlatformRequest.class" in jar.namelist()
                assert "org/cairn/fixture/PlatformSql.class" in jar.namelist()


def test_fixture_builder_rejects_a_different_jdk_major(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def wrong_version(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        del args, kwargs
        return subprocess.CompletedProcess([], 0, stdout="javac 17.0.12", stderr="")

    monkeypatch.setattr(fixture_builder.subprocess, "run", wrong_version)

    with pytest.raises(RuntimeError, match="JDK 21"):
        fixture_builder._require_jdk_21("/fake/javac")
