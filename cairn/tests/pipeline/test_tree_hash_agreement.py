"""One hash, two implementations, nothing pinning them together.

`cairn.server.ingestion.tree` computes `SourceSnapshot.content_sha256` when a
Snapshot is built. `cairn.analysis.tree_hash` recomputes the same value inside
a sandbox, over the extracted copy, and that is what candidate fingerprints and
`root_cause_key`s are derived from.

They agree today by convention — same header, same field order, same
serialisation — and nothing enforces it. The Finding Pipeline binds every
`FindingLocation.snapshot_sha` to the ingestion-side value while the candidate
that produced the location was identified by the sandbox-side one, so a drift
between the two would leave findings citing a Snapshot they do not describe,
silently and without any test failing.
"""

from __future__ import annotations

from pathlib import Path
import tarfile

import pytest

from cairn.analysis.tree_hash import source_tree_sha256
from cairn.server.ingestion import (
    IngestionLimits,
    collect_snapshot_tree,
    write_snapshot_archive,
)


def limits() -> IngestionLimits:
    return IngestionLimits(
        upload_max_bytes=100 * 1024 * 1024,
        max_files=10_000,
        max_total_bytes=100 * 1024 * 1024,
        max_file_bytes=10 * 1024 * 1024,
        max_compression_ratio=200,
        max_path_length=1024,
        max_path_depth=64,
    )


def build_tree(root: Path, files: dict[str, str]) -> None:
    for relative, body in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")


@pytest.mark.parametrize(
    "files",
    [
        pytest.param(
            {
                "src/main/java/A.java": "class A {}\n",
                "pom.xml": "<project/>\n",
            },
            id="flat",
        ),
        pytest.param(
            {
                "web/src/main/java/dev/cairn/Controller.java": "class C {}\n",
                "core/src/main/java/dev/cairn/Repo.java": "class R {}\n",
                "core/src/main/resources/application.yml": "server:\n  port: 8080\n",
                "pom.xml": "<project/>\n",
            },
            id="nested-modules",
        ),
        pytest.param(
            {
                # Names whose ordering differs between byte and codepoint sort,
                # which is exactly where two independent sorts drift apart.
                "src/Z.java": "class Z {}\n",
                "src/a.java": "class a {}\n",
                "src/Ä.java": "class A {}\n",
                "src/sub-dir/B.java": "class B {}\n",
                "src/subdir/C.java": "class C {}\n",
            },
            id="ordering-edges",
        ),
        pytest.param(
            {
                "src/Empty.java": "",
                "src/NoTrailingNewline.java": "class N {}",
                "src/Unicode.java": "// é中文\n class U {}\n",
            },
            id="content-edges",
        ),
    ],
)
def test_the_two_tree_hash_implementations_agree_over_an_archive_round_trip(
    tmp_path: Path,
    files: dict[str, str],
) -> None:
    source = tmp_path / "source"
    source.mkdir()
    build_tree(source, files)

    tree = collect_snapshot_tree(source, limits())
    archive_path = tmp_path / "snapshot.tar"
    write_snapshot_archive(tree, archive_path)

    extracted = tmp_path / "extracted"
    extracted.mkdir()
    with tarfile.open(archive_path) as archive:
        archive.extractall(extracted, filter="data")

    assert source_tree_sha256(extracted) == tree.content_sha256


def test_a_content_change_moves_both_hashes_together(tmp_path: Path) -> None:
    """Neither implementation may be insensitive to something the other sees."""

    digests: list[tuple[str, str]] = []
    for body in ("class A {}\n", "class A { int x; }\n"):
        root = tmp_path / f"tree-{len(digests)}"
        root.mkdir()
        build_tree(root, {"src/A.java": body, "pom.xml": "<project/>\n"})
        tree = collect_snapshot_tree(root, limits())
        archive_path = tmp_path / f"snapshot-{len(digests)}.tar"
        write_snapshot_archive(tree, archive_path)
        extracted = tmp_path / f"extracted-{len(digests)}"
        extracted.mkdir()
        with tarfile.open(archive_path) as archive:
            archive.extractall(extracted, filter="data")
        digests.append((tree.content_sha256, source_tree_sha256(extracted)))

    assert digests[0][0] == digests[0][1]
    assert digests[1][0] == digests[1][1]
    assert digests[0][0] != digests[1][0]
