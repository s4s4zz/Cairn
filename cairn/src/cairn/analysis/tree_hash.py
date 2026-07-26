from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import unicodedata


_HEADER = b"cairn-source-tree-v1\0"
_CHUNK_SIZE = 1024 * 1024


def source_tree_sha256(root: Path) -> str:
    root = root.resolve()
    files: list[tuple[str, Path, bool, str]] = []
    for directory, directory_names, file_names in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        retained: list[str] = []
        for name in directory_names:
            candidate = directory_path / name
            metadata = candidate.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("source tree contains an unsupported directory entry")
            retained.append(name)
        directory_names[:] = retained
        for name in file_names:
            path = directory_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
                raise ValueError("source tree contains an unsupported file entry")
            relative = unicodedata.normalize(
                "NFC",
                path.relative_to(root).as_posix(),
            )
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                while chunk := stream.read(_CHUNK_SIZE):
                    digest.update(chunk)
            files.append(
                (
                    relative,
                    path,
                    bool(metadata.st_mode & 0o111),
                    digest.hexdigest(),
                )
            )

    result = hashlib.sha256(_HEADER)
    for relative, _path, executable, content_sha256 in sorted(
        files,
        key=lambda item: item[0].encode("utf-8"),
    ):
        encoded_path = relative.encode("utf-8")
        result.update(len(encoded_path).to_bytes(4, "big"))
        result.update(encoded_path)
        result.update(b"\0regular\0")
        result.update(b"1" if executable else b"0")
        result.update(bytes.fromhex(content_sha256))
    return result.hexdigest()
