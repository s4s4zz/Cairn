#!/usr/bin/env python3
"""Normalize stopped workload trees without following untrusted links."""

from __future__ import annotations

import os
from pathlib import Path
import stat


ROOTS = (Path("/work/scratch"), Path("/work/output"))


def main() -> int:
    for root in ROOTS:
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            return 65
        os.chmod(root, 0o777, follow_symlinks=False)
        for directory, directory_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            directory_path = Path(directory)
            os.chmod(directory_path, 0o777, follow_symlinks=False)
            for name in directory_names:
                candidate = directory_path / name
                child = candidate.lstat()
                if stat.S_ISDIR(child.st_mode) and not stat.S_ISLNK(child.st_mode):
                    os.chmod(candidate, 0o777, follow_symlinks=False)
            for name in file_names:
                candidate = directory_path / name
                child = candidate.lstat()
                if not stat.S_ISLNK(child.st_mode):
                    os.chmod(candidate, 0o644, follow_symlinks=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
