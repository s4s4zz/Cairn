from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import threading
from uuid import UUID

from pydantic import ValidationError

from cairn.sandbox.contracts import SandboxRecord
from cairn.sandbox.errors import SandboxError, sandbox_not_found


class FileSandboxStateStore:
    """Atomic, local lifecycle records for a single Sandbox Manager replica."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if self.root == Path(self.root.anchor):
            raise ValueError("sandbox state root must be a dedicated directory")
        self.records_root = self.root / "records"
        self.temporary_root = self.root / "tmp"
        self.root.mkdir(parents=True, exist_ok=True)
        self.records_root.mkdir(parents=True, exist_ok=True)
        self.temporary_root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        os.chmod(self.records_root, 0o700)
        os.chmod(self.temporary_root, 0o700)
        self._lock = threading.RLock()

    def save(self, record: SandboxRecord) -> None:
        payload = record.model_dump_json(indent=2).encode("utf-8")
        destination = self._record_path(record.id)
        with self._lock:
            file_descriptor, temporary_name = tempfile.mkstemp(
                prefix=f"{record.id}-",
                suffix=".json",
                dir=self.temporary_root,
            )
            temporary_path = Path(temporary_name)
            try:
                os.fchmod(file_descriptor, 0o600)
                with os.fdopen(file_descriptor, "wb") as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary_path, destination)
                self._fsync_directory(self.records_root)
            except Exception:
                temporary_path.unlink(missing_ok=True)
                raise

    def get(self, sandbox_id: UUID) -> SandboxRecord:
        path = self._record_path(sandbox_id)
        with self._lock:
            try:
                if path.is_symlink() or (path.exists() and not path.is_file()):
                    raise SandboxError(
                        "SANDBOX_STATE_CORRUPT",
                        "Sandbox lifecycle state is corrupt",
                        http_status=500,
                    )
                payload = path.read_bytes()
            except FileNotFoundError as exc:
                raise sandbox_not_found(sandbox_id) from exc
        try:
            return SandboxRecord.model_validate_json(payload)
        except ValidationError as exc:
            raise SandboxError(
                "SANDBOX_STATE_CORRUPT",
                "Sandbox lifecycle state is corrupt",
                http_status=500,
            ) from exc

    def list(self) -> list[SandboxRecord]:
        with self._lock:
            paths = sorted(self.records_root.glob("*.json"))
        records: list[SandboxRecord] = []
        for path in paths:
            try:
                if path.is_symlink() or not path.is_file():
                    raise ValueError("invalid Sandbox state record")
                UUID(path.stem)
                records.append(SandboxRecord.model_validate_json(path.read_bytes()))
            except (OSError, ValueError, ValidationError) as exc:
                raise SandboxError(
                    "SANDBOX_STATE_CORRUPT",
                    "Sandbox lifecycle state is corrupt",
                    http_status=500,
                ) from exc
        return records

    def temporary_path(self, name: str) -> Path:
        if (
            not name
            or name in {".", ".."}
            or "/" in name
            or "\\" in name
            or any(ord(character) < 32 or ord(character) == 127 for character in name)
        ):
            raise ValueError("invalid temporary state filename")
        return self.temporary_root / name

    def _record_path(self, sandbox_id: UUID) -> Path:
        return self.records_root / f"{sandbox_id}.json"

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
