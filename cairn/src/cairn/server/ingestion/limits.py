from dataclasses import dataclass

from cairn.server.config import ServerSettings


@dataclass(frozen=True, slots=True)
class IngestionLimits:
    upload_max_bytes: int
    max_files: int
    max_total_bytes: int
    max_file_bytes: int
    max_compression_ratio: int
    max_path_length: int
    max_path_depth: int

    @classmethod
    def from_settings(cls, settings: ServerSettings) -> "IngestionLimits":
        return cls(
            upload_max_bytes=settings.upload_max_bytes,
            max_files=settings.snapshot_max_files,
            max_total_bytes=settings.snapshot_max_total_bytes,
            max_file_bytes=settings.snapshot_max_file_bytes,
            max_compression_ratio=settings.snapshot_max_compression_ratio,
            max_path_length=settings.snapshot_max_path_length,
            max_path_depth=settings.snapshot_max_path_depth,
        )
