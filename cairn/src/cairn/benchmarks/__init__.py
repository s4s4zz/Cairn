"""Deterministic, data-minimising closed-platform benchmarks."""

from cairn.benchmarks.contracts import (
    AuditRunExport,
    BenchmarkResult,
    ClosedPlatformGoldManifest,
)
from cairn.benchmarks.runner import evaluate_benchmark

__all__ = [
    "AuditRunExport",
    "BenchmarkResult",
    "ClosedPlatformGoldManifest",
    "evaluate_benchmark",
]
