#!/usr/bin/env python3
"""Restricted image entrypoint for fixed deterministic-analysis profiles."""

from __future__ import annotations

from cairn.analysis.runner import main


if __name__ == "__main__":
    raise SystemExit(main())
