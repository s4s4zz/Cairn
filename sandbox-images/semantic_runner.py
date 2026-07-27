#!/usr/bin/env python3
"""Restricted image entrypoint for the Semantic Reviewer."""

from __future__ import annotations

from cairn.semantic.runner import main


if __name__ == "__main__":
    raise SystemExit(main())
