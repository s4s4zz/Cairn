#!/usr/bin/env python3
"""Restricted image entrypoint for the Dynamic Verifier."""

from __future__ import annotations

from cairn.dynamic.runner import main


if __name__ == "__main__":
    raise SystemExit(main())
