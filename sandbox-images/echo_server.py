#!/usr/bin/env python3
"""Restricted image entrypoint for the out-of-band echo service."""

from __future__ import annotations

from cairn.dynamic.echo import main


if __name__ == "__main__":
    raise SystemExit(main())
