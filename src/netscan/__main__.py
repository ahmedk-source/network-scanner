"""Support ``python -m netscan``."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":  # pragma: no cover - exercised through the console script
    raise SystemExit(main())
