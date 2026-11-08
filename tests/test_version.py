"""Keep the version in one place."""

from __future__ import annotations

import tomllib
from importlib.metadata import version
from pathlib import Path

from netscan import __version__


def test_version_matches_installed_metadata() -> None:
    assert version("network-scanner") == __version__


def test_version_matches_pyproject() -> None:
    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    metadata = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert metadata["project"]["version"] == __version__
