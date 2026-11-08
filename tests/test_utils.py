"""Tests for the bounded task helper."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from netscan.utils import windowed_map


def test_windowed_map_preserves_submission_order() -> None:
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(windowed_map(pool, lambda value: value * 2, range(20), window=3))
    assert results == [value * 2 for value in range(20)]


def test_windowed_map_handles_no_items() -> None:
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert list(windowed_map(pool, str, [], window=4)) == []


def test_windowed_map_propagates_task_errors() -> None:
    def fail(value: int) -> int:
        raise RuntimeError(f"boom {value}")

    with ThreadPoolExecutor(max_workers=2) as pool:
        generator = windowed_map(pool, fail, [1], window=1)
        with pytest.raises(RuntimeError, match="boom 1"):
            list(generator)


def test_windowed_map_rejects_a_zero_window() -> None:
    with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(ValueError, match="window"):
        list(windowed_map(pool, str, [1], window=0))
