"""Tests for the small terminal renderer."""

from __future__ import annotations

import io
from typing import TextIO, cast

import pytest

from netscan.console import Console


class TtyStream(io.StringIO):
    def isatty(self) -> bool:
        return True


def test_style_wraps_text_when_colour_is_enabled() -> None:
    console = Console(stream=io.StringIO(), color=True)
    assert console.style("hello", "bold") == "\033[1mhello\033[0m"


def test_style_ignores_unknown_styles() -> None:
    console = Console(stream=io.StringIO(), color=True)
    assert console.style("hello", "not-a-style") == "hello"


def test_style_is_a_noop_without_colour() -> None:
    console = Console(stream=io.StringIO(), color=False)
    assert console.style("hello", "green") == "hello"


def test_info_is_suppressed_in_quiet_mode() -> None:
    stream = io.StringIO()
    console = Console(stream=stream, color=False, quiet=True)
    console.info("hidden")
    console.write("shown")
    assert stream.getvalue() == "shown\n"


def test_table_aligns_columns() -> None:
    stream = io.StringIO()
    Console(stream=stream, color=False).table(
        ["A", "BB"],
        [["1", "2"]],
        aligns=["l", "r"],
    )
    assert stream.getvalue().splitlines() == [
        "A  BB",
        "-  --",
        "1   2",
    ]


def test_table_requires_headers() -> None:
    with pytest.raises(ValueError, match="at least one column"):
        Console(stream=io.StringIO(), color=False).table([], [])


def test_table_rejects_short_rows() -> None:
    with pytest.raises(ValueError, match="match the header width"):
        Console(stream=io.StringIO(), color=False).table(["A", "B"], [["1"]])


def test_paragraph_wraps_with_a_hanging_indent() -> None:
    stream = io.StringIO()
    Console(stream=stream, color=False).paragraph("Label", "one two three four five", width=24)
    lines = stream.getvalue().splitlines()
    assert lines[0].startswith("Label")
    assert all(line.startswith(" " * 12) for line in lines[1:])


def test_colour_is_detected_from_a_tty() -> None:
    assert Console._supports_color(TtyStream()) is True


def test_colour_is_disabled_for_non_tty_streams() -> None:
    assert Console._supports_color(io.StringIO()) is False


def test_no_color_environment_variable_wins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    assert Console._supports_color(TtyStream()) is False


def test_dumb_terminal_disables_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "dumb")
    assert Console._supports_color(TtyStream()) is False


def test_a_stream_without_isatty_is_not_colourful() -> None:
    class Plain:
        pass

    assert Console._supports_color(cast(TextIO, Plain())) is False
