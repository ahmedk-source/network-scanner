"""Tests for port specifications, presets and service names."""

from __future__ import annotations

import socket

import pytest

from netscan import ports
from netscan.errors import PortSpecError


def test_common_preset_matches_the_service_table() -> None:
    assert tuple(sorted(ports.SERVICES)) == ports.COMMON_PORTS
    assert len(ports.COMMON_PORTS) == len(set(ports.COMMON_PORTS))


def test_common_preset_is_substantial() -> None:
    assert len(ports.COMMON_PORTS) >= 100


def test_presets_are_sorted_and_valid() -> None:
    for name, preset in ports.PRESETS.items():
        assert preset == tuple(sorted(set(preset))), name
        assert all(1 <= port <= ports.MAX_PORT for port in preset), name


@pytest.mark.parametrize(
    ("spec", "expected"),
    [
        ("80", (80,)),
        (" 443 ", (443,)),
        ("22,80,443", (22, 80, 443)),
        ("443,80,22", (22, 80, 443)),
        ("80,80,80", (80,)),
        ("1-5", (1, 2, 3, 4, 5)),
        ("5-5", (5,)),
        ("80,1-3,80", (1, 2, 3, 80)),
        ("1-3,100,99", (1, 2, 3, 99, 100)),
    ],
)
def test_parse_ports_expands_and_sorts(spec: str, expected: tuple[int, ...]) -> None:
    assert ports.parse_ports(spec) == expected


@pytest.mark.parametrize("spec", ["common", "COMMON", " Common "])
def test_parse_ports_accepts_the_common_preset(spec: str) -> None:
    assert ports.parse_ports(spec) == ports.COMMON_PORTS


def test_parse_ports_accepts_the_web_preset() -> None:
    assert ports.parse_ports("web") == ports.WEB_PORTS


def test_parse_ports_all_expands_every_port() -> None:
    result = ports.parse_ports("all")
    assert len(result) == 65535
    assert result[0] == 1
    assert result[-1] == 65535


@pytest.mark.parametrize(
    "spec",
    ["", "   ", "0", "65536", "-1", "1-", "-10", "abc", "1,,2", "1-2-3", "80-70", "0-10"],
)
def test_parse_ports_rejects_invalid_specs(spec: str) -> None:
    with pytest.raises(PortSpecError):
        ports.parse_ports(spec)


def test_parse_ports_error_mentions_the_offending_value() -> None:
    with pytest.raises(PortSpecError, match="70000"):
        ports.parse_ports("70000")


@pytest.mark.parametrize(
    ("port", "service"),
    [
        (22, "ssh"),
        (53, "domain"),
        (80, "http"),
        (443, "https"),
        (445, "microsoft-ds"),
        (3306, "mysql"),
        (3389, "ms-wbt-server"),
        (5432, "postgresql"),
        (6379, "redis"),
        (27017, "mongodb"),
    ],
)
def test_service_name_uses_the_curated_table(port: int, service: str) -> None:
    assert ports.service_name(port) == service


def test_service_name_falls_back_to_the_platform_database(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getservbyport", lambda port, proto: "custom-svc")
    ports.service_name.cache_clear()
    try:
        assert ports.service_name(4242) == "custom-svc"
    finally:
        ports.service_name.cache_clear()


def test_service_name_returns_unknown_when_the_platform_has_no_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(port: int, proto: str) -> str:
        raise OSError("no such service")

    monkeypatch.setattr(socket, "getservbyport", missing)
    ports.service_name.cache_clear()
    try:
        assert ports.service_name(4242) == "unknown"
    finally:
        ports.service_name.cache_clear()


def test_web_preset_is_a_subset_of_common_plus_familiar_web_ports() -> None:
    assert 80 in ports.WEB_PORTS
    assert 443 in ports.WEB_PORTS
    assert all(1 <= port <= ports.MAX_PORT for port in ports.WEB_PORTS)
    assert tuple(sorted(ports.WEB_PORTS)) == ports.WEB_PORTS


def test_socket_module_is_used_for_the_fallback() -> None:
    # A guard against accidentally re-implementing the platform lookup.
    assert socket is ports.socket
