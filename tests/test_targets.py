"""Tests for target parsing and expansion."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from netscan import targets as target_module
from netscan.errors import TargetError


def test_single_address() -> None:
    assert target_module.expand_targets(["192.168.1.10"]) == ("192.168.1.10",)


def test_cidr_excludes_network_and_broadcast() -> None:
    assert target_module.expand_targets(["192.168.1.0/30"]) == (
        "192.168.1.1",
        "192.168.1.2",
    )


def test_cidr_accepts_a_host_address_with_a_mask() -> None:
    assert target_module.expand_targets(["192.168.1.77/30"]) == (
        "192.168.1.77",
        "192.168.1.78",
    )


def test_single_host_cidr() -> None:
    assert target_module.expand_targets(["10.0.0.5/32"]) == ("10.0.0.5",)


def test_short_range() -> None:
    assert target_module.expand_targets(["192.168.1.10-13"]) == (
        "192.168.1.10",
        "192.168.1.11",
        "192.168.1.12",
        "192.168.1.13",
    )


def test_long_range() -> None:
    assert target_module.expand_targets(["192.168.1.254-192.168.2.1"]) == (
        "192.168.1.254",
        "192.168.1.255",
        "192.168.2.0",
        "192.168.2.1",
    )


def test_comma_separated_and_repeated_specs_are_deduplicated() -> None:
    result = target_module.expand_targets(["192.168.1.2,192.168.1.1", "192.168.1.1"])
    assert result == ("192.168.1.1", "192.168.1.2")


def test_expansion_is_sorted_numerically() -> None:
    result = target_module.expand_targets(["10.0.0.10", "10.0.0.2", "10.0.0.1"])
    assert result == ("10.0.0.1", "10.0.0.2", "10.0.0.10")


def test_auto_uses_the_guessed_local_network(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        target_module,
        "guess_local_network",
        lambda: ipaddress.ip_network("192.168.5.0/30"),
    )
    assert target_module.expand_targets(["auto"]) == ("192.168.5.1", "192.168.5.2")


def test_hostname_is_resolved(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_getaddrinfo(host: str, *args: object, **kwargs: object) -> list[tuple[object, ...]]:
        assert host == "router.lan"
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.1", 0)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.2", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert target_module.expand_targets(["router.lan"]) == (
        "192.168.1.1",
        "192.168.1.2",
    )


def test_unresolvable_hostname_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        raise socket.gaierror(-2, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", fail)
    with pytest.raises(TargetError, match="could not resolve"):
        target_module.expand_targets(["no-such-host.invalid"])


def test_public_address_is_refused_by_default() -> None:
    with pytest.raises(TargetError, match="not a private address"):
        target_module.expand_targets(["8.8.8.8"])


def test_public_address_is_allowed_with_the_flag() -> None:
    assert target_module.expand_targets(["8.8.8.8"], allow_public=True) == ("8.8.8.8",)


def test_public_cidr_is_refused_even_if_it_starts_privately() -> None:
    with pytest.raises(TargetError, match="not a private address"):
        target_module.expand_targets(["192.168.0.0/15"], max_hosts=200_000)


def test_max_hosts_is_enforced() -> None:
    with pytest.raises(TargetError, match="more than 3 hosts"):
        target_module.expand_targets(["192.168.1.0/29"], max_hosts=3)


def test_max_hosts_accepts_a_list_of_exactly_the_limit() -> None:
    assert len(target_module.expand_targets(["192.168.1.0/30"], max_hosts=2)) == 2


def test_max_hosts_must_be_positive() -> None:
    with pytest.raises(ValueError, match="max_hosts"):
        target_module.expand_targets(["192.168.1.0/30"], max_hosts=0)


@pytest.mark.parametrize(
    ("spec", "message"),
    [
        ("192.168.1.256", "invalid target"),
        ("192.168.1.0/33", "invalid target"),
        ("192.168.1.10-5", "range ends before"),
        ("192.168.1.10-256", "octet must be between"),
        ("::1/128", "IPv6 is not supported"),
        ("0.0.0.0", "not a unicast address"),
        ("224.0.0.1", "not a unicast address"),
    ],
)
def test_invalid_targets_are_rejected(spec: str, message: str) -> None:
    with pytest.raises(TargetError, match=message):
        target_module.expand_targets([spec])


def test_empty_target_list_is_rejected() -> None:
    with pytest.raises(TargetError, match="no targets"):
        target_module.expand_targets([])


def test_blank_target_list_is_rejected() -> None:
    with pytest.raises(TargetError, match="no targets"):
        target_module.expand_targets(["  ", ","])
