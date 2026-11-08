"""Tests for IPv4 parsing, local-range checks and MAC normalisation."""

from __future__ import annotations

import ipaddress

import pytest

from netscan import net
from netscan.errors import TargetError


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("192.168.1.1", "192.168.1.1"),
        (" 10.0.0.254 ", "10.0.0.254"),
        ("0.0.0.0", "0.0.0.0"),
        ("255.255.255.255", "255.255.255.255"),
    ],
)
def test_parse_ipv4_accepts_dotted_quads(value: str, expected: str) -> None:
    assert str(net.parse_ipv4(value)) == expected


@pytest.mark.parametrize(
    "value",
    ["", "256.0.0.1", "1.2.3", "1.2.3.4.5", "::1", "fe80::1", "localhost"],
)
def test_parse_ipv4_rejects_invalid_input(value: str) -> None:
    with pytest.raises(ValueError):
        net.parse_ipv4(value)


@pytest.mark.parametrize(
    "value",
    [
        "10.1.2.3",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "100.64.0.1",
        "127.0.0.1",
        "169.254.1.1",
    ],
)
def test_is_local_true_for_private_ranges(value: str) -> None:
    assert net.is_local(ipaddress.ip_address(value)) is True


@pytest.mark.parametrize(
    "value",
    ["8.8.8.8", "1.1.1.1", "172.32.0.1", "192.169.0.1", "11.0.0.1"],
)
def test_is_local_false_for_public_addresses(value: str) -> None:
    assert net.is_local(ipaddress.ip_address(value)) is False


def test_is_local_supports_ipv6() -> None:
    assert net.is_local(ipaddress.ip_address("::1")) is True
    assert net.is_local(ipaddress.ip_address("fd00::1")) is True
    assert net.is_local(ipaddress.ip_address("2001:4860:4860::8888")) is False


def test_address_sort_key_is_numeric() -> None:
    values = ["192.168.1.10", "192.168.1.2", "10.0.0.9", "10.0.0.10"]
    assert sorted(values, key=net.address_sort_key) == [
        "10.0.0.9",
        "10.0.0.10",
        "192.168.1.2",
        "192.168.1.10",
    ]


def test_sort_addresses_returns_a_new_sorted_list() -> None:
    assert net.sort_addresses(["10.0.0.2", "10.0.0.1"]) == ["10.0.0.1", "10.0.0.2"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("  00-1A-2B-3C-4D-5E  ", "00:1a:2b:3c:4d:5e"),
    ],
)
def test_normalise_mac_accepts_common_formats(raw: str, expected: str) -> None:
    assert net.normalise_mac(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "aa:bb:cc:dd:ee",
        "aa:bb:cc:dd:ee:ff:00",
        "zz:bb:cc:dd:ee:ff",
        "01:00:5e:00:00:16",  # multicast
        "ff:ff:ff:ff:ff:ff",  # broadcast
        "00:00:00:00:00:00",  # incomplete ARP entry
    ],
)
def test_normalise_mac_rejects_unusable_values(raw: str) -> None:
    assert net.normalise_mac(raw) is None


def test_guess_local_network_uses_first_usable_address(monkeypatch: pytest.MonkeyPatch) -> None:
    addresses = [
        ipaddress.IPv4Address("127.0.0.1"),
        ipaddress.IPv4Address("169.254.10.20"),
        ipaddress.IPv4Address("192.168.7.42"),
    ]
    monkeypatch.setattr(net, "local_ipv4_addresses", lambda: addresses)
    assert str(net.guess_local_network()) == "192.168.7.0/24"


def test_guess_local_network_honours_prefix(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        net,
        "local_ipv4_addresses",
        lambda: [ipaddress.IPv4Address("10.20.30.40")],
    )
    assert str(net.guess_local_network(prefix=16)) == "10.20.0.0/16"


def test_guess_local_network_fails_without_usable_address(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        net,
        "local_ipv4_addresses",
        lambda: [ipaddress.IPv4Address("127.0.0.1")],
    )
    with pytest.raises(TargetError, match="could not determine"):
        net.guess_local_network()


def test_local_ipv4_addresses_returns_addresses() -> None:
    addresses = net.local_ipv4_addresses()
    assert all(isinstance(address, ipaddress.IPv4Address) for address in addresses)
    assert len(addresses) == len(set(addresses))
