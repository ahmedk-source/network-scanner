"""Tests for host discovery, including the optional Scapy path."""

from __future__ import annotations

import errno
import subprocess
import sys
from types import SimpleNamespace
from typing import Any

import pytest

from netscan import discovery
from netscan.discovery import DiscoveryResult, Method, discover
from netscan.errors import DiscoveryError

LINUX_NEIGHBORS = """\
192.168.1.1 dev wlp2s0 lladdr aa:bb:cc:dd:ee:01 REACHABLE
192.168.1.2 dev wlp2s0 lladdr aa:bb:cc:dd:ee:02 STALE
192.168.1.3 dev wlp2s0  FAILED
192.168.1.255 dev wlp2s0 lladdr ff:ff:ff:ff:ff:ff REACHABLE
"""

WINDOWS_ARP = """\
Interface: 192.168.1.5 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           aa-bb-cc-dd-ee-01     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
  224.0.0.22            01-00-5e-00-00-16     static
  192.168.1.9           00-00-00-00-00-00     invalid
"""

MACOS_ARP = """\
? (192.168.1.1) at aa:bb:cc:dd:ee:01 on en0 ifscope [ethernet]
? (192.168.1.2) at aa:bb:cc:dd:ee:02 on en0 ifscope [ethernet]
"""


# ---------------------------------------------------------------------------
# TCP probes
# ---------------------------------------------------------------------------


def test_probe_accepts_a_successful_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "_connect", lambda target, port, timeout: 0)
    assert discovery._probe_host("192.168.1.1", 0.1) is True


def test_probe_accepts_a_refused_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "_connect",
        lambda target, port, timeout: errno.ECONNREFUSED,
    )
    assert discovery._probe_host("192.168.1.1", 0.1) is True


def test_probe_rejects_timeouts(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "_connect", lambda target, port, timeout: errno.ETIMEDOUT)
    assert discovery._probe_host("192.168.1.1", 0.1) is False


def test_probe_continues_after_a_socket_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def connect(target: str, port: int, timeout: float) -> int:
        calls.append(port)
        if len(calls) == 1:
            raise OSError("network unreachable")
        return 0

    monkeypatch.setattr(discovery, "_connect", connect)
    assert discovery._probe_host("192.168.1.1", 0.1) is True
    assert calls == list(discovery.PROBE_PORTS[:2])


def test_probe_stops_at_the_first_answer(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []

    def connect(target: str, port: int, timeout: float) -> int:
        calls.append(port)
        return 0

    monkeypatch.setattr(discovery, "_connect", connect)
    discovery._probe_host("192.168.1.1", 0.1)
    assert calls == [discovery.PROBE_PORTS[0]]


# ---------------------------------------------------------------------------
# discover() dispatch
# ---------------------------------------------------------------------------


def test_none_method_assumes_every_target_is_up() -> None:
    targets = ("192.168.1.1", "192.168.1.2")
    result = discover(targets, method=Method.NONE)
    assert result.hosts == targets
    assert result.macs == {}
    assert result.method == "none"


def test_empty_targets_return_an_empty_result() -> None:
    result = discover((), method=Method.TCP)
    assert result.hosts == ()


def test_cache_method_only_returns_known_neighbours(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "neighbor_cache",
        lambda: {"192.168.1.1": "aa:bb:cc:dd:ee:01"},
    )
    result = discover(("192.168.1.1", "192.168.1.2"), method=Method.CACHE)
    assert result.hosts == ("192.168.1.1",)
    assert result.macs == {"192.168.1.1": "aa:bb:cc:dd:ee:01"}
    assert result.method == "cache"


def test_tcp_method_merges_neighbour_macs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        discovery,
        "_probe_host",
        lambda target, timeout: target.endswith(".1"),
    )
    monkeypatch.setattr(
        discovery,
        "neighbor_cache",
        lambda: {
            "192.168.1.1": "aa:bb:cc:dd:ee:01",
            "192.168.1.2": "aa:bb:cc:dd:ee:02",
        },
    )
    result = discover(
        ("192.168.1.1", "192.168.1.2", "192.168.1.3"),
        method=Method.TCP,
        workers=2,
    )
    assert result.hosts == ("192.168.1.1",)
    assert result.macs == {"192.168.1.1": "aa:bb:cc:dd:ee:01"}
    assert result.method == "tcp"
    assert result.warnings == ()


def test_auto_without_scapy_uses_tcp(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "_scapy_available", lambda: False)
    expected = DiscoveryResult(hosts=("192.168.1.1",), method="tcp")
    calls: list[str] = []

    def fake_tcp(targets, timeout, workers, warnings):
        calls.append("tcp")
        return expected

    monkeypatch.setattr(discovery, "_tcp_discover", fake_tcp)
    result = discover(("192.168.1.1",), method=Method.AUTO)
    assert result is expected
    assert calls == ["tcp"]


def test_auto_falls_back_to_tcp_when_arp_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "_scapy_available", lambda: True)

    def failing_arp(targets: tuple[str, ...], timeout: float) -> DiscoveryResult:
        raise DiscoveryError("operation not permitted")

    expected = DiscoveryResult(hosts=("192.168.1.1",), method="tcp")
    monkeypatch.setattr(discovery, "_arp_discover", failing_arp)
    monkeypatch.setattr(
        discovery,
        "_tcp_discover",
        lambda targets, timeout, workers, warnings: DiscoveryResult(
            hosts=expected.hosts,
            method=expected.method,
            warnings=tuple(warnings),
        ),
    )
    result = discover(("192.168.1.1",), method=Method.AUTO)
    assert result.hosts == ("192.168.1.1",)
    assert any("falling back" in warning for warning in result.warnings)


def test_explicit_arp_without_scapy_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(discovery, "_scapy_available", lambda: False)
    monkeypatch.setattr(
        discovery,
        "_import_scapy",
        lambda: (_ for _ in ()).throw(DiscoveryError("Scapy is not installed")),
    )
    with pytest.raises(DiscoveryError, match="Scapy"):
        discover(("192.168.1.1",), method=Method.ARP)


# ---------------------------------------------------------------------------
# ARP path with a stand-in for Scapy
# ---------------------------------------------------------------------------


class FakeEther:
    def __init__(self, dst: str) -> None:
        self.dst = dst

    def __truediv__(self, other: FakeARP) -> FakeEther:
        self.arp = other
        return self


class FakeARP:
    def __init__(self, pdst: str) -> None:
        self.pdst = pdst


class FakeScapy:
    Ether = FakeEther
    ARP = FakeARP

    def __init__(self) -> None:
        self.packets: list[FakeEther] = []

    def srp(
        self,
        packets: list[FakeEther],
        timeout: float,
        verbose: bool,
    ) -> tuple[list[tuple[Any, Any]], list[Any]]:
        self.packets = packets
        answered: list[tuple[Any, Any]] = [
            (None, SimpleNamespace(psrc="192.168.1.2", hwsrc="AA-BB-CC-DD-EE-02")),
            (None, SimpleNamespace(psrc="192.168.1.3", hwsrc="01-00-5E-00-00-16")),
            (None, SimpleNamespace(psrc="192.168.1.99", hwsrc="AA-BB-CC-DD-EE-99")),
            (None, SimpleNamespace(psrc="192.168.1.4", hwsrc="AA-BB-CC-DD-EE-04")),
        ]
        return answered, []


def test_arp_discovery_filters_replies(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeScapy()
    monkeypatch.setattr(discovery, "_import_scapy", lambda: fake)
    result = discovery._arp_discover(
        ("192.168.1.2", "192.168.1.4"),
        1.0,
    )
    assert result.hosts == ("192.168.1.2", "192.168.1.4")
    assert result.macs == {
        "192.168.1.2": "aa:bb:cc:dd:ee:02",
        "192.168.1.4": "aa:bb:cc:dd:ee:04",
    }
    assert result.method == "arp"
    assert len(fake.packets) == 1
    assert fake.packets[0].dst == "ff:ff:ff:ff:ff:ff"
    assert fake.packets[0].arp.pdst == "192.168.1.0/24"


def test_arp_discovery_wraps_scapy_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    class BrokenScapy(FakeScapy):
        def srp(
            self,
            packets: list[FakeEther],
            timeout: float,
            verbose: bool,
        ) -> tuple[list[tuple[Any, Any]], list[Any]]:
            raise OSError("Npcap not installed")

    monkeypatch.setattr(discovery, "_import_scapy", lambda: BrokenScapy())
    with pytest.raises(DiscoveryError, match="Npcap"):
        discovery._arp_discover(("192.168.1.2",), 1.0)


# ---------------------------------------------------------------------------
# Neighbour-table parsing
# ---------------------------------------------------------------------------


def test_parse_windows_arp_output() -> None:
    assert discovery.parse_neighbor_output(WINDOWS_ARP) == {"192.168.1.1": "aa:bb:cc:dd:ee:01"}


def test_parse_linux_neighbour_output() -> None:
    assert discovery.parse_neighbor_output(LINUX_NEIGHBORS) == {
        "192.168.1.1": "aa:bb:cc:dd:ee:01",
        "192.168.1.2": "aa:bb:cc:dd:ee:02",
    }


def test_parse_macos_arp_output() -> None:
    assert discovery.parse_neighbor_output(MACOS_ARP) == {
        "192.168.1.1": "aa:bb:cc:dd:ee:01",
        "192.168.1.2": "aa:bb:cc:dd:ee:02",
    }


def test_parse_neighbour_output_ignores_garbage() -> None:
    assert discovery.parse_neighbor_output("nothing to see here") == {}


def test_neighbor_cache_uses_the_first_working_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    commands: list[tuple[str, ...]] = []

    def fake_run(command: tuple[str, ...]) -> str | None:
        commands.append(command)
        return LINUX_NEIGHBORS if command[0] == "ip" else None

    monkeypatch.setattr(discovery, "_run", fake_run)
    assert discovery.neighbor_cache() == {
        "192.168.1.1": "aa:bb:cc:dd:ee:01",
        "192.168.1.2": "aa:bb:cc:dd:ee:02",
    }
    assert commands == [("ip", "neigh")]


def test_neighbor_cache_returns_empty_when_every_command_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(discovery, "_run", lambda command: None)
    assert discovery.neighbor_cache() == {}


def test_run_returns_decoded_stdout(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = subprocess.CompletedProcess(
        args=["arp", "-a"],
        returncode=0,
        stdout=b"192.168.1.1 aa-bb-cc-dd-ee-01",
    )
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: completed)
    assert discovery._run(("arp", "-a")) == "192.168.1.1 aa-bb-cc-dd-ee-01"


def test_run_returns_none_for_a_failing_command(monkeypatch: pytest.MonkeyPatch) -> None:
    completed = subprocess.CompletedProcess(args=["arp", "-a"], returncode=1, stdout=b"")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: completed)
    assert discovery._run(("arp", "-a")) is None


def test_run_returns_none_when_the_tool_is_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(*args: object, **kwargs: object) -> None:
        raise FileNotFoundError("arp")

    monkeypatch.setattr(subprocess, "run", missing)
    assert discovery._run(("arp", "-a")) is None


def test_scapy_availability_detects_the_environment() -> None:
    available = discovery._scapy_available()
    assert isinstance(available, bool)


def test_platform_sys_module_is_used_for_the_neighbour_table() -> None:
    assert discovery.sys is sys
