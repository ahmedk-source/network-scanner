"""Host discovery: find out which addresses on the target list are alive.

Four strategies are supported:

``tcp``
    A TCP connect to a handful of common ports.  An accepted connection *or* a
    refused connection proves the host exists, because both require an answer
    from the network stack.  No privileges required; the default choice.
``arp``
    A broadcast ARP request per ``/24`` via Scapy.  The most reliable method on
    a local segment, but it needs Scapy and raw-socket privileges.
``cache``
    Only the operating system's neighbour table.  Instant, but it can only see
    hosts the machine has talked to recently.
``none``
    Skip discovery and treat every target as up.  Useful when ICMP/TCP probes
    are filtered and the ports still answer.
"""

from __future__ import annotations

import errno
import importlib.util
import ipaddress
import re
import socket
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .errors import DiscoveryError
from .net import address_sort_key, normalise_mac
from .utils import windowed_map

#: Ports used to decide whether a host answers.  They cover the services that
#: are almost always open (web, SSH) and the ones that are almost always
#: filtered, which makes the probe less dependent on one firewall policy.
PROBE_PORTS: tuple[int, ...] = (80, 443, 22, 445, 3389)

#: ``connect_ex`` reports a refusal when the host is up but the port is closed.
#: Windows uses its own WSA code; both are accepted.
_REFUSED_CODES = frozenset(
    {
        errno.ECONNREFUSED,
        getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED),
    }
)

_NEIGHBOR_RE = re.compile(
    r"(?<![\d.])(?P<ip>(?:\d{1,3}\.){3}\d{1,3})(?![\d.])"
    r"[^\n]*?"
    r"(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})"
)


class Method(StrEnum):
    """Host-discovery strategy selected on the command line."""

    AUTO = "auto"
    TCP = "tcp"
    ARP = "arp"
    CACHE = "cache"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """Responsive hosts, their MAC addresses and how they were found."""

    hosts: tuple[str, ...]
    macs: dict[str, str] = field(default_factory=dict)
    method: str = "none"
    warnings: tuple[str, ...] = ()


def discover(
    targets: tuple[str, ...],
    *,
    method: Method = Method.AUTO,
    timeout: float = 0.5,
    workers: int = 100,
) -> DiscoveryResult:
    """Return the subset of *targets* that answers, plus their MAC addresses."""
    if not targets:
        return DiscoveryResult(hosts=(), method=method.value)

    if method is Method.NONE:
        return DiscoveryResult(hosts=tuple(targets), method=Method.NONE.value)

    if method is Method.CACHE:
        cache = neighbor_cache()
        hosts = tuple(target for target in targets if target in cache)
        return DiscoveryResult(
            hosts=hosts,
            macs={host: cache[host] for host in hosts},
            method=Method.CACHE.value,
        )

    if method is Method.ARP:
        return _arp_discover(targets, timeout)

    warnings: list[str] = []
    if method is Method.AUTO:
        if not _scapy_available():
            method = Method.TCP
        else:
            try:
                return _arp_discover(targets, timeout)
            except (DiscoveryError, OSError) as error:
                warnings.append(f"ARP discovery failed ({error}); falling back to TCP probes")
                method = Method.TCP

    if method is Method.TCP:
        return _tcp_discover(targets, timeout, workers, warnings)

    raise DiscoveryError(f"unsupported discovery method: {method.value}")


# ---------------------------------------------------------------------------
# TCP probes
# ---------------------------------------------------------------------------


def _tcp_discover(
    targets: tuple[str, ...],
    timeout: float,
    workers: int,
    warnings: list[str],
) -> DiscoveryResult:
    probe_timeout = min(timeout, 0.5)
    with ThreadPoolExecutor(
        max_workers=max(1, min(workers, len(targets))),
        thread_name_prefix="netscan-discover",
    ) as pool:
        answers = list(
            windowed_map(
                pool,
                lambda target: _probe_host(target, probe_timeout),
                targets,
                window=workers * 2,
            )
        )

    hosts = tuple(target for target, answered in zip(targets, answers, strict=True) if answered)
    cache = neighbor_cache()
    macs = {host: cache[host] for host in hosts if host in cache}
    return DiscoveryResult(
        hosts=hosts,
        macs=macs,
        method=Method.TCP.value,
        warnings=tuple(warnings),
    )


def _probe_host(target: str, timeout: float) -> bool:
    """Return ``True`` if a TCP connect to any probe port gets an answer."""
    for port in PROBE_PORTS:
        try:
            code = _connect(target, port, timeout)
        except OSError:
            continue
        if code == 0 or code in _REFUSED_CODES:
            return True
    return False


def _connect(target: str, port: int, timeout: float) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((target, port))


# ---------------------------------------------------------------------------
# ARP probes (optional Scapy dependency)
# ---------------------------------------------------------------------------


def _scapy_available() -> bool:
    return importlib.util.find_spec("scapy") is not None


def _import_scapy() -> Any:
    try:
        from scapy import all as scapy_all
    except ImportError as error:  # pragma: no cover - depends on the environment
        raise DiscoveryError(
            "ARP discovery needs Scapy; install it with: pip install 'network-scanner[arp]'"
        ) from error
    return scapy_all


def _arp_discover(targets: tuple[str, ...], timeout: float) -> DiscoveryResult:
    scapy = _import_scapy()
    target_set = set(targets)

    # One broadcast per /24 keeps the number of packets proportional to the
    # size of the range instead of the number of individual addresses.
    networks = sorted(
        {ipaddress.ip_network(f"{target}/24", strict=False) for target in targets},
        key=lambda network: int(network.network_address),
    )
    packets = [
        scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=str(network)) for network in networks
    ]

    try:
        answered, _unanswered = scapy.srp(packets, timeout=timeout, verbose=False)
    except Exception as error:  # scapy raises platform-specific exception types
        raise DiscoveryError(str(error) or type(error).__name__) from error

    macs: dict[str, str] = {}
    for _sent, received in answered:
        try:
            address = str(received.psrc)
            raw_mac = str(received.hwsrc)
        except AttributeError:  # pragma: no cover - defensive against Scapy changes
            continue
        if address not in target_set:
            continue
        mac = normalise_mac(raw_mac)
        if mac is not None:
            macs[address] = mac

    hosts = tuple(sorted(macs, key=address_sort_key))
    return DiscoveryResult(hosts=hosts, macs=macs, method=Method.ARP.value)


# ---------------------------------------------------------------------------
# Operating-system neighbour cache
# ---------------------------------------------------------------------------


def neighbor_cache() -> dict[str, str]:
    """Parse the OS neighbour table into ``{ip: mac}``.

    Fixed, shell-free commands are used, so there is no injection surface.  A
    missing or failing tool simply produces an empty mapping.
    """
    if sys.platform == "win32":
        commands = (("arp", "-a"),)
    elif sys.platform == "darwin":
        commands = (("arp", "-an"),)
    else:
        commands = (("ip", "neigh"), ("arp", "-an"))

    for command in commands:
        output = _run(command)
        if output is None:
            continue
        entries = parse_neighbor_output(output)
        if entries:
            return entries
    return {}


def _run(command: tuple[str, ...]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.decode("utf-8", errors="replace")


def parse_neighbor_output(output: str) -> dict[str, str]:
    """Extract ``{ip: mac}`` pairs from ``arp``/``ip neigh`` output."""
    entries: dict[str, str] = {}
    for match in _NEIGHBOR_RE.finditer(output):
        mac = normalise_mac(match.group("mac"))
        if mac is None:
            continue
        try:
            address = str(ipaddress.IPv4Address(match.group("ip")))
        except ValueError:
            continue
        entries[address] = mac
    return entries
