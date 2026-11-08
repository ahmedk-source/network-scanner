"""IPv4 helpers: parsing, ordering, local interfaces and MAC normalisation.

netscan deliberately supports IPv4 only.  The vast majority of home and office
LANs are still IPv4, and keeping one address family makes the discovery code,
the output and the tests considerably easier to reason about.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterable

from .errors import TargetError

#: Ranges that are safe to scan without asking for explicit permission.  This
#: is a superset of :mod:`ipaddress`'s ``is_private``: it also covers loopback,
#: link-local, CGNAT (RFC 6598) and the IPv6 equivalents.
LOCAL_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

_MAC_PART_RE = re.compile(r"^[0-9a-f]{2}$")


def parse_ipv4(value: str) -> ipaddress.IPv4Address:
    """Parse a dotted-quad IPv4 address or raise :class:`ValueError`."""
    text = value.strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ValueError(f"not a valid IP address: {value!r}") from None
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError(f"IPv6 is not supported: {value!r}")
    return address


def is_local(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return ``True`` for private, loopback, link-local and CGNAT addresses."""
    return any(
        address.version == network.version and address in network for network in LOCAL_NETWORKS
    )


def address_sort_key(value: str) -> tuple[int, int, int, int]:
    """Return a numeric sort key so ``192.168.1.9`` sorts before ``...10``."""
    first, second, third, fourth = (int(part) for part in value.split("."))
    return (first, second, third, fourth)


def local_ipv4_addresses() -> list[ipaddress.IPv4Address]:
    """Best-effort list of this machine's IPv4 addresses.

    Two independent sources are combined: the address the hostname resolves to
    and the source address the routing table would pick for outbound traffic.
    Both are optional, so an empty list is a valid result on unusual systems.
    """
    found: dict[str, ipaddress.IPv4Address] = {}

    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        infos = []
    for info in infos:
        raw = str(info[4][0])
        try:
            address = parse_ipv4(raw)
        except ValueError:
            continue
        found[str(address)] = address

    # A UDP connect() performs no network traffic, but makes the kernel select
    # the source address it would use for the default route.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            probe.connect(("192.0.2.1", 9))
            raw = str(probe.getsockname()[0])
    except OSError:
        raw = ""
    if raw:
        try:
            address = parse_ipv4(raw)
        except ValueError:
            pass
        else:
            found[str(address)] = address

    return sorted(found.values(), key=lambda item: int(item))


def guess_local_network(prefix: int = 24) -> ipaddress.IPv4Network:
    """Guess the local subnet from the machine's own address.

    The prefix defaults to ``/24`` because that is what consumer routers use.
    The guess is never silently applied to a scan without being displayed.
    """
    for address in local_ipv4_addresses():
        if address.is_loopback or address.is_link_local or address.is_unspecified:
            continue
        return ipaddress.IPv4Network((str(address), prefix), strict=False)
    raise TargetError("could not determine the local network; pass a target such as 192.168.1.0/24")


def normalise_mac(value: str) -> str | None:
    """Return a lowercase colon-separated MAC address, or ``None`` if unusable.

    Unicast addresses only: the all-zero placeholder used by incomplete ARP
    entries, broadcast addresses and multicast addresses are rejected.
    """
    cleaned = value.strip().lower()
    if re.fullmatch(r"[0-9a-f]{4}(?:\.[0-9a-f]{4}){2}", cleaned):
        cleaned = cleaned.replace(".", "")
        parts = [cleaned[index : index + 2] for index in range(0, 12, 2)]
    else:
        parts = cleaned.replace("-", ":").split(":")
    if len(parts) != 6 or not all(_MAC_PART_RE.match(part) for part in parts):
        return None
    first_octet = int(parts[0], 16)
    if first_octet & 1:  # multicast and broadcast bit
        return None
    if all(part == "00" for part in parts):
        return None
    return ":".join(parts)


def sort_addresses(addresses: Iterable[str]) -> list[str]:
    """Sort IPv4 address strings numerically."""
    return sorted(addresses, key=address_sort_key)
