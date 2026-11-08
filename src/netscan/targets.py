"""Target expansion: single addresses, CIDR blocks, ranges and hostnames.

The parser is deliberately strict.  A typo such as ``192.168.1.0/33`` or
``10.0.0.1-500`` fails with a message that explains the problem, instead of
silently scanning a different range than the user intended.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Iterator, Sequence

from .errors import TargetError
from .net import address_sort_key, guess_local_network, is_local, parse_ipv4

_ADDRESS_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_RANGE_RE = re.compile(
    r"^(?P<start>\d{1,3}(?:\.\d{1,3}){3})-(?P<end>\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$"
)

#: Default upper bound on the number of addresses a single invocation may scan.
DEFAULT_MAX_HOSTS = 4096


def expand_targets(
    specs: Sequence[str],
    *,
    max_hosts: int = DEFAULT_MAX_HOSTS,
    allow_public: bool = False,
) -> tuple[str, ...]:
    """Expand *specs* into a sorted, de-duplicated tuple of IPv4 addresses.

    ``specs`` may contain any mix of addresses, CIDR blocks, ``start-end``
    ranges, hostnames and the keyword ``auto`` (the local ``/24``).  Commas
    separate multiple values inside one argument.

    Public addresses are rejected unless *allow_public* is true; scanning
    networks you do not own is a legal and professional problem, not just a
    technical one.
    """
    if max_hosts < 1:
        raise ValueError("max_hosts must be at least 1")

    chunks = [chunk.strip() for spec in specs for chunk in spec.split(",")]
    chunks = [chunk for chunk in chunks if chunk]
    if not chunks:
        raise TargetError("no targets specified")

    addresses: set[ipaddress.IPv4Address] = set()
    for chunk in chunks:
        for address in _expand_one(chunk):
            if address.is_unspecified or address.is_multicast:
                raise TargetError(f"{address} is not a unicast address")
            if not allow_public and not is_local(address):
                raise TargetError(
                    f"{address} is not a private address; "
                    "use --allow-public only for networks you are authorised to scan"
                )
            addresses.add(address)
            if len(addresses) > max_hosts:
                raise TargetError(
                    f"target expands to more than {max_hosts} hosts; "
                    "narrow the range or raise --max-hosts"
                )

    if not addresses:
        raise TargetError("no targets specified")
    return tuple(sorted((str(address) for address in addresses), key=address_sort_key))


def _expand_one(spec: str) -> Iterator[ipaddress.IPv4Address]:
    lowered = spec.lower()
    if lowered == "auto":
        network = guess_local_network()
        yield from network.hosts()
        return

    if "/" in spec:
        yield from _expand_network(spec)
        return

    match = _RANGE_RE.match(spec)
    if match is not None:
        yield from _expand_range(match.group("start"), match.group("end"), spec)
        return

    if _ADDRESS_RE.match(spec):
        try:
            yield parse_ipv4(spec)
        except ValueError as error:
            raise TargetError(f"invalid target {spec!r}: {error}") from None
        return

    yield from _resolve(spec)


def _expand_network(spec: str) -> Iterator[ipaddress.IPv4Address]:
    try:
        network = ipaddress.ip_network(spec, strict=False)
    except ValueError as error:
        raise TargetError(f"invalid target {spec!r}: {error}") from None
    if not isinstance(network, ipaddress.IPv4Network):
        raise TargetError(f"IPv6 is not supported: {spec!r}")
    yield from network.hosts()


def _expand_range(start_text: str, end_text: str, spec: str) -> Iterator[ipaddress.IPv4Address]:
    try:
        start = parse_ipv4(start_text)
    except ValueError as error:
        raise TargetError(f"invalid target {spec!r}: {error}") from None

    if "." in end_text:
        try:
            end = parse_ipv4(end_text)
        except ValueError as error:
            raise TargetError(f"invalid target {spec!r}: {error}") from None
    else:
        last_octet = int(end_text)
        if not 0 <= last_octet <= 255:
            raise TargetError(f"invalid target {spec!r}: octet must be between 0 and 255")
        end = ipaddress.IPv4Address((int(start) & 0xFFFFFF00) | last_octet)

    if int(end) < int(start):
        raise TargetError(f"invalid target {spec!r}: range ends before it starts")
    for value in range(int(start), int(end) + 1):
        yield ipaddress.IPv4Address(value)


def _resolve(spec: str) -> Iterator[ipaddress.IPv4Address]:
    try:
        infos = socket.getaddrinfo(spec, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as error:
        detail = error.strerror or str(error)
        raise TargetError(f"could not resolve {spec!r}: {detail}") from None

    seen: set[str] = set()
    yielded = False
    for info in infos:
        raw = str(info[4][0])
        if raw in seen:
            continue
        seen.add(raw)
        try:
            address = parse_ipv4(raw)
        except ValueError:
            continue
        yielded = True
        yield address
    if not yielded:
        raise TargetError(f"could not resolve {spec!r} to an IPv4 address")
