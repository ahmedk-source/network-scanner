"""TCP connect scanning with optional banner grabbing and reverse DNS.

This is a *connect* scan, not a SYN scan: it completes the three-way handshake
using ordinary sockets, so it works without administrator privileges and
without raw-packet libraries.  The trade-off is that a full connection shows up
in the target's logs, which is also why the tool is explicit about authorised
use.
"""

from __future__ import annotations

import errno
import socket
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from functools import partial

from .models import HostResult, PortResult
from .ports import service_name
from .utils import windowed_map
from .version import __version__

#: ``connect_ex`` answers that mean "the probe timed out", worth a retry.
_RETRY_CODES = frozenset(
    {
        errno.ETIMEDOUT,
        errno.EAGAIN,
        errno.EWOULDBLOCK,
        getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT),
        getattr(errno, "WSAEWOULDBLOCK", errno.EWOULDBLOCK),
    }
)

#: Ports that speak plain HTTP and therefore accept a harmless ``HEAD``.
PLAIN_HTTP_PORTS: frozenset[int] = frozenset(
    {80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8090, 8161, 8888, 9000, 9001, 10000}
)

#: Upper bound on the banner we keep, in bytes.
_BANNER_LIMIT = 1024

#: Upper bound on the banner we display, in characters.
_BANNER_DISPLAY_LIMIT = 120


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Tuning knobs shared by every port probe."""

    timeout: float = 0.5
    workers: int = 200
    retries: int = 0
    banners: bool = True
    resolve: bool = False
    banner_timeout: float = 1.0
    resolve_timeout: float = 1.5


HostCallback = Callable[[HostResult, int, int], None]


def scan_hosts(
    hosts: tuple[str, ...],
    ports: tuple[int, ...],
    options: ScanOptions,
    *,
    macs: dict[str, str] | None = None,
    on_host: HostCallback | None = None,
) -> tuple[HostResult, ...]:
    """Scan every host/port pair, returning one result per responsive host.

    ``on_host`` is called after each host with ``(result, completed, total)``
    so the CLI can draw a progress line without knowing how scanning works.
    """
    mac_map = macs if macs is not None else {}
    results: list[HostResult] = []
    total = len(hosts)
    if total == 0:
        return ()

    window = max(options.workers * 2, 8)
    with ThreadPoolExecutor(
        max_workers=max(1, options.workers),
        thread_name_prefix="netscan",
    ) as pool:
        for index, address in enumerate(hosts, start=1):
            open_ports = tuple(
                sorted(
                    (
                        result
                        for result in windowed_map(
                            pool,
                            partial(check_port, address, options=options),
                            ports,
                            window=window,
                        )
                        if result is not None
                    ),
                    key=lambda entry: entry.port,
                )
            )
            hostname = (
                resolve_hostname(address, options.resolve_timeout) if options.resolve else None
            )
            host = HostResult(
                address=address,
                mac=mac_map.get(address),
                hostname=hostname,
                ports=open_ports,
            )
            results.append(host)
            if on_host is not None:
                on_host(host, index, total)
    return tuple(results)


def check_port(address: str, port: int, *, options: ScanOptions) -> PortResult | None:
    """Return a :class:`PortResult` if *port* accepts a TCP connection.

    Only timeout-like failures are retried.  A refusal is a definitive answer
    and retrying it would only slow the scan down.
    """
    for attempt in range(options.retries + 1):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(options.timeout)
                code = sock.connect_ex((address, port))
                if code == 0:
                    banner = (
                        _grab_banner(
                            sock,
                            address=address,
                            port=port,
                            timeout=options.banner_timeout,
                        )
                        if options.banners
                        else None
                    )
                    return PortResult(port=port, service=service_name(port), banner=banner)
        except TimeoutError:
            code = errno.ETIMEDOUT
        except OSError:
            return None
        if attempt == options.retries or code not in _RETRY_CODES:
            return None
    return None


def _grab_banner(
    sock: socket.socket,
    *,
    address: str,
    port: int,
    timeout: float,
) -> str | None:
    """Read (or politely ask for) a short service banner."""
    is_http = port in PLAIN_HTTP_PORTS
    if is_http:
        request = f"HEAD / HTTP/1.0\r\nHost: {address}\r\nUser-Agent: netscan/{__version__}\r\n\r\n"
        try:
            sock.sendall(request.encode("ascii"))
        except OSError:
            return None

    sock.settimeout(timeout)
    chunks: list[bytes] = []
    received = 0
    try:
        while received < _BANNER_LIMIT:
            chunk = sock.recv(_BANNER_LIMIT - received)
            if not chunk:
                break
            chunks.append(chunk)
            received += len(chunk)
            if is_http and b"\r\n\r\n" in b"".join(chunks):
                break
    except OSError:
        return None
    return _clean_banner(b"".join(chunks), http=is_http)


def _clean_banner(raw: bytes, *, http: bool) -> str | None:
    """Turn a raw banner into one printable line, preferring ``Server:``."""
    text = raw.decode("utf-8", errors="replace")
    if http:
        headers = text.splitlines()
        server = next(
            (line for line in headers if line.lower().startswith("server:")),
            None,
        )
        if server is not None:
            text = server.split(":", 1)[1]
        elif headers:
            text = headers[0]
        else:
            text = ""

    printable = "".join(char if char.isprintable() else " " for char in text)
    collapsed = " ".join(printable.split())
    return collapsed[:_BANNER_DISPLAY_LIMIT] or None


def resolve_hostname(address: str, timeout: float = 1.5) -> str | None:
    """Reverse-resolve *address* with a hard timeout.

    ``socket.gethostbyaddr`` has no timeout of its own, and a broken DNS server
    can block a worker for many seconds.  The lookup therefore runs in a daemon
    thread that is abandoned when the deadline passes.
    """
    outcome: list[str | None] = []

    def lookup() -> None:
        try:
            outcome.append(socket.gethostbyaddr(address)[0])
        except OSError:
            outcome.append(None)

    thread = threading.Thread(target=lookup, name="netscan-mdns", daemon=True)
    thread.start()
    thread.join(timeout)
    return outcome[0] if outcome else None
