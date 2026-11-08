"""netscan - a small, dependency-free TCP network scanner.

The command line is the primary interface, but the same building blocks are
usable from Python::

    from netscan import ScanOptions, discover, expand_targets, parse_ports, scan_hosts

    targets = expand_targets(["192.168.1.0/24"])
    found = discover(targets)
    report = scan_hosts(found.hosts, parse_ports("common"), ScanOptions())
"""

from __future__ import annotations

from .discovery import DiscoveryResult, Method, discover
from .models import HostResult, PortResult, ScanReport
from .ports import parse_ports, service_name
from .scanner import ScanOptions, scan_hosts
from .targets import expand_targets
from .version import __version__

__all__ = [
    "DiscoveryResult",
    "HostResult",
    "Method",
    "PortResult",
    "ScanOptions",
    "ScanReport",
    "__version__",
    "discover",
    "expand_targets",
    "parse_ports",
    "scan_hosts",
    "service_name",
]
