"""Immutable value objects shared by the scanner, the renderers and the CLI."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class PortResult:
    """An open TCP port and whatever the service volunteered about itself."""

    port: int
    service: str
    banner: str | None = None


@dataclass(frozen=True, slots=True)
class HostResult:
    """A responsive host and the open ports found on it."""

    address: str
    mac: str | None = None
    hostname: str | None = None
    ports: tuple[PortResult, ...] = ()

    @property
    def open_port_count(self) -> int:
        """Number of open ports recorded for this host."""
        return len(self.ports)

    @property
    def port_numbers(self) -> tuple[int, ...]:
        """Open port numbers, ascending."""
        return tuple(result.port for result in self.ports)


@dataclass(frozen=True, slots=True)
class ScanReport:
    """Everything the CLI needs to render one completed scan."""

    specs: tuple[str, ...]
    targets: tuple[str, ...]
    method: str
    started_at: str
    duration: float
    hosts: tuple[HostResult, ...]
    port_spec: str
    port_count: int
    warnings: tuple[str, ...] = ()

    @property
    def scanned_hosts(self) -> int:
        """Number of addresses that were probed, whether they answered or not."""
        return len(self.targets)

    @property
    def hosts_up(self) -> int:
        """Number of responsive hosts."""
        return len(self.hosts)

    @property
    def open_ports(self) -> int:
        """Total number of open ports across all hosts."""
        return sum(host.open_port_count for host in self.hosts)
