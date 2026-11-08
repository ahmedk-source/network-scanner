"""Report rendering: terminal table, JSON payload and CSV.

All three formats are derived from the same :class:`~netscan.models.ScanReport`
so a script and a human always see the same scan.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from .console import Console
from .models import HostResult, ScanReport
from .version import __version__

SCHEMA_VERSION = 1

#: How many open ports to list inline in the host table before summarising.
INLINE_PORT_LIMIT = 8


def report_payload(report: ScanReport) -> dict[str, Any]:
    """Return the versioned JSON payload for *report*."""
    return {
        "schema": SCHEMA_VERSION,
        "tool": "netscan",
        "version": __version__,
        "started_at": report.started_at,
        "duration_seconds": round(report.duration, 3),
        "targets": list(report.specs),
        "hosts_scanned": report.scanned_hosts,
        "method": report.method,
        "port_spec": report.port_spec,
        "ports_scanned": report.port_count,
        "warnings": list(report.warnings),
        "hosts": [_host_payload(host) for host in report.hosts],
        "summary": {
            "hosts_scanned": report.scanned_hosts,
            "hosts_up": report.hosts_up,
            "open_ports": report.open_ports,
        },
    }


def _host_payload(host: HostResult) -> dict[str, Any]:
    return {
        "address": host.address,
        "mac": host.mac,
        "hostname": host.hostname,
        "open_ports": [
            {"port": entry.port, "service": entry.service, "banner": entry.banner}
            for entry in host.ports
        ],
    }


def report_csv(report: ScanReport) -> str:
    """Return one CSV row per open port.

    Responsive hosts without an open port still get a row, with the three port
    columns empty, so the CSV is a complete record of the scan.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(["host", "mac", "hostname", "port", "service", "banner"])
    for host in report.hosts:
        identity = [host.address, host.mac or "", host.hostname or ""]
        if not host.ports:
            writer.writerow([*identity, "", "", ""])
            continue
        for entry in host.ports:
            writer.writerow([*identity, str(entry.port), entry.service, entry.banner or ""])
    return buffer.getvalue()


def render_table(console: Console, report: ScanReport) -> None:
    """Print the human-readable report."""
    console.info("")
    if not console.quiet:
        console.paragraph("Target", _target_description(report))
        method = report.method
        if method == "none":
            method = "none (every target assumed up)"
        console.paragraph("Discovery", method)
        console.paragraph("Ports", f"{report.port_spec} ({report.port_count} ports)")
        console.paragraph("Duration", f"{report.duration:.2f}s")

    if report.warnings:
        console.info("")
        for warning in report.warnings:
            console.write(console.style(f"warning: {warning}", "yellow"))

    console.info("")
    if report.hosts_up == 0:
        console.write(console.style("No responsive hosts found.", "yellow"))
        return

    console.write(
        console.style(
            f"Hosts  {report.hosts_up} up / {report.scanned_hosts} probed",
            "green",
        )
    )
    console.info("")
    rows = [
        [
            host.address,
            host.mac or "-",
            host.hostname or "-",
            _inline_ports(host),
        ]
        for host in report.hosts
    ]
    console.table(["Address", "MAC", "Hostname", "Open ports"], rows)

    with_ports = [host for host in report.hosts if host.ports]
    if not with_ports:
        console.info("")
        console.info("No open TCP ports found on the responsive hosts.")
        return

    console.info("")
    console.info("Open ports")
    console.info("-" * 10)
    for host in with_ports:
        heading = host.address
        if host.hostname:
            heading += f"  {host.hostname}"
        console.write(console.style(heading, "bold"))
        port_rows = [[str(entry.port), entry.service, entry.banner or "-"] for entry in host.ports]
        console.table(["Port", "Service", "Banner"], port_rows, aligns=["r", "l", "l"])
        console.info("")


def _target_description(report: ScanReport) -> str:
    specs = ", ".join(report.specs)
    if len(specs) > 52:
        specs = f"{specs[:49]}..."
    return f"{specs} ({report.scanned_hosts} hosts)"


def _inline_ports(host: HostResult) -> str:
    numbers = host.port_numbers
    if not numbers:
        return "-"
    shown = ", ".join(str(port) for port in numbers[:INLINE_PORT_LIMIT])
    hidden = len(numbers) - INLINE_PORT_LIMIT
    return f"{shown} (+{hidden} more)" if hidden > 0 else shown
