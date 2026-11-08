"""Scan your own machine with the netscan Python API.

This is the safest possible first run: it only ever talks to 127.0.0.1,
never to any other address. Start a server first (for example
``python -m http.server 8000``) and you will see port 8000 in the
results, including its banner.

Run it with:  python examples/scan_localhost.py
"""

from __future__ import annotations

from netscan import ScanOptions, discover, expand_targets, parse_ports, scan_hosts


def main() -> None:
    targets = expand_targets(["127.0.0.1"])
    found = discover(targets)  # TCP probes; no privileges needed
    print(f"Discovery: {len(found.hosts)}/{len(targets)} host(s) up")

    hosts = scan_hosts(
        found.hosts,
        parse_ports("common"),
        ScanOptions(timeout=0.5, workers=100),
        macs=found.macs,
    )
    open_ports = sum(host.open_port_count for host in hosts)
    print(f"Scan complete: {open_ports} open port(s) on {len(hosts)} host(s)")
    for host in hosts:
        for port in host.ports:
            banner = f" | {port.banner}" if port.banner else ""
            print(f"  {host.address}:{port.port} {port.service}{banner}")


if __name__ == "__main__":
    main()
