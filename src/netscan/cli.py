"""Command-line interface for netscan."""

from __future__ import annotations

import argparse
import io
import json
import math
import sys
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TextIO, cast

from .console import Console
from .discovery import Method, discover
from .errors import NetscanError, OutputError
from .models import HostResult, ScanReport
from .output import render_table, report_csv, report_payload
from .ports import COMMON_PORTS, MAX_PORT, PRESETS, parse_ports, service_name
from .scanner import ScanOptions, scan_hosts
from .targets import DEFAULT_MAX_HOSTS, expand_targets
from .version import __version__

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130

_EPILOG = """\
examples:
  netscan scan                          scan the local /24 with the common ports
  netscan scan 192.168.1.0/24           scan a whole subnet
  netscan scan 192.168.1.10 -p 1-1024   scan one host on ports 1-1024
  netscan scan 192.168.1.0/24 -m arp    use ARP discovery (Scapy + privileges)
  netscan scan 10.0.0.0/24 --format json -o scan.json
  netscan ports 1-100                   list service names for a port range

Only scan networks you own or are authorised to test.
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscan",
        description=(
            "Discover devices on an IPv4 network and list their open TCP ports. "
            "No raw packets and no administrator privileges required by default."
        ),
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-v", "--verbose", action="count", default=0, help="show extra detail")
    common.add_argument("-q", "--quiet", action="store_true", help="hide headers and progress")
    common.add_argument("--no-color", action="store_true", help="disable ANSI colour")

    subparsers = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    scan = subparsers.add_parser(
        "scan",
        parents=[common],
        help="discover hosts and scan their TCP ports",
        description="Discover responsive hosts and list the TCP ports that accept connections.",
    )
    scan.add_argument(
        "targets",
        nargs="*",
        metavar="TARGET",
        help="IPv4 address, CIDR block, start-end range or hostname (default: local /24)",
    )
    scan.add_argument(
        "-p",
        "--ports",
        default="common",
        metavar="SPEC",
        help="ports to scan: common, web, all, 22,80,443 or 1-1024 (default: common)",
    )
    scan.add_argument(
        "-m",
        "--method",
        choices=[method.value for method in Method],
        default=Method.AUTO.value,
        help="host discovery: auto, tcp, arp, cache or none (default: auto)",
    )
    scan.add_argument(
        "--timeout",
        type=_positive_float,
        default=0.5,
        metavar="SECONDS",
        help="connect timeout per port (default: 0.5)",
    )
    scan.add_argument(
        "--workers",
        type=_int_in_range(1, 1024),
        default=200,
        metavar="N",
        help="number of concurrent connections (default: 200)",
    )
    scan.add_argument(
        "--retries",
        type=_int_in_range(0, 5),
        default=0,
        metavar="N",
        help="retries for ports that time out (default: 0)",
    )
    scan.add_argument(
        "--banners",
        dest="banners",
        action="store_true",
        default=True,
        help="read service banners from open ports (default)",
    )
    scan.add_argument(
        "--no-banners",
        dest="banners",
        action="store_false",
        help="skip banner grabbing",
    )
    scan.add_argument(
        "--resolve",
        action="store_true",
        help="reverse-resolve hostnames (can be slow on broken DNS)",
    )
    scan.add_argument(
        "--allow-public",
        action="store_true",
        help="allow targets outside private address ranges",
    )
    scan.add_argument(
        "--max-hosts",
        type=_int_in_range(1, 65536),
        default=DEFAULT_MAX_HOSTS,
        metavar="N",
        help=f"refuse target lists larger than this (default: {DEFAULT_MAX_HOSTS})",
    )
    scan.add_argument(
        "--format",
        choices=("table", "json", "csv"),
        default="table",
        help="report format (default: table)",
    )
    scan.add_argument(
        "-o",
        "--output",
        type=Path,
        metavar="PATH",
        help="write the report to a file instead of standard output",
    )
    scan.add_argument(
        "--dry-run",
        action="store_true",
        help="show what would be scanned without sending any packets",
    )
    scan.add_argument(
        "--progress",
        action="store_true",
        help="show a live progress line on standard error",
    )
    scan.set_defaults(handler=_cmd_scan)

    ports = subparsers.add_parser(
        "ports",
        parents=[common],
        help="list the built-in presets or expand a port specification",
        description="Show port numbers and their service names.",
    )
    ports.add_argument("spec", nargs="?", metavar="SPEC", help="preset or specification to expand")
    ports.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    ports.set_defaults(handler=_cmd_ports)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code instead of calling ``sys.exit``."""
    _enable_utf8()
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(
        color=False if getattr(args, "no_color", False) else None,
        quiet=getattr(args, "quiet", False),
    )
    handler = cast(Callable[[argparse.Namespace, Console], int], args.handler)
    try:
        return handler(args, console)
    except NetscanError as error:
        print(f"error: {error}", file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print("\ncancelled", file=sys.stderr)
        return EXIT_INTERRUPTED
    except BrokenPipeError:  # e.g. ``netscan scan | head``
        return EXIT_OK


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _cmd_scan(args: argparse.Namespace, console: Console) -> int:
    specs = tuple(args.targets) if args.targets else ("auto",)
    targets = expand_targets(
        specs,
        max_hosts=args.max_hosts,
        allow_public=args.allow_public,
    )
    ports = parse_ports(args.ports)

    if args.dry_run:
        _print_plan(console, specs, targets, args, ports)
        return EXIT_OK

    if args.format == "table":
        console.info(
            f"Scanning {len(targets)} address(es) on {len(ports)} port(s) "
            f"(discovery: {args.method}) ..."
        )

    progress = _Progress(
        sys.stderr,
        enabled=args.progress and not console.quiet and args.format == "table",
    )
    started_at = datetime.now(UTC).isoformat(timespec="seconds")
    started = time.monotonic()
    try:
        discovery = discover(
            targets,
            method=Method(args.method),
            timeout=args.timeout,
            workers=min(args.workers, 256),
        )
        if args.verbose and args.format == "table" and not console.quiet:
            console.info(
                f"Discovery: {len(discovery.hosts)}/{len(targets)} host(s) up "
                f"via {discovery.method}"
            )
        hosts = scan_hosts(
            discovery.hosts,
            ports,
            ScanOptions(
                timeout=args.timeout,
                workers=args.workers,
                retries=args.retries,
                banners=args.banners,
                resolve=args.resolve,
            ),
            macs=discovery.macs,
            on_host=progress,
        )
    finally:
        progress.finish()
    duration = time.monotonic() - started

    report = ScanReport(
        specs=specs,
        targets=targets,
        method=discovery.method,
        started_at=started_at,
        duration=duration,
        hosts=hosts,
        port_spec=args.ports.strip().lower(),
        port_count=len(ports),
        warnings=discovery.warnings,
    )
    _emit_report(report, args, console)
    return EXIT_OK


def _emit_report(report: ScanReport, args: argparse.Namespace, console: Console) -> None:
    output: Path | None = args.output
    if args.format == "table":
        if output is None:
            render_table(console, report)
            console.info(console.style(f"Scan complete in {report.duration:.2f}s.", "dim"))
            return
        buffer = io.StringIO()
        render_table(Console(stream=buffer, color=False), report)
        _write(output, buffer.getvalue())
        _summarise(console, report, output)
        return

    if args.format == "json":
        text = json.dumps(report_payload(report), indent=2, ensure_ascii=False) + "\n"
    else:
        text = report_csv(report)

    if output is None:
        sys.stdout.write(text)
        return
    _write(output, text)
    _summarise(console, report, output)


def _summarise(console: Console, report: ScanReport, output: Path) -> None:
    console.info(
        f"Scanned {report.scanned_hosts} host(s): {report.hosts_up} up, "
        f"{report.open_ports} open port(s). Report written to {output}."
    )


def _write(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8")
    except OSError as error:
        raise OutputError(f"could not write {path}: {error}") from error


def _print_plan(
    console: Console,
    specs: tuple[str, ...],
    targets: tuple[str, ...],
    args: argparse.Namespace,
    ports: tuple[int, ...],
) -> None:
    console.paragraph("Targets", f"{', '.join(specs)} ({len(targets)} hosts)")
    console.paragraph("Discovery", args.method)
    console.paragraph("Ports", f"{args.ports} ({len(ports)} ports)")
    console.paragraph(
        "Timeout",
        f"{args.timeout:g}s per connection, {args.workers} workers, {args.retries} retries",
    )
    console.paragraph("Max attempts", f"{len(targets) * len(ports):,}")
    console.info("")
    console.write(console.style("Preview only - re-run without --dry-run to scan.", "yellow"))


# ---------------------------------------------------------------------------
# ports
# ---------------------------------------------------------------------------


def _cmd_ports(args: argparse.Namespace, console: Console) -> int:
    if args.spec is None:
        _list_presets(console, as_json=args.format == "json")
        return EXIT_OK

    ports = parse_ports(args.spec)
    if args.format == "json":
        payload: dict[str, Any] = {
            "schema": 1,
            "spec": args.spec,
            "ports": [{"port": port, "service": service_name(port)} for port in ports],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_OK

    console.info(f"{args.spec} ({len(ports)} ports)")
    console.info("")
    console.table(
        ["Port", "Service"],
        [[str(port), service_name(port)] for port in ports],
        aligns=["r", "l"],
    )
    return EXIT_OK


def _list_presets(console: Console, *, as_json: bool) -> None:
    if as_json:
        presets = {name: len(ports) for name, ports in PRESETS.items()}
        presets["all"] = MAX_PORT
        payload = {
            "schema": 1,
            "presets": presets,
            "common": [{"port": port, "service": service_name(port)} for port in COMMON_PORTS],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    console.info("Presets")
    rows = [[name, str(len(ports))] for name, ports in PRESETS.items()]
    rows.append(["all", str(MAX_PORT)])
    console.table(["Name", "Ports"], rows, aligns=["l", "r"])
    console.info("")
    console.info(f"Common ports ({len(COMMON_PORTS)})")
    console.table(
        ["Port", "Service"],
        [[str(port), service_name(port)] for port in COMMON_PORTS],
        aligns=["r", "l"],
    )


# ---------------------------------------------------------------------------
# progress and argument helpers
# ---------------------------------------------------------------------------


class _Progress:
    """A single-line progress indicator written to standard error."""

    def __init__(self, stream: TextIO, *, enabled: bool) -> None:
        self._stream = stream
        self._enabled = enabled
        self._up = 0
        self._started = False

    def __call__(self, host: HostResult, completed: int, total: int) -> None:
        if not self._enabled:
            return
        self._started = True
        if host.open_port_count > 0:
            self._up += 1
        self._stream.write(f"\rScanned {completed}/{total} hosts, {self._up} with open ports")
        self._stream.flush()

    def finish(self) -> None:
        if self._started:
            self._stream.write("\n")
            self._stream.flush()


def _positive_float(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid number: {value!r}") from None
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("must be a positive number")
    return number


def _int_in_range(minimum: int, maximum: int) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            number = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid integer: {value!r}") from None
        if not minimum <= number <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return number

    return parse


def _enable_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (AttributeError, OSError, ValueError):
            continue
