"""Tests for the table, JSON and CSV renderers."""

from __future__ import annotations

import csv
import io
import json

from netscan.console import Console
from netscan.models import HostResult, PortResult, ScanReport
from netscan.output import SCHEMA_VERSION, render_table, report_csv, report_payload
from netscan.version import __version__


def make_report(
    *,
    hosts: tuple[HostResult, ...] = (),
    warnings: tuple[str, ...] = (),
    specs: tuple[str, ...] = ("192.168.1.0/30",),
    targets: tuple[str, ...] = ("192.168.1.1", "192.168.1.2"),
    method: str = "tcp",
    duration: float = 1.234,
    port_spec: str = "common",
    port_count: int = 110,
) -> ScanReport:
    return ScanReport(
        specs=specs,
        targets=targets,
        method=method,
        started_at="2026-01-01T00:00:00+00:00",
        duration=duration,
        hosts=hosts,
        port_spec=port_spec,
        port_count=port_count,
        warnings=warnings,
    )


def sample_host(address: str = "192.168.1.1") -> HostResult:
    return HostResult(
        address=address,
        mac="aa:bb:cc:dd:ee:01",
        hostname="router.lan",
        ports=(
            PortResult(port=22, service="ssh", banner="SSH-2.0-OpenSSH_9.6"),
            PortResult(port=80, service="http", banner="nginx/1.27"),
        ),
    )


def test_report_totals() -> None:
    report = make_report(hosts=(sample_host(), HostResult(address="192.168.1.2")))
    assert report.scanned_hosts == 2
    assert report.hosts_up == 2
    assert report.open_ports == 2


def test_payload_has_a_stable_shape() -> None:
    report = make_report(hosts=(sample_host(),))
    payload = report_payload(report)
    assert payload["schema"] == SCHEMA_VERSION == 1
    assert payload["tool"] == "netscan"
    assert payload["version"] == __version__
    assert payload["targets"] == ["192.168.1.0/30"]
    assert payload["hosts_scanned"] == 2
    assert payload["method"] == "tcp"
    assert payload["port_spec"] == "common"
    assert payload["ports_scanned"] == 110
    assert payload["duration_seconds"] == round(report.duration, 3)
    assert payload["hosts"][0]["address"] == "192.168.1.1"
    assert payload["hosts"][0]["open_ports"][0] == {
        "port": 22,
        "service": "ssh",
        "banner": "SSH-2.0-OpenSSH_9.6",
    }
    assert payload["summary"] == {
        "hosts_scanned": 2,
        "hosts_up": 1,
        "open_ports": 2,
    }


def test_payload_is_json_serialisable() -> None:
    payload = report_payload(make_report(hosts=(sample_host(),)))
    text = json.dumps(payload)
    assert "router.lan" in text


def test_csv_has_one_row_per_open_port_plus_portless_hosts() -> None:
    report = make_report(
        hosts=(sample_host(), HostResult(address="192.168.1.2", hostname="printer.lan"))
    )
    rows = list(csv.reader(io.StringIO(report_csv(report))))
    assert rows[0] == ["host", "mac", "hostname", "port", "service", "banner"]
    assert rows[1] == [
        "192.168.1.1",
        "aa:bb:cc:dd:ee:01",
        "router.lan",
        "22",
        "ssh",
        "SSH-2.0-OpenSSH_9.6",
    ]
    assert rows[2][3:5] == ["80", "http"]
    assert rows[3] == ["192.168.1.2", "", "printer.lan", "", "", ""]


def test_csv_quotes_values_containing_commas() -> None:
    host = HostResult(
        address="192.168.1.1",
        ports=(PortResult(port=80, service="http", banner="hello, world"),),
    )
    rows = list(csv.reader(io.StringIO(report_csv(make_report(hosts=(host,))))))
    assert rows[1][5] == "hello, world"


def test_csv_ends_with_a_newline() -> None:
    text = report_csv(make_report(hosts=(sample_host(),)))
    assert text.endswith("\n")
    assert "\r" not in text


def test_table_renders_hosts_and_details() -> None:
    stream = io.StringIO()
    console = Console(stream=stream, color=False)
    render_table(console, make_report(hosts=(sample_host(),)))
    output = stream.getvalue()
    assert "Target      192.168.1.0/30 (2 hosts)" in output
    assert "Discovery   tcp" in output
    assert "Ports       common (110 ports)" in output
    assert "Hosts  1 up / 2 probed" in output
    assert "aa:bb:cc:dd:ee:01" in output
    assert "router.lan" in output
    assert "22, 80" in output
    assert "SSH-2.0-OpenSSH_9.6" in output
    assert "nginx/1.27" in output


def test_table_marks_assumed_hosts() -> None:
    stream = io.StringIO()
    render_table(Console(stream=stream, color=False), make_report(method="none"))
    assert "none (every target assumed up)" in stream.getvalue()


def test_table_says_when_no_host_answered() -> None:
    stream = io.StringIO()
    render_table(Console(stream=stream, color=False), make_report(hosts=()))
    assert "No responsive hosts found." in stream.getvalue()


def test_table_says_when_hosts_answered_without_open_ports() -> None:
    stream = io.StringIO()
    report = make_report(hosts=(HostResult(address="192.168.1.1"),))
    render_table(Console(stream=stream, color=False), report)
    assert "No open TCP ports found on the responsive hosts." in stream.getvalue()


def test_table_prints_warnings() -> None:
    stream = io.StringIO()
    report = make_report(hosts=(sample_host(),), warnings=("ARP failed",))
    render_table(Console(stream=stream, color=False), report)
    assert "warning: ARP failed" in stream.getvalue()


def test_table_truncates_a_long_target_list() -> None:
    stream = io.StringIO()
    report = make_report(
        specs=("192.168.1.0/24", "192.168.2.0/24", "192.168.3.0/24", "192.168.4.0/24"),
        hosts=(sample_host(),),
    )
    render_table(Console(stream=stream, color=False), report)
    assert "..." in stream.getvalue()


def test_table_summarises_many_open_ports_inline() -> None:
    host = HostResult(
        address="192.168.1.1",
        ports=tuple(PortResult(port=port, service="http") for port in range(1, 11)),
    )
    stream = io.StringIO()
    render_table(Console(stream=stream, color=False), make_report(hosts=(host,)))
    assert "(+2 more)" in stream.getvalue()
