"""End-to-end tests for the command-line interface."""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

import pytest

from netscan import __version__
from netscan.cli import main

from .conftest import ServerFactory


def scan_json(port: int) -> list[str]:
    return [
        "scan",
        "127.0.0.1",
        "-m",
        "none",
        "-p",
        str(port),
        "--format",
        "json",
        "--no-banners",
        "--timeout",
        "1",
    ]


def test_version_flag(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["--version"])
    assert exit_info.value.code == 0
    assert __version__ in capsys.readouterr().out


def test_scan_help(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["scan", "--help"])
    assert exit_info.value.code == 0
    output = capsys.readouterr().out
    assert "--dry-run" in output
    assert "--allow-public" in output


def test_missing_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main([])
    assert exit_info.value.code == 2


def test_dry_run_prints_a_plan(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "192.168.1.0/30", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "Preview only" in output
    assert "192.168.1.0/30 (2 hosts)" in output
    assert "Max attempts" in output


def test_dry_run_accepts_the_auto_target(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import ipaddress

    from netscan import targets

    monkeypatch.setattr(
        targets,
        "guess_local_network",
        lambda: ipaddress.ip_network("192.168.5.0/30"),
    )
    assert main(["scan", "--dry-run"]) == 0
    output = capsys.readouterr().out
    assert "auto (2 hosts)" in output


def test_invalid_port_spec_exits_with_usage(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "192.168.1.1", "-p", "70000", "--dry-run"]) == 2
    assert "port 70000" in capsys.readouterr().err


def test_public_target_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "8.8.8.8", "--dry-run"]) == 2
    assert "not a private address" in capsys.readouterr().err


def test_public_target_can_be_allowed(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "8.8.8.8", "--allow-public", "--dry-run"]) == 0
    assert "8.8.8.8 (1 hosts)" in capsys.readouterr().out


def test_invalid_address_is_reported(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "999.1.1.1", "--dry-run"]) == 2
    assert "invalid target" in capsys.readouterr().err


def test_scan_json_output(
    server_factory: ServerFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    server = server_factory(b"SSH-2.0-Test\r\n")
    assert main(scan_json(server.port)) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == 1
    assert payload["method"] == "none"
    assert payload["hosts_scanned"] == 1
    assert payload["summary"] == {"hosts_scanned": 1, "hosts_up": 1, "open_ports": 1}
    assert payload["hosts"][0]["address"] == "127.0.0.1"
    assert payload["hosts"][0]["open_ports"][0]["port"] == server.port


def test_scan_csv_output(server_factory: ServerFactory, capsys: pytest.CaptureFixture[str]) -> None:
    server = server_factory(b"hello\r\n")
    arguments = scan_json(server.port)
    arguments[arguments.index("json")] = "csv"
    assert main(arguments) == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert rows[0] == ["host", "mac", "hostname", "port", "service", "banner"]
    assert rows[1][0] == "127.0.0.1"
    assert rows[1][3] == str(server.port)


def test_scan_table_output(
    server_factory: ServerFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    server = server_factory(b"hello\r\n")
    arguments = ["scan", "127.0.0.1", "-m", "none", "-p", str(server.port), "--timeout", "1"]
    assert main(arguments) == 0
    output = capsys.readouterr().out
    assert "Hosts  1 up / 1 probed" in output
    assert "Open ports" in output
    assert "Scan complete" in output


def test_verbose_reports_the_discovery_outcome(
    server_factory: ServerFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    server = server_factory(b"hello\r\n")
    arguments = [
        "scan",
        "127.0.0.1",
        "-m",
        "none",
        "-p",
        str(server.port),
        "--timeout",
        "1",
        "-v",
    ]
    assert main(arguments) == 0
    assert "Discovery: 1/1 host(s) up via none" in capsys.readouterr().out


def test_quiet_hides_the_header_but_keeps_the_table(
    server_factory: ServerFactory, capsys: pytest.CaptureFixture[str]
) -> None:
    server = server_factory(b"hello\r\n")
    arguments = [
        "scan",
        "127.0.0.1",
        "-m",
        "none",
        "-p",
        str(server.port),
        "--timeout",
        "1",
        "-q",
    ]
    assert main(arguments) == 0
    output = capsys.readouterr().out
    assert "Target" not in output
    assert "127.0.0.1" in output
    assert "Hosts  1 up / 1 probed" in output


def test_json_report_can_be_written_to_a_file(
    server_factory: ServerFactory,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    server = server_factory(b"hello\r\n")
    destination = tmp_path / "scan.json"
    arguments = [*scan_json(server.port), "-o", str(destination)]
    assert main(arguments) == 0
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["summary"]["open_ports"] == 1
    assert "Report written" in capsys.readouterr().out


def test_table_report_can_be_written_to_a_file(
    server_factory: ServerFactory,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    server = server_factory(b"hello\r\n")
    destination = tmp_path / "scan.txt"
    arguments = ["scan", "127.0.0.1", "-m", "none", "-p", str(server.port), "-o", str(destination)]
    assert main(arguments) == 0
    content = destination.read_text(encoding="utf-8")
    assert "Address" in content
    assert "127.0.0.1" in content
    assert "Report written" in capsys.readouterr().out


def test_unwritable_output_is_reported(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = ["scan", "127.0.0.1", "-m", "none", "-p", "1", "--output", str(tmp_path)]
    assert main(arguments) == 2
    assert "could not write" in capsys.readouterr().err


def test_progress_is_written_to_stderr(free_port: int, capsys: pytest.CaptureFixture[str]) -> None:
    arguments = [
        "scan",
        "127.0.0.1",
        "-m",
        "none",
        "-p",
        str(free_port),
        "--timeout",
        "1",
        "--progress",
    ]
    assert main(arguments) == 0
    captured = capsys.readouterr()
    assert "Scanned 1/1 hosts" in captured.err


def test_interrupt_returns_130(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr("netscan.cli.scan_hosts", interrupted)
    assert main(["scan", "127.0.0.1", "-m", "none", "-p", "1"]) == 130
    assert "cancelled" in capsys.readouterr().err


def test_ports_command_lists_presets(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ports"]) == 0
    output = capsys.readouterr().out
    assert "Presets" in output
    assert "common" in output
    assert "web" in output
    assert "all" in output
    assert "ssh" in output


def test_ports_command_expands_a_range(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ports", "22-23"]) == 0
    output = capsys.readouterr().out
    assert "22-23 (2 ports)" in output
    assert "ssh" in output
    assert "telnet" in output


def test_ports_command_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ports", "80,443", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["spec"] == "80,443"
    assert payload["ports"] == [
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"},
    ]


def test_ports_json_lists_presets(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["ports", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["presets"]["web"] == 7
    assert payload["presets"]["all"] == 65535
    assert {"port": 22, "service": "ssh"} in payload["common"]


@pytest.mark.parametrize(
    "arguments",
    [
        ["scan", "--workers", "0", "192.168.1.1"],
        ["scan", "--timeout", "0", "192.168.1.1"],
        ["scan", "--timeout", "nan", "192.168.1.1"],
        ["scan", "--retries", "9", "192.168.1.1"],
    ],
)
def test_argument_validation_uses_exit_code_two(arguments: list[str]) -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(arguments)
    assert exit_info.value.code == 2
