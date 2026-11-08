"""Tests for the port scanner, banner parsing and reverse DNS."""

from __future__ import annotations

import errno
import socket
import time
from typing import cast

import pytest

from netscan import scanner
from netscan.models import HostResult
from netscan.ports import service_name
from netscan.scanner import (
    ScanOptions,
    _clean_banner,
    _grab_banner,
    check_port,
    resolve_hostname,
    scan_hosts,
)

from .conftest import LocalServer, ServerFactory


class FakeSocket:
    """Minimal stand-in for a connected socket used by banner tests."""

    def __init__(self, payload: bytes = b"", error: OSError | None = None) -> None:
        self.payload = payload
        self.sent = b""
        self.error = error

    def __enter__(self) -> FakeSocket:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        return None

    def sendall(self, data: bytes) -> None:
        if self.error is not None:
            raise self.error
        self.sent += data

    def recv(self, size: int) -> bytes:
        chunk, self.payload = self.payload[:size], self.payload[size:]
        return chunk


class TimeoutSocket(FakeSocket):
    """A socket whose ``connect_ex`` always answers with a retryable code."""

    calls = 0
    code = errno.ETIMEDOUT

    def __init__(self, *args: object, **kwargs: object) -> None:
        super().__init__()

    def connect_ex(self, address: tuple[str, int]) -> int:
        type(self).calls += 1
        return type(self).code


def test_scan_options_defaults_are_conservative() -> None:
    options = ScanOptions()
    assert options.timeout == 0.5
    assert options.workers == 200
    assert options.retries == 0
    assert options.banners is True
    assert options.resolve is False


def test_open_port_is_detected_with_a_banner(server_factory: ServerFactory) -> None:
    server: LocalServer = server_factory(b"SSH-2.0-OpenSSH_9.6\r\n")
    result = check_port(
        "127.0.0.1",
        server.port,
        options=ScanOptions(timeout=2.0, banner_timeout=2.0),
    )
    assert result is not None
    assert result.port == server.port
    assert result.service == service_name(server.port)
    assert result.banner == "SSH-2.0-OpenSSH_9.6"


def test_banners_can_be_disabled(server_factory: ServerFactory) -> None:
    server = server_factory(b"SSH-2.0-OpenSSH_9.6\r\n")
    result = check_port(
        "127.0.0.1",
        server.port,
        options=ScanOptions(timeout=2.0, banners=False),
    )
    assert result is not None
    assert result.banner is None


def test_silent_service_does_not_block_forever(server_factory: ServerFactory) -> None:
    server = server_factory()
    started = time.monotonic()
    result = check_port(
        "127.0.0.1",
        server.port,
        options=ScanOptions(timeout=2.0, banner_timeout=0.05),
    )
    assert result is not None
    assert result.banner is None
    assert time.monotonic() - started < 2.0


def test_closed_port_is_not_reported(free_port: int) -> None:
    result = check_port(
        "127.0.0.1",
        free_port,
        options=ScanOptions(timeout=0.3, banners=False),
    )
    assert result is None


def test_timeout_like_failures_are_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    TimeoutSocket.calls = 0
    TimeoutSocket.code = errno.ETIMEDOUT
    monkeypatch.setattr(socket, "socket", TimeoutSocket)
    result = check_port(
        "127.0.0.1",
        12345,
        options=ScanOptions(timeout=0.01, retries=2, banners=False),
    )
    assert result is None
    assert TimeoutSocket.calls == 3


def test_refusals_are_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    TimeoutSocket.calls = 0
    TimeoutSocket.code = errno.ECONNREFUSED
    monkeypatch.setattr(socket, "socket", TimeoutSocket)
    result = check_port(
        "127.0.0.1",
        12345,
        options=ScanOptions(timeout=0.01, retries=2, banners=False),
    )
    assert result is None
    assert TimeoutSocket.calls == 1


def test_scan_hosts_returns_sorted_ports_and_metadata(
    server_factory: ServerFactory,
) -> None:
    first = server_factory(b"first\r\n")
    second = server_factory(b"second\r\n")

    result = scan_hosts(
        ("127.0.0.1",),
        (second.port, first.port),
        ScanOptions(timeout=2.0, banner_timeout=2.0, workers=4),
        macs={"127.0.0.1": "aa:bb:cc:dd:ee:01"},
    )
    assert len(result) == 1
    host = result[0]
    assert host.address == "127.0.0.1"
    assert host.mac == "aa:bb:cc:dd:ee:01"
    assert host.port_numbers == tuple(sorted((first.port, second.port)))
    assert host.hostname is None


def test_scan_hosts_can_resolve_hostnames(
    server_factory: ServerFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = server_factory(b"hello\r\n")
    monkeypatch.setattr(scanner, "resolve_hostname", lambda address, timeout=1.5: "loopback.local")
    result = scan_hosts(
        ("127.0.0.1",),
        (server.port,),
        ScanOptions(timeout=2.0, banner_timeout=2.0, resolve=True),
    )
    assert result[0].hostname == "loopback.local"


def test_scan_hosts_reports_hosts_without_open_ports(free_port: int) -> None:
    result = scan_hosts(
        ("127.0.0.1",),
        (free_port,),
        ScanOptions(timeout=0.3, banners=False),
    )
    assert len(result) == 1
    assert result[0].ports == ()


def test_scan_hosts_calls_the_progress_callback(server_factory: ServerFactory) -> None:
    server = server_factory(b"hello\r\n")
    events: list[tuple[str, int, int, int]] = []

    def on_host(host: HostResult, completed: int, total: int) -> None:
        events.append((host.address, host.open_port_count, completed, total))

    scan_hosts(
        ("127.0.0.1",),
        (server.port,),
        ScanOptions(timeout=2.0, banner_timeout=2.0),
        on_host=on_host,
    )
    assert events == [("127.0.0.1", 1, 1, 1)]


def test_scan_hosts_with_no_hosts_returns_empty() -> None:
    assert scan_hosts((), (80,), ScanOptions()) == ()


def test_http_banner_prefers_the_server_header() -> None:
    payload = b"HTTP/1.1 200 OK\r\nServer: test-server/1.0\r\nDate: today\r\n\r\n"
    fake = FakeSocket(payload)
    banner = _grab_banner(cast(socket.socket, fake), address="192.168.1.1", port=80, timeout=1.0)
    assert banner == "test-server/1.0"
    assert b"HEAD / HTTP/1.0" in fake.sent
    assert b"Host: 192.168.1.1" in fake.sent
    assert b"User-Agent: netscan/" in fake.sent


def test_http_banner_sends_the_request_and_handles_errors() -> None:
    fake = FakeSocket(b"", error=OSError("broken pipe"))
    assert (
        _grab_banner(cast(socket.socket, fake), address="192.168.1.1", port=8080, timeout=1.0)
        is None
    )


def test_non_http_banner_is_read_without_sending() -> None:
    fake = FakeSocket(b"FTP ready\r\n")
    assert (
        _grab_banner(cast(socket.socket, fake), address="192.168.1.1", port=21, timeout=1.0)
        == "FTP ready"
    )
    assert fake.sent == b""


def test_empty_banner_returns_none() -> None:
    fake = FakeSocket(b"")
    assert (
        _grab_banner(cast(socket.socket, fake), address="192.168.1.1", port=22, timeout=1.0) is None
    )


def test_clean_banner_falls_back_to_the_status_line() -> None:
    raw = b"HTTP/1.1 204 No Content\r\nDate: today\r\n\r\n"
    assert _clean_banner(raw, http=True) == "HTTP/1.1 204 No Content"


def test_clean_banner_removes_control_characters() -> None:
    assert _clean_banner(b"hello\x00world\r\n", http=False) == "hello world"


def test_clean_banner_collapses_whitespace() -> None:
    assert _clean_banner(b"  hello \r\n  world  ", http=False) == "hello world"


def test_clean_banner_is_truncated() -> None:
    banner = _clean_banner(b"x" * 300, http=False)
    assert banner is not None
    assert len(banner) == 120


def test_clean_banner_returns_none_for_empty_input() -> None:
    assert _clean_banner(b"", http=False) is None


def test_resolve_hostname_returns_the_first_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        socket,
        "gethostbyaddr",
        lambda address: ("router.lan", [], [address]),
    )
    assert resolve_hostname("192.168.1.1") == "router.lan"


def test_resolve_hostname_returns_none_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(address: str) -> tuple[str, list[str], list[str]]:
        raise socket.herror("unknown host")

    monkeypatch.setattr(socket, "gethostbyaddr", fail)
    assert resolve_hostname("192.168.1.1") is None


def test_resolve_hostname_honours_its_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def slow(address: str) -> tuple[str, list[str], list[str]]:
        time.sleep(0.2)
        return ("late", [], [address])

    monkeypatch.setattr(socket, "gethostbyaddr", slow)
    assert resolve_hostname("192.168.1.1", timeout=0.01) is None
