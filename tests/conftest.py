"""Shared fixtures: real loopback servers instead of mocked sockets."""

from __future__ import annotations

import contextlib
import socket
import threading
from collections.abc import Iterator
from dataclasses import dataclass

import pytest


@dataclass
class LocalServer:
    """A tiny TCP server on 127.0.0.1 used to exercise the scanner."""

    port: int
    _socket: socket.socket
    _stop: threading.Event
    _thread: threading.Thread | None = None
    _banner: bytes | None = None
    _read_request: bool = False


class ServerFactory:
    """Starts loopback servers and guarantees they are closed after the test."""

    def __init__(self) -> None:
        self._servers: list[LocalServer] = []

    def __call__(
        self,
        banner: bytes | None = None,
        *,
        read_request: bool = False,
    ) -> LocalServer:
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        stop = threading.Event()
        server = LocalServer(
            port=int(listener.getsockname()[1]),
            _socket=listener,
            _stop=stop,
            _banner=banner,
            _read_request=read_request,
        )
        server._thread = threading.Thread(target=_serve, args=(server,), daemon=True)
        server._thread.start()
        self._servers.append(server)
        return server

    def close(self) -> None:
        for server in self._servers:
            server._stop.set()
            with contextlib.suppress(OSError):
                server._socket.close()
            if server._thread is not None:
                server._thread.join(timeout=2)


def _serve(server: LocalServer) -> None:
    listener = server._socket
    listener.settimeout(0.1)
    while not server._stop.is_set():
        try:
            connection, _address = listener.accept()
        except (TimeoutError, OSError):
            continue
        with connection:
            if server._read_request:
                connection.settimeout(0.5)
                with contextlib.suppress(OSError):
                    connection.recv(2048)
            if server._banner is not None:
                with contextlib.suppress(OSError):
                    connection.sendall(server._banner)


@pytest.fixture
def server_factory() -> Iterator[ServerFactory]:
    factory = ServerFactory()
    try:
        yield factory
    finally:
        factory.close()


@pytest.fixture
def free_port() -> int:
    """Return a port that was free a moment ago (nothing is listening on it)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])
