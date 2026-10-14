"""Hermetic doubles for the AI provider transport: a scripted loopback server and fake openers.

Nothing here leaves 127.0.0.1 (SPEC-41 section 8). A scripted server drives the real urllib and
http.client stack; a fake opener gives exact control over what each blocking step does.
"""
from __future__ import annotations

import socket
import threading
import time
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass


@dataclass
class Received:
    request_line: str
    headers: dict[str, str]
    body: bytes


Reply = Callable[[socket.socket, Received, threading.Event], None]


def _read_request(conn: socket.socket) -> Received:
    buffer = b''
    while b'\r\n\r\n' not in buffer:
        chunk = conn.recv(65536)
        if not chunk:
            break
        buffer += chunk
    head, _, body = buffer.partition(b'\r\n\r\n')
    lines = head.decode('latin-1').split('\r\n')
    headers = {name.lower(): value for name, _, value in (line.partition(': ') for line in lines[1:])}
    while len(body) < int(headers.get('content-length', 0)):
        chunk = conn.recv(65536)
        if not chunk:
            break
        body += chunk
    return Received(lines[0], headers, body)


def raw_reply(data: bytes) -> Reply:
    def reply(conn, received, release):
        conn.sendall(data)
    return reply


def http_reply(status: str = '200 OK', body: bytes = b'', *, headers: dict[str, str] | None = None) -> Reply:
    lines = [f'HTTP/1.1 {status}', f'Content-Length: {len(body)}', 'Connection: close',
             *(f'{name}: {value}' for name, value in (headers or {}).items())]
    return raw_reply('\r\n'.join(lines).encode('latin-1') + b'\r\n\r\n' + body)


def stall_after(data: bytes) -> Reply:
    """Send `data`, then keep the connection open until the server is torn down."""
    def reply(conn, received, release):
        conn.sendall(data)
        release.wait(30)
    return reply


def no_reply(conn, received, release):
    conn.close()


class Loopback:
    """Loopback TCP server: records every request and lets `reply` script the answer."""

    def __init__(self, reply: Reply, *, parse: bool = True) -> None:
        self.reply = reply
        self.parse = parse  # False hands the raw connection to `reply` (a TLS client says hello first)
        self.received: list[Received] = []
        self.release = threading.Event()
        self._stop = threading.Event()
        self._listener = socket.create_server(('127.0.0.1', 0))
        self._listener.settimeout(0.1)
        self._threads: list[threading.Thread] = []
        self.port = self._listener.getsockname()[1]
        self.endpoint = f'http://127.0.0.1:{self.port}'
        self._acceptor = threading.Thread(target=self._accept, daemon=True, name='loopback-accept')

    def __enter__(self) -> Loopback:
        self._acceptor.start()
        return self

    def __exit__(self, *exc) -> None:
        self.release.set()
        self._stop.set()
        self._acceptor.join(5)
        for thread in self._threads:
            thread.join(5)
        self._listener.close()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self._handle, args=(conn,), daemon=True, name='loopback-conn')
            self._threads.append(thread)
            thread.start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5)
            try:
                received = _read_request(conn) if self.parse else Received('', {}, b'')
                self.received.append(received)
                self.reply(conn, received, self.release)
            except OSError:
                pass  # the client gave up first (size cap, cancel or deadline)


class FakeResponse:
    """Context-manager response served from byte chunks; `error` is raised once the chunks run out."""

    def __init__(self, *chunks: bytes, error: BaseException | None = None) -> None:
        self.chunks = list(chunks)
        self.error = error
        self.closed = False
        self.reads = 0

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def close(self) -> None:
        self.closed = True

    def read1(self, size: int) -> bytes:
        self.reads += 1
        if self.chunks:
            chunk = self.chunks.pop(0)
            if len(chunk) > size:
                self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        if self.error is not None:
            raise self.error
        return b''


class FakeOpener:
    """Stands in for the opener built by providers; `outcome` is a response, an exception or a factory."""

    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.calls: list[tuple[urllib.request.Request, float | None]] = []

    def open(self, request, timeout=None):
        self.calls.append((request, timeout))
        outcome = self.outcome() if callable(self.outcome) else self.outcome
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def install_opener(monkeypatch, opener: FakeOpener) -> FakeOpener:
    monkeypatch.setattr(urllib.request, 'build_opener', lambda *handlers: opener)
    return opener


def wait_until(predicate: Callable[[], bool], timeout: float = 10.0) -> bool:
    """Poll `predicate`; never a fixed sleep (the Windows monotonic clock ticks every 15.6 ms)."""
    end = time.perf_counter() + timeout  # perf_counter: tests freeze time.monotonic with a fake clock
    while not predicate():
        if time.perf_counter() > end:
            return False
        time.sleep(0.01)
    return True


class FakeClock:
    """Stands in for time.monotonic: it moves only when a test advances it."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class BlockedResponse(FakeResponse):
    """A peer that stopped sending: read1 blocks until `release`, or five seconds so a failure cannot hang."""

    def __init__(self) -> None:
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def read1(self, size: int) -> bytes:
        self.started.set()
        self.release.wait(5)
        return b''


class LockedResponse(BlockedResponse):
    """Like http.client.HTTPResponse: close() waits for a read that is still blocked (reader lock)."""

    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()

    def read1(self, size: int) -> bytes:
        with self._lock:
            return super().read1(size)

    def close(self) -> None:
        with self._lock:
            super().close()
