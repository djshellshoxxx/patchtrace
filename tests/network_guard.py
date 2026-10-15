"""Network guard for the consent tests (SPEC-42 sections 5 and 7).

Arm a `NetworkGuard` around code that must not reach a network. While it is armed, a socket connect, a datagram
send, a name lookup, a `urllib.request` open or an `http.client` connection raises `NetworkAttempt` before anything
leaves the process, and the attempt is recorded. A test claims the attempts it expects; any left over, for example
one that the code under test caught and swallowed, fails the test at teardown.

Two layers: Python-level patches, which refuse before a name is resolved and name the URL, and one process-wide
audit hook, inert unless a guard is armed, which covers lookups and whatever bypasses the patches (`_socket` used
directly, any thread). A child process opens its own sockets and is invisible here: observe it by argv and
environment only.

Use the fixture by importing it; its registered name is `network_guard`:
    from network_guard import network_guard_fixture  # noqa: F401
"""
from __future__ import annotations

import http.client
import ipaddress
import socket
import sys
import threading
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass

import pytest

_ADDRESS_EVENTS = {'socket.connect': 'connect', 'socket.sendto': 'send', 'socket.sendmsg': 'send'}
_LOOKUP_EVENTS = ('socket.getaddrinfo', 'socket.gethostbyname', 'socket.gethostbyaddr', 'socket.getnameinfo')
_state = threading.Lock()
_active: NetworkGuard | None = None
_hook_installed = False


class NetworkAttempt(AssertionError):
    """Not an OSError, so urllib and socket users do not report it as an ordinary connection failure."""


@dataclass(frozen=True)
class Attempt:
    kind: str  # connect | send | lookup | urllib | http.client
    target: str


def is_loopback_host(host: object) -> bool:
    if isinstance(host, bytes):
        host = host.decode('ascii', 'replace')
    if not isinstance(host, str) or not host:
        return False
    if host.lower() == 'localhost':
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    # CPython 3.12 and 3.13 disagree about IPv4-mapped IPv6 loopback (SPEC-41 R11): refuse it on both.
    return address.is_loopback and getattr(address, 'ipv4_mapped', None) is None


def _target(host: object, port: object = None) -> str:
    text = host.decode('ascii', 'replace') if isinstance(host, bytes) else str(host)
    return text if port is None else f'{text}:{port}'


class NetworkGuard:
    """Context manager. `allow_loopback=True` lets local fake servers through; nothing else is let through."""

    def __init__(self, allow_loopback: bool = False):
        self.allow_loopback = allow_loopback
        self.attempts: list[Attempt] = []
        self._lock = threading.Lock()
        self._patches = pytest.MonkeyPatch()

    def __enter__(self) -> NetworkGuard:
        global _active
        with _state:
            if _active is not None:
                raise RuntimeError('a network guard is already armed')
            _install_audit_hook()
            self._patch()
            _active = self
        return self

    def __exit__(self, *_exc) -> None:
        global _active
        with _state:
            _active = None
        self._patches.undo()

    def claim(self) -> list[Attempt]:
        """The attempts so far, which the test expected; they no longer fail it."""
        with self._lock:
            taken = list(self.attempts)
            self.attempts.clear()
        return taken

    def assert_clean(self) -> None:
        if self.attempts:
            lines = '\n'.join(f'  {a.kind}: {a.target}' for a in self.attempts)
            raise AssertionError('network attempts the test did not claim (the code under test may have '
                                 f'swallowed NetworkAttempt):\n{lines}')

    def _refuse(self, kind: str, target: str) -> None:
        with self._lock:
            self.attempts.append(Attempt(kind, target))
        raise NetworkAttempt(f'{kind} to {target} refused by the network guard')

    def _check(self, kind: str, host: object, port: object = None) -> None:
        if not (self.allow_loopback and is_loopback_host(host)):
            self._refuse(kind, _target(host, port))

    def _check_address(self, kind: str, address: object) -> None:
        # Only (host, port, ...) tuples are network addresses; an AF_UNIX path is local.
        if isinstance(address, tuple) and address:
            self._check(kind, address[0], address[1] if len(address) > 1 else None)

    def _check_url(self, url: str) -> None:
        try:
            host = urllib.parse.urlsplit(url).hostname
        except ValueError:
            host = None
        if not (self.allow_loopback and is_loopback_host(host)):
            self._refuse('urllib', url)

    def _guarded_http_connect(self, original: Callable) -> Callable:
        def connect(connection):
            self._check('http.client', connection.host, connection.port)
            return original(connection)
        return connect

    def _patch(self) -> None:
        guard, patch = self, self._patches
        connect, connect_ex, sendto = socket.socket.connect, socket.socket.connect_ex, socket.socket.sendto
        opener_open = urllib.request.OpenerDirector.open

        def guarded_connect(sock, address):
            guard._check_address('connect', address)
            return connect(sock, address)

        def guarded_connect_ex(sock, address):
            guard._check_address('connect', address)
            return connect_ex(sock, address)

        def guarded_sendto(sock, data, *rest):
            guard._check_address('send', rest[-1])
            return sendto(sock, data, *rest)

        def guarded_open(opener, fullurl, *args, **kwargs):
            guard._check_url(fullurl if isinstance(fullurl, str) else fullurl.full_url)
            return opener_open(opener, fullurl, *args, **kwargs)

        patch.setattr(socket.socket, 'connect', guarded_connect)
        patch.setattr(socket.socket, 'connect_ex', guarded_connect_ex)
        patch.setattr(socket.socket, 'sendto', guarded_sendto)
        patch.setattr(urllib.request.OpenerDirector, 'open', guarded_open)
        for cls in (http.client.HTTPConnection, http.client.HTTPSConnection):
            patch.setattr(cls, 'connect', self._guarded_http_connect(cls.connect))


def _audit(event: str, args: tuple) -> None:
    guard = _active
    if guard is None:
        return
    if event in _ADDRESS_EVENTS:
        guard._check_address(_ADDRESS_EVENTS[event], args[1])
    elif event == 'socket.getnameinfo':
        guard._check_address('lookup', args[0])
    elif event in _LOOKUP_EVENTS:
        guard._check('lookup', args[0], args[1] if event == 'socket.getaddrinfo' else None)


def _install_audit_hook() -> None:
    # A hook cannot be removed, so it is installed once and stays inert while no guard is armed.
    global _hook_installed
    if not _hook_installed:
        sys.addaudithook(_audit)
        _hook_installed = True


@pytest.fixture(name='network_guard')
def network_guard_fixture() -> Iterator[NetworkGuard]:
    with NetworkGuard() as guard:
        yield guard
    guard.assert_clean()
