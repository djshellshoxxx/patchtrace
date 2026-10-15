"""The reusable network guard (tests/network_guard.py): what it blocks, what it records and when it disarms.

Every target is reserved (`.invalid`, TEST-NET-3), and the guard refuses before any name lookup or connect, so
nothing here touches a network."""
from __future__ import annotations

import _socket
import http.client
import os
import socket
import subprocess
import sys
import textwrap
import threading
import urllib.request
from pathlib import Path

import pytest
from network_guard import NetworkAttempt, NetworkGuard, is_loopback_host

TESTS_DIR = Path(__file__).resolve().parent
UNROUTABLE = ('203.0.113.7', 9)


def _tcp_connect():
    with socket.socket() as sock:
        sock.connect(UNROUTABLE)


def _tcp_connect_by_name():
    with socket.socket() as sock:  # refused before the name is resolved: no lookup leaves the process
        sock.connect(('example.invalid', 9))


def _tcp_connect_ex():
    with socket.socket() as sock:
        sock.connect_ex(UNROUTABLE)


def _udp_send():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b'x', UNROUTABLE)


def _udp_send_by_name():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(b'x', ('example.invalid', 9))


def _raw_socket_module():
    sock = _socket.socket()  # not a socket.socket: the Python-level patches miss it, only the audit hook sees it
    try:
        sock.connect(UNROUTABLE)
    finally:
        sock.close()


CHANNELS = [
    (_tcp_connect, 'connect', '203.0.113.7:9'),
    (_tcp_connect_ex, 'connect', '203.0.113.7:9'),
    (_udp_send, 'send', '203.0.113.7:9'),
    (_tcp_connect_by_name, 'connect', 'example.invalid:9'),
    (_udp_send_by_name, 'send', 'example.invalid:9'),
    (_raw_socket_module, 'connect', '203.0.113.7:9'),
    (lambda: socket.create_connection(UNROUTABLE, timeout=1), 'lookup', '203.0.113.7:9'),
    (lambda: socket.getaddrinfo('example.invalid', 443), 'lookup', 'example.invalid:443'),
    (lambda: socket.gethostbyname('example.invalid'), 'lookup', 'example.invalid'),
    (lambda: urllib.request.urlopen('https://example.invalid/a', timeout=1), 'urllib',
     'https://example.invalid/a'),
    (lambda: urllib.request.build_opener(urllib.request.ProxyHandler({})).open('https://example.invalid/b'),
     'urllib', 'https://example.invalid/b'),
    (lambda: urllib.request.urlopen(urllib.request.Request('http://example.invalid/c', method='HEAD')),
     'urllib', 'http://example.invalid/c'),
    (lambda: http.client.HTTPSConnection('example.invalid', timeout=1).request('GET', '/'), 'http.client',
     'example.invalid:443'),
    (lambda: http.client.HTTPConnection('example.invalid', 8080, timeout=1).connect(), 'http.client',
     'example.invalid:8080'),
]
CHANNEL_IDS = ['tcp-connect', 'tcp-connect-ex', 'udp-sendto', 'tcp-connect-name', 'udp-sendto-name',
               'raw-socket-module', 'create-connection',
               'getaddrinfo', 'gethostbyname', 'urlopen', 'opener-open', 'urlopen-request', 'https-request',
               'http-connect']


@pytest.mark.parametrize(('call', 'kind', 'target'), CHANNELS, ids=CHANNEL_IDS)
def test_every_channel_is_refused_and_recorded_once(call, kind, target):
    with NetworkGuard() as guard:
        with pytest.raises(NetworkAttempt):
            call()
        assert [(a.kind, a.target) for a in guard.claim()] == [(kind, target)]
        guard.assert_clean()


def test_an_attempt_the_code_swallowed_still_fails_the_check():
    with NetworkGuard() as guard:
        try:
            urllib.request.urlopen('https://example.invalid/swallowed')
        except Exception:  # noqa: BLE001 - this is what the code under test does
            pass
        with pytest.raises(AssertionError, match=r'urllib: https://example\.invalid/swallowed'):
            guard.assert_clean()
        assert len(guard.claim()) == 1
        guard.assert_clean()


def test_an_attempt_in_a_worker_thread_is_recorded():
    def worker():
        try:
            socket.getaddrinfo('example.invalid', 80)
        except Exception:  # noqa: BLE001 - a thread's failure never reaches the test
            pass

    with NetworkGuard() as guard:
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        assert [(a.kind, a.target) for a in guard.claim()] == [('lookup', 'example.invalid:80')]


@pytest.fixture
def listener():
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        yield server


def test_loopback_is_refused_by_default(listener):
    with NetworkGuard() as guard:
        with pytest.raises(NetworkAttempt), socket.socket() as client:
            client.connect(listener.getsockname())
        assert [a.kind for a in guard.claim()] == ['connect']


def test_loopback_is_allowed_on_request_and_nothing_else_is(listener):
    with NetworkGuard(allow_loopback=True) as guard:
        with socket.socket() as client:
            client.connect(listener.getsockname())
        with pytest.raises(NetworkAttempt):
            _tcp_connect()
        assert [a.kind for a in guard.claim()] == ['connect']


@pytest.mark.skipif(not hasattr(socket, 'AF_UNIX'), reason='this platform has no AF_UNIX sockets')
def test_a_local_unix_socket_is_not_network(tmp_path):
    path = str(tmp_path / 's')
    with socket.socket(socket.AF_UNIX) as server, socket.socket(socket.AF_UNIX) as client:
        server.bind(path)
        server.listen(1)
        with NetworkGuard() as guard:
            client.connect(path)
            assert guard.attempts == []


@pytest.mark.parametrize(('host', 'loopback'), [
    ('localhost', True), ('LocalHost', True), ('127.0.0.1', True), ('127.0.0.2', True), ('::1', True),
    ('0.0.0.0', False), ('192.0.2.1', False), ('example.invalid', False), ('::ffff:127.0.0.1', False),
    ('', False), (None, False), (b'127.0.0.1', True),
], ids=['localhost', 'mixed-case', 'v4', 'v4-other', 'v6', 'any-address', 'documentation', 'name',
        'v4-mapped', 'empty', 'none', 'bytes'])
def test_loopback_classification_does_not_depend_on_the_interpreter(host, loopback):
    assert is_loopback_host(host) is loopback


def test_the_guard_restores_everything_on_exit(listener):
    originals = (socket.socket.connect, urllib.request.OpenerDirector.open, http.client.HTTPConnection.connect)
    with NetworkGuard():
        assert socket.socket.connect is not originals[0]
    assert (socket.socket.connect, urllib.request.OpenerDirector.open,
            http.client.HTTPConnection.connect) == originals
    with socket.socket() as client:  # the audit hook stays installed for the process but is inert
        client.connect(listener.getsockname())
    with NetworkGuard() as second:  # and a later guard arms normally
        assert second.attempts == []


def test_guards_do_not_nest():
    with NetworkGuard(), pytest.raises(RuntimeError, match='already armed'), NetworkGuard():
        pass


def test_the_fixture_arms_a_guard_and_a_swallowed_attempt_fails_the_test(tmp_path):
    source = textwrap.dedent('''
        import urllib.request

        from network_guard import network_guard_fixture  # noqa: F401


        def test_claimed(network_guard):
            try:
                urllib.request.urlopen('https://example.invalid/claimed')
            except AssertionError:
                pass
            assert [a.target for a in network_guard.claim()] == ['https://example.invalid/claimed']


        def test_clean(network_guard):
            assert network_guard.attempts == []


        def test_swallowed(network_guard):
            try:
                urllib.request.urlopen('https://example.invalid/swallowed')
            except Exception:
                pass


        def test_uncaught(network_guard):
            urllib.request.urlopen('https://example.invalid/uncaught')
    ''')
    (tmp_path / 'test_inner.py').write_text(source, encoding='utf-8', newline='\n')
    env = {**os.environ, 'PYTHONPATH': str(TESTS_DIR), 'PYTEST_DISABLE_PLUGIN_AUTOLOAD': '1'}
    done = subprocess.run([sys.executable, '-m', 'pytest', '-q', '-rA', '-p', 'no:cacheprovider', 'test_inner.py'],
                          cwd=tmp_path, env=env, capture_output=True, text=True, timeout=120, check=False)
    rows = (line.split()[:2] for line in done.stdout.splitlines() if line.startswith(('PASSED ', 'FAILED ', 'ERROR ')))
    outcomes = {(status, node.split('::')[-1]) for status, node in rows}
    # A swallowed attempt passes the call phase and errors at teardown; an uncaught one fails the call phase and
    # its record, still unclaimed, errors at teardown as well.
    assert outcomes == {('PASSED', 'test_claimed'), ('PASSED', 'test_clean'), ('PASSED', 'test_swallowed'),
                        ('ERROR', 'test_swallowed'), ('FAILED', 'test_uncaught'), ('ERROR', 'test_uncaught')}, \
        done.stdout
    assert 'urllib: https://example.invalid/swallowed' in done.stdout
