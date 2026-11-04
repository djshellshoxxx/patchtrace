"""CSAF transport against a real loopback socket that drips one byte at a time (random audit RA-3).

`test_intel_transport.py` proves the deadline with a fake clock only. Here the production `urllib_open` reads from
`drip_server` on 127.0.0.1, so the per-read deadline and cancellation checks are exercised on a real socket: a
server that keeps every recv alive can no longer hold a read open. No other host is reachable from these tests."""
from __future__ import annotations

import socket
import threading
import time

import pytest
from drip_server import drip_server

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as tr

DOC = 'https://msrc.microsoft.com/csaf/advisories/2099/pt-synth_cve-2099-10001.json'


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    real = socket.create_connection

    def connect(address, *args, **kwargs):
        if address[0] != '127.0.0.1':
            raise AssertionError(f'a test tried to reach {address[0]}')
        return real(address, *args, **kwargs)
    monkeypatch.setattr(socket, 'create_connection', connect)


@pytest.fixture
def dripping():
    url, close = drip_server(40, 0.2)  # 8 s of dripping
    yield url
    close()


class CancelAfterFirstRead:
    """The real response; the analyst cancels as soon as the first dripped byte has arrived."""

    def __init__(self, response, cancel: threading.Event):
        self._response, self._cancel = response, cancel
        self.status, self.headers = response.status, response.headers

    def read(self, size: int) -> bytes:
        return self._response.read(size)

    def read1(self, size: int) -> bytes:
        piece = self._response.read1(size)
        self._cancel.set()
        return piece

    def close(self) -> None:
        self._response.close()


def client(local: str, **kw) -> tr.CsafTransport:
    def opener(_url, headers, timeout):
        return tr.urllib_open(local, headers, timeout)
    return tr.CsafTransport(tr.CsafConsent.for_hosts(['msrc.microsoft.com']), opener=kw.pop('opener', opener), **kw)


def test_a_slow_drip_cannot_hold_a_read_past_the_deadline(dripping):
    started = time.monotonic()
    transport = client(dripping, plan_deadline=1.0)
    with pytest.raises(IntelError) as caught:
        transport.get(DOC, 'document')
    elapsed = time.monotonic() - started
    assert caught.value.code == 'PT-INTEL-NETWORK' and 'deadline' in caught.value.message
    assert 1.0 <= elapsed < 4.0, elapsed


def test_cancel_during_a_slow_drip_stops_the_read(dripping):
    cancel = threading.Event()

    def opener(_url, headers, timeout):
        return CancelAfterFirstRead(tr.urllib_open(dripping, headers, timeout), cancel)
    started = time.monotonic()
    with pytest.raises(IntelError) as caught:
        client(dripping, opener=opener, cancel=cancel).get(DOC, 'document')
    assert caught.value.code == 'PT-INTEL-CANCEL' and cancel.is_set()
    assert time.monotonic() - started < 4.0
