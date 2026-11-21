"""Actual-source deadline regressions for a stalled HTTP body read."""
import http.server
import threading
import time
import urllib.request

import pytest

from patchtrace import netutil


class StallingBody:
    def __init__(self, released):
        self.released = released
        self.calls = 0

    def read(self, size):
        self.calls += 1
        if self.calls == 1:
            return b'first-byte'
        self.released.wait(2)
        return b''


def test_deadline_interrupts_blocked_body_without_cancel_event():
    released = threading.Event()
    timer = threading.Timer(0.7, released.set)
    timer.start()
    start = time.monotonic()
    try:
        with pytest.raises(netutil.DeadlineExceeded):
            netutil.read_bounded(StallingBody(released), 1024, deadline=start + 0.12,
                                 clock=time.monotonic, cancel=None)
        assert time.monotonic() - start < 0.5
    finally:
        released.set()
        timer.cancel()
        timer.join(timeout=2)


def test_deadline_interrupts_blocked_body_even_if_cancel_not_set():
    released = threading.Event()
    cancel = threading.Event()
    timer = threading.Timer(0.7, released.set)
    timer.start()
    start = time.monotonic()
    try:
        with pytest.raises(netutil.DeadlineExceeded):
            netutil.read_bounded(StallingBody(released), 1024, deadline=start + 0.12,
                                 clock=time.monotonic, cancel=cancel)
        assert time.monotonic() - start < 0.5
    finally:
        released.set()
        timer.cancel()
        timer.join(timeout=2)


def test_cancelled_read_keeps_cancelled_classification():
    released = threading.Event()
    cancel = threading.Event()
    timer = threading.Timer(0.05, cancel.set)
    timer.start()
    try:
        with pytest.raises(netutil.Cancelled):
            netutil.read_bounded(StallingBody(released), 1024, deadline=time.monotonic() + 5,
                                 clock=time.monotonic, cancel=cancel)
    finally:
        released.set()
        timer.cancel()
        timer.join(timeout=2)


def test_fast_body_and_size_cap_are_unchanged():
    class Body:
        def __init__(self):
            self.body = b'abcdef'

        def read(self, size):
            part, self.body = self.body[:size], self.body[size:]
            return part

    assert netutil.read_bounded(Body(), 6, deadline=time.monotonic() + 5,
                                clock=time.monotonic, cancel=None, chunk=2) == b'abcdef'
    with pytest.raises(netutil.CapExceeded):
        netutil.read_bounded(Body(), 2, deadline=time.monotonic() + 5,
                             clock=time.monotonic, cancel=None)


def test_completed_read_is_refused_if_deadline_passed_during_call():
    class Eof:
        def read(self, size):
            return b''

    clock_values = iter([0., 0., 10.])
    with pytest.raises(netutil.DeadlineExceeded):
        netutil.read_bounded(Eof(), 1024, deadline=5., clock=lambda: next(clock_values), cancel=None)


def test_real_http_stall_does_not_delay_deadline_or_response_close():
    released = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            self.send_response(200)
            self.send_header('Content-Length', '50')
            self.end_headers()
            self.wfile.write(b'A')
            self.wfile.flush()
            released.wait(2)
            try:
                self.wfile.write(b'B' * 49)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        response = urllib.request.urlopen(f'http://127.0.0.1:{server.server_port}/x', timeout=5)
        started = time.monotonic()
        try:
            with pytest.raises(netutil.DeadlineExceeded):
                netutil.read_bounded(response, 128, deadline=started + 0.15,
                                     clock=time.monotonic, cancel=None)
            assert time.monotonic() - started < 1.0
        finally:
            close_start = time.monotonic()
            response.close()
            assert time.monotonic() - close_start < 1.0
    finally:
        released.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
