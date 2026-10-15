"""RA-3: a slow-drip server must not stretch a request deadline; real loopback sockets, no mocks."""
from __future__ import annotations

import http.server
import json
import threading
import time
import urllib.request

import pytest

from patchtrace import providers
from patchtrace.enrichment import intelligence as enrich
from patchtrace.enrichment.contracts import EnrichmentError
from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as csaf

DEADLINE = 2.0
INTERVAL = 0.5
BODY_BYTES = 24  # drips for ~12 s, six times the deadline
SLICE = 1.5  # allowed overshoot: one drip interval plus scheduling slack
DOC = 'https://msrc.microsoft.com/csaf/advisories/2099/pt-synth_cve-2099-10001.json'


class _Drip(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self._drip()

    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self._drip()

    def _drip(self):
        self.send_response(200)
        self.send_header('Content-Length', str(BODY_BYTES))
        self.end_headers()
        self.wfile.flush()
        try:
            for _ in range(BODY_BYTES):
                if self.server.stop.wait(INTERVAL):
                    return
                self.wfile.write(b'x')
                self.wfile.flush()
        except OSError:
            return

    def log_message(self, *args):
        pass


@pytest.fixture
def port():
    server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), _Drip)
    server.stop = threading.Event()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.stop.set()
    server.shutdown()
    server.server_close()


def _csaf_client(port, **kw):
    def opener(url, headers, timeout):
        return csaf._Response(urllib.request.urlopen(f'http://127.0.0.1:{port}/x', timeout=timeout))
    return csaf.CsafTransport(csaf.CsafConsent.for_hosts(['msrc.microsoft.com']), opener=opener, **kw)


def _csaf_call(port, cancel):
    _csaf_client(port, cancel=cancel).get(DOC, 'document')


def _enrich_call(port, cancel):
    def opener(url, headers, timeout):
        return enrich._UrllibResponse(urllib.request.urlopen(f'http://127.0.0.1:{port}/x', timeout=timeout))
    plan = enrich.plan_requests(['CVE-2099-10001'], ['msrc'])
    enrich.fetch(plan, enrich.FetchConsent.for_plan(plan), opener=opener, cancel=cancel)


def _provider_call(port, cancel):
    config = providers.ProviderConfig('ollama', f'http://127.0.0.1:{port}', 'm')
    providers.request_completion(config, 'system', json.dumps({'a': 1}), cancel)


@pytest.fixture(params=['csaf', 'enrichment', 'provider'])
def transport_call(request, monkeypatch):
    monkeypatch.setattr(csaf, 'REQUEST_DEADLINE', DEADLINE)
    monkeypatch.setattr(enrich, 'TOTAL_TIMEOUT', DEADLINE)
    monkeypatch.setattr(providers, 'TIMEOUT_SECONDS', DEADLINE)
    call = {'csaf': _csaf_call, 'enrichment': _enrich_call, 'provider': _provider_call}[request.param]
    errors = {'csaf': IntelError, 'enrichment': EnrichmentError, 'provider': providers.ProviderError}
    return call, errors[request.param]


def _run(call, port, cancel, trigger=None):
    outcome: dict = {}
    started = time.monotonic()

    def target():
        try:
            call(port, cancel)
        except BaseException as exc:  # noqa: BLE001 - asserted below
            outcome['error'] = exc
        outcome['elapsed'] = time.monotonic() - started
    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    if trigger is not None:
        time.sleep(trigger)
        cancel.set()
    thread.join(DEADLINE + 6 * INTERVAL + 8)
    assert not thread.is_alive()
    return outcome


def test_deadline_bounds_a_slow_drip(port, transport_call):
    call, error = transport_call
    outcome = _run(call, port, threading.Event())
    assert isinstance(outcome['error'], error)
    assert DEADLINE <= outcome['elapsed'] < DEADLINE + SLICE + 0.5


def test_cancel_interrupts_a_slow_drip(port, transport_call):
    call, error = transport_call
    outcome = _run(call, port, threading.Event(), trigger=0.7)
    assert isinstance(outcome['error'], error) and 'cancel' in str(outcome['error']).lower()
    assert outcome['elapsed'] < 0.7 + SLICE
