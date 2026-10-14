"""H9: blocking network calls observe cancel within a fraction of a second (SPEC-07h)."""
import threading
import time
import urllib.request

import pytest

from patchtrace import netutil, providers
from patchtrace.enrichment import intelligence as it
from patchtrace.enrichment.contracts import EnrichmentError

CVE = 'CVE-2024-38063'


def _cancel_soon(cancel, delay=0.1):
    threading.Timer(delay, cancel.set).start()


def _plan():
    plan = it.plan_requests([CVE], ('msrc',))
    return plan, it.FetchConsent.for_plan(plan)


def test_blocked_opener_is_abandoned_on_cancel_and_closed_later():
    release = threading.Event()
    late = []

    class Resp:
        status = 200
        headers = {}

        def read(self, size):
            return b''

        def close(self):
            late.append('closed')

    def opener(url, headers, timeout):
        release.wait(10)
        return Resp()

    cancel = threading.Event()
    plan, consent = _plan()
    _cancel_soon(cancel)
    start = time.monotonic()
    with pytest.raises(EnrichmentError) as exc:
        it.fetch(plan, consent, opener=opener, cancel=cancel)
    assert exc.value.code == 'PT-ENRICH-CANCEL' and time.monotonic() - start < 0.5
    release.set()
    deadline = time.monotonic() + 2
    while not late and time.monotonic() < deadline:
        time.sleep(0.01)
    assert late == ['closed']
    deadline = time.monotonic() + 2
    while netutil.abandoned_count() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert netutil.abandoned_count() == 0


def test_blocked_read_is_cancelled_and_response_closed():
    release = threading.Event()
    closed = threading.Event()

    class Resp:
        status = 200
        headers = {}

        def read(self, size):
            release.wait(10)
            return b''

        def close(self):
            closed.set()
            release.set()

    cancel = threading.Event()
    plan, consent = _plan()
    _cancel_soon(cancel)
    start = time.monotonic()
    with pytest.raises(EnrichmentError) as exc:
        it.fetch(plan, consent, opener=lambda *a: Resp(), cancel=cancel)
    assert exc.value.code == 'PT-ENRICH-CANCEL' and time.monotonic() - start < 0.5
    assert closed.wait(1)


def test_interruptible_caps_abandoned_threads():
    release = threading.Event()
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(netutil.Cancelled):
        netutil.interruptible(lambda: 1, cancel)
    cancel.clear()
    threads = []
    for _ in range(netutil.MAX_ABANDONED):
        local = threading.Event()
        threading.Timer(0.05, local.set).start()
        with pytest.raises(netutil.Cancelled):
            netutil.interruptible(lambda: release.wait(10), local, poll=0.01)
    with pytest.raises(netutil.TooManyAbandoned):
        netutil.interruptible(lambda: 1, threading.Event())
    release.set()
    deadline = time.monotonic() + 2
    while netutil.abandoned_count() and time.monotonic() < deadline:
        time.sleep(0.01)
    assert netutil.abandoned_count() == 0 and threads == []


def test_provider_completion_cancel_latency(monkeypatch):
    release = threading.Event()

    class FakeOpener:
        def open(self, request, timeout=None):
            release.wait(10)
            raise OSError('released')

    monkeypatch.setattr(urllib.request, 'build_opener', lambda *a, **k: FakeOpener())
    config = providers.ProviderConfig('ollama', 'http://127.0.0.1:11434', 'm')
    cancel = threading.Event()
    _cancel_soon(cancel)
    start = time.monotonic()
    with pytest.raises(providers.ProviderCancelled):
        providers.request_completion(config, 'system', 'context', cancel)
    assert time.monotonic() - start < 0.5
    release.set()
