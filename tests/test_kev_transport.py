"""kev/1 transport: fixed URLs, same-host redirects only, bounded bodies, fixed headers, cancel and deadline."""
from __future__ import annotations

import datetime
import hashlib
import threading
import urllib.request

import pytest

from patchtrace.kev import limits
from patchtrace.kev.contracts import KevError, KevPlan
from patchtrace.kev.transport import KevConsent, KevTransport, build_director, check_url

SITE = limits.SOURCE_URLS['cisa-site']
MIRROR = limits.SOURCE_URLS['cisa-github']
NOW = datetime.datetime(2099, 3, 2, 8, 30, tzinfo=datetime.UTC)


class FakeResponse:
    def __init__(self, status=200, body=b'{}', headers=None, chunks=None):
        self.status, self.headers = status, dict(headers or {})
        self._body, self._chunks = bytearray(body), chunks
        self.closed = False
        self.reads = 0

    def read(self, size):
        self.reads += 1
        if self._chunks is not None:  # an endless stream
            return self._chunks[:size]
        out, self._body = bytes(self._body[:size]), self._body[size:]
        return out

    def close(self):
        self.closed = True


class Script:
    """An opener that serves queued responses and records every request."""

    def __init__(self, *responses):
        self.queue, self.calls = list(responses), []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        item = self.queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item


def transport(opener, source='cisa-site', **kwargs):
    plan = KevPlan.for_source(source)
    kwargs.setdefault('sleep', lambda _s, _c: None)
    kwargs.setdefault('now', lambda: NOW)
    return plan, KevTransport(KevConsent.from_plan(plan), opener=opener, **kwargs)


def code(info) -> str:
    return info.value.code


def test_transport_returns_body_hash_and_stamp():
    opener = Script(FakeResponse(body=b'{"a": 1}'))
    plan, tr = transport(opener)
    got = tr.fetch(plan)
    assert got.body == b'{"a": 1}'
    assert got.sha256 == hashlib.sha256(b'{"a": 1}').hexdigest()
    assert got.url == got.final_url == SITE
    assert got.retrieved_at == '2099-03-02T08:30:00Z'
    assert opener.calls[0][0] == SITE
    assert tr.requests == [SITE]


def test_transport_sends_only_fixed_headers_and_ignores_proxies(monkeypatch):
    opener = Script(FakeResponse())
    plan, tr = transport(opener)
    tr.fetch(plan)
    assert opener.calls[0][1] == {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
    for name in ('HTTPS_PROXY', 'https_proxy'):
        monkeypatch.setenv(name, 'http://proxy.invalid:3128')
    handlers = build_director().handlers
    # The explicit empty ProxyHandler replaces the default one, so no handler routes through the environment proxy.
    assert urllib.request.getproxies().get('https') == 'http://proxy.invalid:3128'
    assert not any(isinstance(h, urllib.request.ProxyHandler) and h.proxies for h in handlers)
    assert not any(h.__class__.__name__ == 'ProxyHandler' for h in handlers)


def test_request_is_announced_before_it_is_sent():
    events = []

    def opener(url, headers, timeout):
        events.append('open')
        return FakeResponse()

    plan, tr = transport(opener, announce=events.append)
    tr.fetch(plan)
    assert events == [f'GET {SITE}', 'open']


@pytest.mark.parametrize('location', [
    'https://evil.example/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
    'http://www.cisa.gov/feeds/x.json',
    'https://www.cisa.gov:8443/feeds/x.json',
    'https://user@www.cisa.gov/feeds/x.json',
    'https://www.cisa.gov/feeds/x.json?token=1',
], ids=['foreign', 'other-allowed-host', 'http', 'port', 'userinfo', 'query'])
def test_transport_refuses_cross_host_redirect(location):
    opener = Script(FakeResponse(302, headers={'Location': location}), FakeResponse())
    plan, tr = transport(opener)
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-CONSENT'
    assert len(opener.calls) == 1


def test_same_host_redirect_is_followed_and_recorded():
    opener = Script(FakeResponse(301, headers={'Location': '/feeds/moved.json'}), FakeResponse(body=b'[]'))
    plan, tr = transport(opener)
    got = tr.fetch(plan)
    assert got.final_url == 'https://www.cisa.gov/feeds/moved.json'
    assert got.url == SITE


def test_more_than_two_redirects_are_refused():
    hop = {'Location': '/a.json'}
    opener = Script(*[FakeResponse(302, headers=hop) for _ in range(4)])
    plan, tr = transport(opener)
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-NETWORK'
    assert len(opener.calls) == 3


def test_redirect_without_location_is_a_provider_error():
    plan, tr = transport(Script(FakeResponse(302)))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-PROVIDER'


def test_transport_caps_body_and_lying_content_length():
    declared = FakeResponse(headers={'Content-Length': str(limits.MAX_BYTES + 1)})
    plan, tr = transport(Script(declared))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-LIMIT'
    assert declared.reads == 0 and declared.closed

    lying = FakeResponse(headers={'Content-Length': '10'}, chunks=b'0' * 65536)
    plan, tr = transport(Script(lying))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-LIMIT'
    assert lying.reads <= limits.MAX_BYTES // 65536 + 2


def test_exact_cap_is_accepted():
    plan, tr = transport(Script(FakeResponse(body=b'0' * limits.MAX_BYTES)))
    assert len(tr.fetch(plan).body) == limits.MAX_BYTES


def test_status_errors():
    plan, tr = transport(Script(FakeResponse(404)))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-PROVIDER'
    assert 'HTTP 404' in info.value.message


def test_retry_after_then_success():
    waits = []
    opener = Script(FakeResponse(503, headers={'Retry-After': '7'}), FakeResponse(429), FakeResponse(body=b'ok'))
    plan, tr = transport(opener, sleep=lambda s, _c: waits.append(s))
    assert tr.fetch(plan).body == b'ok'
    assert waits == [7.0, 2.0]


def test_three_unavailable_answers_fail():
    plan, tr = transport(Script(*[FakeResponse(503) for _ in range(3)]))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-NETWORK'


def test_retry_after_beyond_sixty_seconds_is_refused():
    opener = Script(FakeResponse(503, headers={'Retry-After': '61'}))
    plan, tr = transport(opener)
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-NETWORK'
    assert len(opener.calls) == 1


@pytest.mark.parametrize('failure', [ConnectionError('x'), TimeoutError('t')], ids=['connection', 'timeout'])
def test_connection_failures_are_network_errors(failure):
    plan, tr = transport(Script(*[failure] * 3))
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-NETWORK'


def test_consent_must_cover_the_plan():
    plan = KevPlan.for_source('cisa-github')
    tr = KevTransport(KevConsent.from_plan(KevPlan.for_source('cisa-site')), opener=Script())
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-CONSENT'


def test_mirror_plan_uses_its_own_host_for_redirects():
    opener = Script(FakeResponse(302, headers={'Location': 'https://www.cisa.gov/x.json'}))
    plan, tr = transport(opener, source='cisa-github')
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-CONSENT'


@pytest.mark.parametrize('url', [SITE, MIRROR], ids=['site', 'mirror'])
def test_check_url_admits_the_two_fixed_urls(url):
    assert check_url(url) == url.split('/')[2]


@pytest.mark.parametrize('url', [
    'http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov/other.json', SITE + '?x=1', SITE + '#f', 'https://x@www.cisa.gov/y', 'ftp://www.cisa.gov/x',
    'https://www.cisa.gov:444/x', 'https://evil.example/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov/a b',
], ids=['http', 'path', 'query', 'fragment', 'userinfo', 'scheme', 'port', 'host', 'space'])
def test_check_url_refuses_everything_else(url):
    with pytest.raises(KevError):
        check_url(url)


class Blocking:
    """A response whose second read blocks like a silent server until ``abort`` wakes it."""

    status, headers = 200, {}

    def __init__(self, before_block):
        self.before_block, self.gate, self.aborted, self.n = before_block, threading.Event(), False, 0

    def read(self, size):
        self.n += 1
        if self.n == 1:
            return b'x'
        self.before_block()
        self.gate.wait(10)
        if self.aborted:
            raise OSError('aborted')
        return b''

    def abort(self):
        self.aborted = True
        self.gate.set()

    def close(self):
        pass


def test_cancel_aborts_a_blocked_read():
    cancel = threading.Event()
    response = Blocking(cancel.set)
    plan, tr = transport(Script(response), cancel=cancel)
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-CANCEL'
    assert response.aborted


def test_deadline_aborts_a_blocked_read():
    ticks = {'now': 0.0}
    response = Blocking(lambda: ticks.update(now=1000.0))
    plan, tr = transport(Script(response), clock=lambda: ticks['now'])
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-NETWORK'
    assert response.aborted


def test_cancel_before_start_sends_nothing():
    cancel = threading.Event()
    cancel.set()
    opener = Script(FakeResponse())
    plan, tr = transport(opener, cancel=cancel)
    with pytest.raises(KevError) as info:
        tr.fetch(plan)
    assert code(info) == 'PT-KEV-CANCEL'
    assert opener.calls == []
