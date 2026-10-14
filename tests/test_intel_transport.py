"""CSAF transport (SPEC-28 section D) with a FAKE opener only: no test opens a socket. Consent, allowlist,
redirect, size, retry, deadline, cancellation and offline-cache behaviour."""
from __future__ import annotations

import hashlib
import threading
from datetime import UTC, datetime

import pytest

from patchtrace.intelligence.contracts import IntelError
from patchtrace.intelligence.csaf import transport as tr

BASE = 'https://msrc.microsoft.com/csaf'
DOC = f'{BASE}/advisories/2099/pt-synth_cve-2099-10001.json'


class FakeResponse:
    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None, chunk: int = 7):
        self.status, self._body, self.headers, self._chunk = status, body, dict(headers or {}), chunk
        self.closed = False

    def read(self, size: int) -> bytes:
        piece, self._body = self._body[:min(size, self._chunk)], self._body[min(size, self._chunk):]
        return piece

    def close(self) -> None:
        self.closed = True


class FakeServer:
    """Routes URL -> list of responses (served in order, the last one repeats)."""

    def __init__(self, routes: dict):
        self.routes = {url: list(v) if isinstance(v, list) else [v] for url, v in routes.items()}
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        queue = self.routes.get(url)
        if not queue:
            return FakeResponse(404)
        spec = queue.pop(0) if len(queue) > 1 else queue[0]
        return spec() if callable(spec) else FakeResponse(*spec)


def transport(routes: dict, **kw) -> tuple[tr.CsafTransport, FakeServer]:
    server = FakeServer(routes)
    kw.setdefault('sleep', lambda seconds, cancel: None)
    kw.setdefault('now', lambda: datetime(2099, 3, 1, tzinfo=UTC))
    consent = kw.pop('consent', tr.CsafConsent.for_hosts(['msrc.microsoft.com']))
    return tr.CsafTransport(consent, opener=server, **kw), server


@pytest.mark.parametrize('url', [
    'http://msrc.microsoft.com/csaf/x.json', 'https://evil.example/csaf/x.json',
    'https://msrc.microsoft.com:8443/csaf/x.json', 'https://user:pw@msrc.microsoft.com/csaf/x.json',
    'https://msrc.microsoft.com/csaf/x.json?a=1', 'https://msrc.microsoft.com/csaf/x.json#frag',
    'https://msrc.microsoft.com/update-guide/x.json', 'https://msrc.microsoft.com/csaf/../secret.json',
    'https://msrc.microsoft.com/csaf/%2e%2e/x.json', 'https://msrc.microsoft.com/csaf/a b.json',
    'https://msrc.microsoft.com.evil.example/csaf/x.json',
])
def test_urls_outside_the_allowlist_are_refused_before_any_request(url):
    client, server = transport({})
    with pytest.raises(IntelError) as info:
        client.get(url, 'document')
    assert info.value.code == 'PT-INTEL-CONFIG' and server.calls == []


def test_consent_is_required_and_exact():
    with pytest.raises(IntelError):
        tr.CsafConsent.for_hosts(['msrc.microsoft.com', 'nvd.nist.gov'])
    with pytest.raises(IntelError):
        tr.CsafConsent.for_hosts([])
    with pytest.raises(IntelError) as info:
        tr.CsafTransport(None, opener=FakeServer({}))
    assert info.value.code == 'PT-INTEL-CONFIG'


def test_fetch_sends_only_fixed_headers_and_announces_each_request():
    seen = []
    client, server = transport({DOC: (200, b'{"x": 1}')}, announce=seen.append)
    fetched = client.get(DOC, 'document')
    assert fetched.body == b'{"x": 1}' and fetched.sha256 == hashlib.sha256(b'{"x": 1}').hexdigest()
    assert fetched.retrieved_at == '2099-03-01T00:00:00Z' and not fetched.from_cache
    ((url, headers, timeout),) = server.calls
    assert url == DOC and headers == {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
    assert timeout <= tr.CONNECT_TIMEOUT and seen == [f'GET {DOC}']


def test_redirects_are_rechecked_and_bounded():
    target = f'{BASE}/advisories/2099/moved.json'
    client, _ = transport({DOC: (302, b'', {'Location': '/csaf/advisories/2099/moved.json'}), target: (200, b'ok')})
    assert client.get(DOC, 'document').final_url == target
    client, _ = transport({DOC: (302, b'', {'Location': 'https://evil.example/csaf/x.json'})})
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-CONFIG'
    loop = {DOC: (302, b'', {'Location': DOC})}
    client, server = transport(loop)
    with pytest.raises(IntelError, match='redirects refused'):
        client.get(DOC, 'document')
    assert len(server.calls) == tr.MAX_REDIRECTS + 1


def test_size_caps_by_header_and_by_stream():
    client, _ = transport({DOC: (200, b'x', {'Content-Length': str(tr.CAPS['hash'] + 1)})})
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'hash')
    assert info.value.code == 'PT-INTEL-LIMIT'
    client, _ = transport({DOC: (200, b'y' * (tr.CAPS['hash'] + 1))})
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'hash')
    assert info.value.code == 'PT-INTEL-LIMIT'


def test_retries_with_bounded_retry_after():
    waits = []
    client, server = transport({DOC: [(503, b'', {'Retry-After': '2'}), (200, b'ok')]},
                               sleep=lambda seconds, cancel: waits.append(seconds))
    assert client.get(DOC, 'document').body == b'ok' and waits == [2.0] and len(server.calls) == 2
    client, _ = transport({DOC: (503, b'')})
    with pytest.raises(IntelError, match='after retries'):
        client.get(DOC, 'document')
    client, _ = transport({DOC: (429, b'', {'Retry-After': '120'})})
    with pytest.raises(IntelError, match='later than 60 s'):
        client.get(DOC, 'document')


def test_status_handling():
    client, _ = transport({DOC: (500, b'')})
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-PROVIDER'
    client, _ = transport({})
    assert client.get(DOC, 'document', allow_404=True) is None
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-NOTFOUND'


def test_connection_failure_and_deadline():
    def boom():
        raise ConnectionError('down')

    client, _ = transport({DOC: boom})
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-NETWORK'
    ticks = iter([0.0, 0.0] + [1000.0] * 20)
    client, _ = transport({DOC: (200, b'late')}, clock=lambda: next(ticks))
    with pytest.raises(IntelError, match='deadline'):
        client.get(DOC, 'document')


def test_cancellation_before_and_while_reading():
    cancel = threading.Event()
    cancel.set()
    client, server = transport({DOC: (200, b'x')}, cancel=cancel)
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-CANCEL' and server.calls == []

    cancel = threading.Event()

    class Slow(FakeResponse):
        def read(self, size):
            cancel.set()
            return super().read(size)
    client, _ = transport({DOC: lambda: Slow(200, b'abcdefghijklmnop')}, cancel=cancel)
    with pytest.raises(IntelError) as info:
        client.get(DOC, 'document')
    assert info.value.code == 'PT-INTEL-CANCEL'


def test_offline_cache_round_trip_without_network(tmp_path):
    cache = tr.OfflineCache(tmp_path / 'cache')
    online, _ = transport({DOC: (200, b'{"doc": 1}')}, cache=cache)
    online.get(DOC, 'document')
    offline_server = FakeServer({})
    offline = tr.CsafTransport(None, opener=offline_server, cache=cache, offline=True)
    hit = offline.get(DOC, 'document')
    assert hit.body == b'{"doc": 1}' and hit.from_cache and offline_server.calls == []
    with pytest.raises(IntelError) as info:
        offline.get(f'{BASE}/advisories/2099/other.json', 'document')
    assert info.value.code == 'PT-INTEL-NOTFOUND'
    (tmp_path / 'cache' / 'bodies' / hit.sha256).write_bytes(b'tampered')
    with pytest.raises(IntelError):
        offline.get(DOC, 'document')  # a body failing its hash counts as absent
    (tmp_path / 'cache' / 'urls.json').write_text('{not json', encoding='utf-8')
    assert tr.OfflineCache(tmp_path / 'cache').get(DOC) is None
    with pytest.raises(IntelError):
        tr.CsafTransport(None, opener=offline_server, offline=True)


def test_default_opener_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:3128')
    director = tr.build_director()  # an explicit empty ProxyHandler suppresses the environment-driven default
    assert not any(getattr(h, 'proxies', None) for h in director.handlers)
    assert not any(hasattr(h, 'https_open') and h.__class__.__name__ == 'ProxyHandler' for h in director.handlers)
