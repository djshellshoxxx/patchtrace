"""kev/1 transport (KEV-integration-plan section 7): consent, URL allowlist, redirects, size caps, bounded time, fixed
headers, no environment proxies. Fake openers serve almost every case. The real-socket tests talk to a loopback server
only (the autouse guard refuses every other address), so nothing here can reach a network."""
from __future__ import annotations

import email.utils
import hashlib
import http.client
import socket
import threading
import time
import urllib.request
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from patchtrace import netutil
from patchtrace.kev import limits
from patchtrace.kev import transport as tr
from patchtrace.kev.contracts import KevError, plan_for

SITE, MIRROR = plan_for('cisa-site'), plan_for('cisa-github')
FIXED = {'Accept': 'application/json', 'User-Agent': 'PatchTrace'}
STAMP = datetime(2099, 3, 2, 8, 0, tzinfo=UTC)
CAP = limits.MAX_CATALOG_BYTES
LOOPBACK = {'127.0.0.1', '::1', 'localhost'}


@pytest.fixture(autouse=True)
def loopback_only(monkeypatch):
    connect, resolve = socket.socket.connect, socket.getaddrinfo

    def guarded_connect(self, address):
        if address[0] not in LOOPBACK:
            raise AssertionError(f'KEV tests may only reach loopback, not {address[0]}')
        return connect(self, address)

    def guarded_resolve(host, *args, **kwargs):
        if host not in LOOPBACK:
            raise AssertionError(f'KEV tests may only resolve loopback, not {host}')
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket.socket, 'connect', guarded_connect)
    monkeypatch.setattr(socket, 'getaddrinfo', guarded_resolve)


# --- fakes ----------------------------------------------------------------------------------------------------

class FakeResponse:
    """Serves ``body`` in pieces of at most ``chunk`` bytes through ``read1`` only: it has no ``read``, so a transport
    that blocks on a full chunk cannot even be written against it."""

    def __init__(self, status: int, body: bytes = b'', headers: dict | None = None, chunk: int = 7,
                 on_read=None):
        self.status, self._body, self.headers, self._chunk = status, body, dict(headers or {}), chunk
        self.closed, self.reads, self._on_read = False, 0, on_read

    def read1(self, size: int) -> bytes:
        self.reads += 1
        if self._on_read is not None:
            self._on_read(self.reads)
        piece, self._body = self._body[:min(size, self._chunk)], self._body[min(size, self._chunk):]
        return piece

    def close(self) -> None:
        self.closed = True


class FakeServer:
    """Routes URL -> responses served in order (the last one repeats); a callable builds the response, an exception
    class or instance is raised."""

    def __init__(self, routes: dict):
        self.routes = {url: list(v) if isinstance(v, list) else [v] for url, v in routes.items()}
        self.calls: list[tuple[str, dict, float]] = []

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers), timeout))
        queue = self.routes.get(url)
        if not queue:
            return FakeResponse(404)
        spec = queue.pop(0) if len(queue) > 1 else queue[0]
        if isinstance(spec, BaseException) or (isinstance(spec, type) and issubclass(spec, BaseException)):
            raise spec
        return spec() if callable(spec) else FakeResponse(*spec)


class Clock:
    """A monotonic clock that only moves when told to."""

    def __init__(self, start: float = 1000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now


def transport(routes: dict, plan=MIRROR, **kw) -> tuple[tr.KevTransport, FakeServer]:
    server = FakeServer(routes)
    kw.setdefault('sleep', lambda seconds, cancel: None)
    kw.setdefault('now', lambda: STAMP)
    consent = kw.pop('consent', tr.KevConsent.for_plan(plan))
    return tr.KevTransport(consent, opener=server, **kw), server


def code_of(call, *args) -> KevError:
    with pytest.raises(KevError) as info:
        call(*args)
    return info.value


# --- consent and the URL allowlist ----------------------------------------------------------------------------

def test_consent_is_built_from_a_displayed_plan_and_names_only_fixed_urls():
    assert tr.KevConsent.for_plan(SITE).urls == frozenset({SITE.url})
    assert tr.KevConsent.for_plan(MIRROR).urls == frozenset({MIRROR.url})
    for urls in (frozenset(), frozenset({'https://evil.example/known_exploited_vulnerabilities.json'}),
                 frozenset({SITE.url, 'https://www.cisa.gov/other.json'})):
        error = code_of(tr.KevConsent, urls)
        assert error.code == 'PT-KEV-CONSENT' and error.exit_code == 2


def test_a_plan_the_consent_does_not_cover_is_refused_before_any_request():
    client, server = transport({}, plan=MIRROR)
    error = code_of(client.fetch, SITE)
    assert error.code == 'PT-KEV-CONSENT' and server.calls == []


@pytest.mark.parametrize('url', [
    'http://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://WWW.CISA.GOV/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov./sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov:443/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov:8443/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://user:pw@www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json?x=1',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json#x',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.csv',
    'https://www.cisa.gov/sites/default/files/feeds/../feeds/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json ',
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json\n',
    'https://www.cisa.gov.evil.example/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
    '', 'https://www.cisa.gov',
], ids=['http', 'upper-host', 'trailing-dot', 'port-443', 'port-8443', 'userinfo', 'query', 'fragment', 'csv',
        'dot-segments', 'trailing-space', 'newline', 'suffix-host', 'other-source', 'empty', 'no-path'])
def test_only_the_exact_fixed_url_the_consent_names_is_requested(url):
    consent = tr.KevConsent.for_plan(SITE)
    assert tr.check_request(SITE.url, consent) == 'www.cisa.gov'
    error = code_of(tr.check_request, url, consent)
    assert error.code == 'PT-KEV-CONSENT'


# --- redirects ------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('target', [
    'https://evil.example/known_exploited_vulnerabilities.json',
    'https://www.cisa.gov.evil.example/known_exploited_vulnerabilities.json',
    'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json',
    '//evil.example/known_exploited_vulnerabilities.json',
    'http://www.cisa.gov/known_exploited_vulnerabilities.json',
], ids=['other-host', 'suffix-host', 'other-source-host', 'scheme-relative', 'downgrade'])
def test_transport_refuses_cross_host_redirect(target):
    announced = []
    client, server = transport({SITE.url: (302, b'', {'Location': target})}, plan=SITE, announce=announced.append)
    error = code_of(client.fetch, SITE)
    assert error.code == 'PT-KEV-PROVIDER' and error.exit_code == 3
    assert [call[0] for call in server.calls] == [SITE.url] and announced == [f'GET {SITE.url}']


@pytest.mark.parametrize('target', [
    'https://www.cisa.gov:443/x.json', 'https://www.cisa.gov:8443/x.json', 'https://user@www.cisa.gov/x.json',
    'https://www.cisa.gov/x.json?a=1', 'https://www.cisa.gov/x.json#a', 'https://WWW.CISA.GOV/x.json',
    'https://www.cisa.gov/a b.json', 'https://www.cisa.gov/a\\b.json', 'https://www.cisa.gov/' + chr(0xe9) + '.json',
    'https://www.cisa.gov/x.json\r\nX-Evil: 1', 'ftp://www.cisa.gov/x.json', 'https://www.cisa.gov/' + 'a' * 600,
], ids=['port-443', 'port-8443', 'userinfo', 'query', 'fragment', 'upper-host', 'space', 'backslash', 'non-ascii',
        'header-injection', 'ftp', 'too-long'])
def test_a_redirect_target_must_be_a_plain_same_host_https_address(target):
    assert tr.check_redirect('https://www.cisa.gov/new/x.json', 'www.cisa.gov') == 'https://www.cisa.gov/new/x.json'
    error = code_of(tr.check_redirect, target, 'www.cisa.gov')
    assert error.code == 'PT-KEV-PROVIDER'


def test_same_host_redirects_are_followed_twice_and_announced_before_they_are_sent():
    events, second = [], 'https://www.cisa.gov/sites/default/files/feeds/moved/known_exploited_vulnerabilities.json'
    server = FakeServer({SITE.url: (301, b'', {'Location': '/sites/default/files/feeds/moved/a.json'}),
                         'https://www.cisa.gov/sites/default/files/feeds/moved/a.json': (
                             302, b'', {'Location': second}),
                         second: (200, b'{}')})
    opener = lambda url, headers, timeout: (events.append(f'open {url}'), server(url, headers, timeout))[1]  # noqa: E731
    client = tr.KevTransport(tr.KevConsent.for_plan(SITE), opener=opener, announce=lambda m: events.append(m),
                             now=lambda: STAMP)
    fetched = client.fetch(SITE)
    assert (fetched.url, fetched.final_url, fetched.body) == (SITE.url, second, b'{}')
    urls = [call[0] for call in server.calls]
    assert events == [item for url in urls for item in (f'GET {url}', f'open {url}')]
    assert len(urls) == 3


def test_a_third_redirect_a_loop_and_a_redirect_without_an_address_are_refused():
    loop = {MIRROR.url: (302, b'', {'Location': MIRROR.url})}
    client, server = transport(loop)
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-PROVIDER' and 'redirects' in error.message
    assert len(server.calls) == limits.MAX_REDIRECTS + 1
    client, _ = transport({MIRROR.url: (302, b'', {})})
    assert code_of(client.fetch, MIRROR).code == 'PT-KEV-PROVIDER'


# --- fixed headers, announcement, provenance ------------------------------------------------------------------

def test_transport_sends_only_fixed_headers_and_ignores_proxies():
    events = []
    server = FakeServer({MIRROR.url: (200, b'{"a": 1}')})
    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=server, now=lambda: STAMP,
                             announce=lambda message: events.append((message, len(server.calls))))
    fetched = client.fetch(MIRROR)
    assert fetched.body == b'{"a": 1}' and fetched.sha256 == hashlib.sha256(b'{"a": 1}').hexdigest()
    assert (fetched.url, fetched.final_url, fetched.retrieved_at) == (MIRROR.url, MIRROR.url, '2099-03-02T08:00:00Z')
    ((url, headers, timeout),) = server.calls
    assert url == MIRROR.url and headers == FIXED and 0 < timeout <= limits.CONNECT_TIMEOUT_S
    assert events == [(f'GET {MIRROR.url}', 0)]          # announced before the opener was called


def test_each_request_gets_its_own_copy_of_the_fixed_headers():
    seen = []

    def careless(url, headers, timeout):
        seen.append(dict(headers))
        headers['Cookie'] = 'x'                       # an opener that changes what it was given must not reach the next hop
        return FakeResponse(302, b'', {'Location': '/b.json'}) if len(seen) == 1 else FakeResponse(200, b'ok')
    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=careless, now=lambda: STAMP)
    assert client.fetch(MIRROR).body == b'ok'
    assert seen == [FIXED, FIXED] and MIRROR.headers == FIXED


def test_default_opener_ignores_environment_proxies(monkeypatch):
    monkeypatch.setenv('HTTPS_PROXY', 'http://proxy.invalid:3128')
    director = tr.build_director()
    # An explicit empty ProxyHandler has no *_open method, so the opener does not register it, and its presence in the
    # argument list is what stops urllib from adding the environment-driven default; the wire test below proves it.
    assert not any(isinstance(h, urllib.request.ProxyHandler) for h in director.handlers)
    assert any(isinstance(h, tr._NoRedirect) for h in director.handlers)


def test_the_content_type_is_ignored_and_the_body_is_returned_whole():
    body = b'{"count": 0}' * 50
    client, _ = transport({MIRROR.url: (200, body, {'Content-Type': 'text/plain; charset=utf-8',
                                                     'Content-Length': str(len(body))}, 4096)})
    assert client.fetch(MIRROR).body == body


@pytest.mark.parametrize('encoding', ['gzip', 'br', 'deflate'])
def test_an_encoded_body_that_was_not_asked_for_is_refused(encoding):
    client, _ = transport({MIRROR.url: (200, b'x', {'Content-Encoding': encoding})})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-PROVIDER' and 'encoded' in error.message
    client, _ = transport({MIRROR.url: (200, b'ok', {'Content-Encoding': 'identity'})})
    assert client.fetch(MIRROR).body == b'ok'


def test_response_adapter_reads_status_from_code_for_http_errors():
    raw = SimpleNamespace(code=404, headers={'A': 'b'}, close=lambda: None)
    assert tr.Response(raw).status == 404 and tr.Response(raw).headers == {'A': 'b'}


# --- size caps ------------------------------------------------------------------------------------------------

class NeverRead(FakeResponse):
    def read1(self, size):
        raise AssertionError('the body must not be read when the header already exceeds the cap')


@pytest.mark.parametrize('length', [str(CAP + 1), '9' * 20, ' ' + str(CAP + 5) + ' '],
                         ids=['one-over', 'absurd', 'padded'])
def test_a_content_length_above_the_cap_is_refused_before_the_body_is_read(length):
    client, _ = transport({MIRROR.url: lambda: NeverRead(200, b'x', {'Content-Length': length})})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-LIMIT' and error.exit_code == 3


@pytest.mark.parametrize('headers', [{}, {'Content-Length': 'abc'}, {'Content-Length': '-1'}, {'Content-Length': '1,2'}],
                         ids=['no-header', 'not-a-number', 'negative', 'list'])
def test_transport_caps_body_and_lying_content_length(headers):
    """A header that says nothing usable cannot lift the cap: the stream itself is counted."""
    client, _ = transport({MIRROR.url: (200, b'y' * (CAP + 1), headers, 1 << 16)})
    assert code_of(client.fetch, MIRROR).code == 'PT-KEV-LIMIT'


def test_chunked_transfer_ignores_a_content_length_header_as_http_client_does():
    client, _ = transport({MIRROR.url: (200, b'z' * 100, {'Transfer-Encoding': 'chunked', 'Content-Length': '5'})})
    assert client.fetch(MIRROR).body == b'z' * 100


def test_a_body_longer_than_its_content_length_is_cut_at_the_first_excess_chunk():
    response = FakeResponse(200, b'y' * (CAP + 1), {'Content-Length': '5'}, chunk=1 << 16)
    client, _ = transport({MIRROR.url: lambda: response})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and response.reads == 1 and response.closed


def test_a_body_of_exactly_the_cap_is_accepted():
    body = b'z' * CAP
    client, _ = transport({MIRROR.url: (200, body, {'Content-Length': str(CAP)}, 1 << 16)})
    assert len(client.fetch(MIRROR).body) == CAP


@pytest.mark.parametrize('declared, body', [('1000', b'x' * 100), ('10', b'x' * 100)], ids=['short', 'long'])
def test_a_body_that_does_not_match_its_content_length_is_a_network_error(declared, body):
    client, _ = transport({MIRROR.url: (200, body, {'Content-Length': declared})})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and error.recoverable


def test_reading_stops_as_soon_as_the_announced_length_has_arrived():
    response = FakeResponse(200, b'abcd', {'Content-Length': '4'}, chunk=4)
    client, _ = transport({MIRROR.url: lambda: response})
    assert client.fetch(MIRROR).body == b'abcd' and response.reads == 1 and response.closed


# --- status handling and retries ------------------------------------------------------------------------------

@pytest.mark.parametrize('status', [429, 502, 503, 504])
def test_retryable_statuses_wait_as_told_and_then_succeed(status):
    waits = []
    client, server = transport({MIRROR.url: [(status, b'', {'Retry-After': '2'}), (200, b'ok')]},
                               sleep=lambda seconds, cancel: waits.append(seconds))
    assert client.fetch(MIRROR).body == b'ok' and waits == [2.0] and len(server.calls) == 2


def test_without_retry_after_the_waits_double_and_three_attempts_are_the_most():
    waits = []
    client, server = transport({MIRROR.url: [(503, b''), (503, b''), (200, b'ok')]},
                               sleep=lambda seconds, cancel: waits.append(seconds))
    assert client.fetch(MIRROR).body == b'ok' and waits == [1.0, 2.0] and len(server.calls) == 3
    waits.clear()
    client, server = transport({MIRROR.url: (503, b'')}, sleep=lambda seconds, cancel: waits.append(seconds))
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and 'attempts' in error.message
    assert len(server.calls) == limits.ATTEMPTS and waits == [1.0, 2.0]


def test_retry_after_may_be_a_date_and_is_never_longer_than_sixty_seconds():
    when = email.utils.format_datetime(STAMP + timedelta(seconds=3), usegmt=True)
    waits = []
    client, _ = transport({MIRROR.url: [(429, b'', {'Retry-After': when}), (200, b'ok')]},
                          sleep=lambda seconds, cancel: waits.append(seconds))
    assert client.fetch(MIRROR).body == b'ok' and waits == [4.0]
    for value in ('61', '120', '99999999999'):
        client, server = transport({MIRROR.url: (429, b'', {'Retry-After': value})},
                                   sleep=lambda seconds, cancel: pytest.fail('must not wait'))
        error = code_of(client.fetch, MIRROR)
        assert error.code == 'PT-KEV-NETWORK' and '60 seconds' in error.message and len(server.calls) == 1


def test_a_retry_after_of_exactly_sixty_seconds_is_waited_for():
    waits = []
    client, _ = transport({MIRROR.url: [(429, b'', {'Retry-After': '60'}), (200, b'ok')]},
                          sleep=lambda seconds, cancel: waits.append(seconds))
    assert client.fetch(MIRROR).body == b'ok' and waits == [60.0]


@pytest.mark.parametrize('deadline, started', [(30, False), (31, True)], ids=['ends-at-the-deadline', 'ends-before'])
def test_a_retry_is_started_only_when_it_ends_before_the_plan_deadline(deadline, started):
    waits = []
    client, _ = transport({MIRROR.url: (503, b'', {'Retry-After': '30'})}, clock=Clock(), plan_deadline=deadline,
                          sleep=lambda seconds, cancel: waits.append(seconds))
    error = code_of(client.fetch, MIRROR)
    assert (waits != []) is started and error.code == 'PT-KEV-NETWORK'
    assert ('attempts' in error.message) is started


def test_a_retry_that_would_pass_the_plan_deadline_is_not_started():
    clock = Clock()
    client, server = transport({MIRROR.url: (503, b'', {'Retry-After': '30'})}, clock=clock, plan_deadline=20)
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and 'time limit' in error.message and len(server.calls) == 1


@pytest.mark.parametrize('status', [400, 401, 403, 404, 410, 500, 304, 206],
                         ids=['400', '401', '403', '404', '410', '500', '304', '206'])
def test_other_statuses_are_not_retried_and_name_the_status(status):
    client, server = transport({MIRROR.url: (status, b'')})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-PROVIDER' and f'HTTP {status}' in error.message and len(server.calls) == 1


@pytest.mark.parametrize('failure', [TimeoutError('t'), ConnectionError('c'), OSError('o'),
                                     http.client.IncompleteRead(b'', 5), http.client.BadStatusLine('x')],
                         ids=['timeout', 'connection', 'oserror', 'incomplete', 'bad-status'])
def test_connection_problems_fail_once_and_can_be_retried_by_the_person(failure):
    client, server = transport({MIRROR.url: failure})
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and error.recoverable and len(server.calls) == 1


def test_a_failure_while_reading_the_body_is_a_network_error():
    def broken(reads):
        if reads == 2:
            raise ConnectionResetError('reset')
    client, _ = transport({MIRROR.url: lambda: FakeResponse(200, b'a' * 100, on_read=broken)})
    assert code_of(client.fetch, MIRROR).code == 'PT-KEV-NETWORK'


# --- time limits and cancellation -----------------------------------------------------------------------------

def test_the_deadline_is_checked_before_every_read():
    clock = Clock()
    response = FakeResponse(200, b'x' * 100, chunk=1, on_read=lambda reads: setattr(clock, 'now', clock.now + 1.0))
    client, _ = transport({MIRROR.url: lambda: response}, clock=clock, plan_deadline=5)
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and 'time limit' in error.message and error.recoverable
    assert response.reads == 5 and response.closed


def test_connect_timeout_is_the_smaller_of_ten_seconds_and_the_time_left():
    clock = Clock()
    client, server = transport({MIRROR.url: (200, b'ok')}, clock=clock)
    client.fetch(MIRROR)
    client, tight = transport({MIRROR.url: (200, b'ok')}, clock=clock, plan_deadline=3)
    client.fetch(MIRROR)
    assert server.calls[0][2] == limits.CONNECT_TIMEOUT_S and tight.calls[0][2] == 3


def test_cancel_before_the_request_between_reads_and_during_a_wait():
    cancel = threading.Event()
    cancel.set()
    client, server = transport({}, cancel=cancel)
    assert code_of(client.fetch, MIRROR).code == 'PT-KEV-CANCEL' and server.calls == []

    cancel = threading.Event()
    response = FakeResponse(200, b'a' * 100, on_read=lambda reads: cancel.set() if reads == 2 else None)
    client, _ = transport({MIRROR.url: lambda: response}, cancel=cancel)
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-CANCEL' and error.exit_code == 5 and response.closed

    cancel = threading.Event()
    client, server = transport({MIRROR.url: [(503, b'', {'Retry-After': '1'}), (200, b'ok')]}, cancel=cancel,
                               sleep=lambda seconds, event: event.set())
    assert code_of(client.fetch, MIRROR).code == 'PT-KEV-CANCEL' and len(server.calls) == 1


def test_cancel_interrupts_a_blocked_connection_and_the_late_response_is_closed():
    cancel, release, closed = threading.Event(), threading.Event(), threading.Event()

    def opener(url, headers, timeout):
        cancel.set()                      # the person pressed Cancel while the connection was still being made
        release.wait(10)
        response = FakeResponse(200, b'late')
        response.close = closed.set
        return response

    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=opener, cancel=cancel)
    started = time.monotonic()
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-CANCEL' and time.monotonic() - started < 5
    assert netutil.abandoned_count() >= 1
    release.set()
    assert closed.wait(5)
    assert netutil.abandoned_count() == 0


# --- real sockets (loopback only) -----------------------------------------------------------------------------

def read_head(connection) -> bytes:
    connection.settimeout(5)
    data = b''
    while b'\r\n\r\n' not in data and len(data) < 65536:
        piece = connection.recv(4096)
        if not piece:
            break
        data += piece
    return data


class Loopback:
    """A TCP server on 127.0.0.1 that runs ``handler(connection, request_head, stop)`` once per connection."""

    def __init__(self, handler):
        self._handler = handler
        self.stop, self.requests, self.connections = threading.Event(), [], 0
        self._listener = socket.socket()
        self._listener.bind(('127.0.0.1', 0))
        self._listener.listen(8)
        self._listener.settimeout(0.1)
        self._workers: list[threading.Thread] = []
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    @property
    def url(self) -> str:
        return f'http://127.0.0.1:{self._listener.getsockname()[1]}/known_exploited_vulnerabilities.json'

    def _accept(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self._listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            self.connections += 1
            worker = threading.Thread(target=self._serve, args=(connection,), daemon=True)
            worker.start()
            self._workers.append(worker)

    def _serve(self, connection) -> None:
        with connection:
            try:
                head = read_head(connection)
                self.requests.append(head)
                self._handler(connection, head, self.stop)
            except OSError:
                pass                      # the client went away, which is what several tests make it do

    def close(self) -> None:
        self.stop.set()
        self._listener.close()
        for thread in [self._acceptor, *self._workers]:
            thread.join(timeout=5)


@pytest.fixture
def serve():
    servers = []

    def start(handler) -> Loopback:
        servers.append(Loopback(handler))
        return servers[-1]

    yield start
    for server in servers:
        server.close()


def reply(head: bytes, body: bytes = b''):
    """A handler that sends ``head`` (status line and headers, through the blank line) and then ``body``."""
    def handler(connection, request, stop):
        connection.sendall(head + body)
    return handler


def at_loopback(server: Loopback, seen: list | None = None):
    """The production opener, pointed at the loopback server whatever URL the transport asks for."""
    def opener(url, headers, timeout):
        if seen is not None:
            seen.append(url)
        return tr.urllib_open(server.url, headers, timeout)
    return opener


def fetch_from(server: Loopback, **kw) -> tr.Fetched:
    return tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=at_loopback(server), **kw).fetch(MIRROR)


def drip(count: int = 24, interval: float = 0.5):
    def handler(connection, head, stop):
        connection.sendall(b'HTTP/1.0 200 OK\r\n\r\n')
        start = time.monotonic()
        for index in range(count):
            connection.sendall(b' ')
            if stop.wait(max(0.0, start + (index + 1) * interval - time.monotonic())):
                return
    return handler


def test_a_slow_drip_server_cannot_hold_the_download_past_its_deadline(serve):
    """Random audit RA-3: ``response.read(65536)`` blocks until the chunk fills, the per-recv socket timeout never
    fires while one byte arrives every half second, and a deadline checked only between chunks is never reached. This
    server would hold the old read for 12 s; ``read1`` plus a check per read returns within a read or two of 2 s."""
    server = serve(drip())
    started = time.monotonic()
    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=at_loopback(server), plan_deadline=2.0)
    error = code_of(client.fetch, MIRROR)
    elapsed = time.monotonic() - started
    assert error.code == 'PT-KEV-NETWORK' and 'time limit' in error.message
    assert 2.0 <= elapsed < 3.5, elapsed


def test_a_server_that_goes_silent_is_cut_by_the_socket_timeout(serve):
    def silent(connection, head, stop):
        connection.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\nabc')
        stop.wait(10)
    server = serve(silent)
    started = time.monotonic()
    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=at_loopback(server), plan_deadline=1.0)
    error = code_of(client.fetch, MIRROR)
    assert error.code == 'PT-KEV-NETWORK' and error.recoverable and time.monotonic() - started < 3.5


def test_a_complete_download_over_a_real_socket(serve):
    body = b'{"vulnerabilities": []}' * 20_000
    server = serve(reply(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n' % len(body), body))
    seen = []
    client = tr.KevTransport(tr.KevConsent.for_plan(MIRROR), opener=at_loopback(server, seen), now=lambda: STAMP)
    fetched = client.fetch(MIRROR)
    assert fetched.body == body and fetched.sha256 == hashlib.sha256(body).hexdigest()
    assert seen == [MIRROR.url] and server.connections == 1


def test_a_chunked_download_over_a_real_socket(serve):
    body = b'{"a": 1}' * 3000

    def chunked(connection, head, stop):
        connection.sendall(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n')
        for index in range(0, len(body), 4096):
            piece = body[index:index + 4096]
            connection.sendall(b'%x\r\n' % len(piece) + piece + b'\r\n')
        connection.sendall(b'0\r\n\r\n')
    assert fetch_from(serve(chunked)).body == body


@pytest.mark.parametrize('response', [
    b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n' + b'x' * 10,
    b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1000\r\n' + b'x' * 10,
], ids=['content-length', 'chunked'])
def test_a_truncated_body_over_a_real_socket_is_a_network_error(serve, response):
    """``read1`` returns end-of-file for a short body where ``read`` would raise IncompleteRead, so the length check
    has to be made by the transport itself."""
    error = code_of(fetch_from, serve(reply(response, b'')))
    assert error.code == 'PT-KEV-NETWORK' and error.recoverable


def test_the_real_opener_sends_only_the_two_fixed_headers_and_no_redirect_is_followed(serve):
    elsewhere = serve(reply(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n', b'{}'))
    origin = serve(reply(b'HTTP/1.1 302 Found\r\nLocation: ' + elsewhere.url.encode() + b'\r\nContent-Length: 0\r\n\r\n'))
    response = tr.urllib_open(origin.url, FIXED, 5)
    try:
        assert response.status == 302 and response.headers.get('Location') == elsewhere.url
    finally:
        response.close()
    assert elsewhere.connections == 0 and origin.connections == 1      # the 302 was surfaced, never followed
    lines = origin.requests[0].decode('latin-1').split('\r\n')
    assert lines[0] == 'GET /known_exploited_vulnerabilities.json HTTP/1.1'
    sent = {name.lower(): value for name, value in (line.split(': ', 1) for line in lines[1:] if line)}
    assert set(sent) == {'host', 'accept', 'user-agent', 'accept-encoding', 'connection'}
    assert (sent['accept'], sent['user-agent'], sent['accept-encoding']) == ('application/json', 'PatchTrace', 'identity')


def test_the_real_opener_ignores_environment_proxies(serve, monkeypatch):
    origin = serve(reply(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n', b'{}'))
    decoy = serve(reply(b'HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n', b'proxy'))
    for name in ('http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'):
        monkeypatch.setenv(name, decoy.url.rsplit('/', 1)[0])
    for name in ('no_proxy', 'NO_PROXY'):
        monkeypatch.delenv(name, raising=False)
    assert urllib.request.build_opener().open(origin.url, timeout=5).read() == b'proxy'       # the control
    assert (decoy.connections, origin.connections) == (1, 0)
    response = tr.urllib_open(origin.url, FIXED, 5)
    response.close()
    assert (decoy.connections, origin.connections) == (1, 1)


def test_the_real_opener_returns_http_errors_as_responses_and_maps_connection_failures(serve):
    refusing = socket.socket()
    refusing.bind(('127.0.0.1', 0))
    port = refusing.getsockname()[1]
    refusing.close()
    with pytest.raises(OSError):
        tr.urllib_open(f'http://127.0.0.1:{port}/', FIXED, 2)
    response = tr.urllib_open(serve(reply(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')).url, FIXED, 5)
    try:
        assert response.status == 404
    finally:
        response.close()
