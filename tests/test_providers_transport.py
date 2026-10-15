"""Provider transport over fake openers and loopback servers; no network (SPEC-41 R1-R7, R13, R14, R33)."""
import http.client
import io
import json
import socket
import ssl
import threading
import time
import urllib.error

import pytest
from providers_support import (
    BlockedResponse,
    FakeClock,
    FakeOpener,
    FakeResponse,
    LockedResponse,
    Loopback,
    http_reply,
    install_opener,
    no_reply,
    raw_reply,
    stall_after,
    wait_until,
)

from patchtrace import netutil, providers
from patchtrace.providers import (
    MAX_RESPONSE_BYTES,
    ProviderCancelled,
    ProviderConfig,
    ProviderError,
    request_completion,
)

PEER = 'PEER_TEXT'
OLLAMA = ProviderConfig('ollama', 'http://127.0.0.1:11434', 'fixture')
OPENAI = ProviderConfig('openai', 'https://api.example.com/v1', 'fixture', 'SESSION_SECRET')
CONNECTION = 'connection failed or timed out'
INVALID_HTTP = 'invalid HTTP response'
TLS = 'TLS handshake or certificate verification failed'


def call(config=OLLAMA, cancel=None):
    return request_completion(config, 'system', '{}', cancel or threading.Event())


FAILURES = [
    ('bad-status-line', lambda: http.client.BadStatusLine(PEER), INVALID_HTTP),
    ('incomplete-read', lambda: http.client.IncompleteRead(PEER.encode()), INVALID_HTTP),
    ('line-too-long', lambda: http.client.LineTooLong(PEER), INVALID_HTTP),
    ('remote-closed', lambda: http.client.RemoteDisconnected(PEER), INVALID_HTTP),
    ('tls-certificate', lambda: ssl.SSLCertVerificationError(PEER), TLS),
    ('tls-wrapped', lambda: urllib.error.URLError(ssl.SSLError(PEER)), TLS),
    ('tls-eof', lambda: ssl.SSLEOFError(PEER), TLS),
    ('timeout', lambda: TimeoutError(PEER), CONNECTION),
    ('refused', lambda: urllib.error.URLError(ConnectionRefusedError(PEER)), CONNECTION),
    ('reset', lambda: ConnectionResetError(PEER), CONNECTION),
    ('dns', lambda: urllib.error.URLError(socket.gaierror(-2, PEER)), CONNECTION),
    ('os-error', lambda: OSError(PEER), CONNECTION),
    ('http-503', lambda: urllib.error.HTTPError('http://x', 503, PEER, {}, io.BytesIO(PEER.encode())),
     'server returned HTTP 503'),
    ('runtime', lambda: RuntimeError(PEER), 'transport failed unexpectedly (RuntimeError)'),
    ('value', lambda: ValueError(PEER), 'transport failed unexpectedly (ValueError)'),
    ('encode', lambda: UnicodeEncodeError('latin-1', '\N{EURO SIGN}', 0, 1, PEER),
     'transport failed unexpectedly (UnicodeEncodeError)'),
]
FAILURE_IDS = [item[0] for item in FAILURES]


def assert_fixed_text(error, message):
    text = str(error.value)
    assert type(error.value) is ProviderError
    assert text.startswith('PT-PROVIDER: ') and message in text
    assert PEER not in text


@pytest.mark.parametrize('make,message', [item[1:] for item in FAILURES], ids=FAILURE_IDS)
def test_failure_while_connecting_maps_to_fixed_text(monkeypatch, make, message):
    install_opener(monkeypatch, FakeOpener(make))
    with pytest.raises(ProviderError) as error:
        call()
    assert_fixed_text(error, message)


@pytest.mark.parametrize('make,message', [item[1:] for item in FAILURES if item[0] not in {'http-503'}],
                         ids=[i for i in FAILURE_IDS if i != 'http-503'])
def test_failure_while_reading_maps_to_fixed_text(monkeypatch, make, message):
    install_opener(monkeypatch, FakeOpener(lambda: FakeResponse(b'{"message"', error=make())))
    with pytest.raises(ProviderError) as error:
        call()
    assert_fixed_text(error, message)


ENVELOPES = [
    ('not-json', b'not json'),
    ('not-utf8', b'\xff\xfe\x00'),
    ('list', b'[]'),
    ('string-message', b'{"message": "x"}'),
    ('no-content', b'{"message": {}}'),
    ('number-content', b'{"message": {"content": 5}}'),
    ('truncated', b'{"message": {"content": "abc'),
    ('too-deep', b'[' * 100000),
]


@pytest.mark.parametrize('body', [item[1] for item in ENVELOPES], ids=[item[0] for item in ENVELOPES])
def test_malformed_ollama_envelope_maps_to_fixed_text(monkeypatch, body):
    install_opener(monkeypatch, FakeOpener(lambda: FakeResponse(body)))
    with pytest.raises(ProviderError) as error:
        call()
    assert_fixed_text(error, 'malformed provider envelope')


@pytest.mark.parametrize('body', [b'{"choices": []}', b'{"choices": "x"}', b'{"choices": [1]}',
                                  b'{"choices": [{"message": {"content": null}}]}'],
                         ids=['empty', 'string', 'bare-item', 'null-content'])
def test_malformed_openai_envelope_maps_to_fixed_text(monkeypatch, body):
    install_opener(monkeypatch, FakeOpener(lambda: FakeResponse(body)))
    with pytest.raises(ProviderError) as error:
        call(OPENAI)
    assert_fixed_text(error, 'malformed provider envelope')


def test_garbage_status_line_is_classified_not_raised_raw():
    """Probe P3: a peer that does not speak HTTP used to escape as http.client.BadStatusLine."""
    with Loopback(raw_reply(b'NOT-HTTP garbage\r\n\r\n')) as server:
        with pytest.raises(ProviderError) as error:
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert INVALID_HTTP in str(error.value) and 'garbage' not in str(error.value)
    assert len(server.received) == 1


def test_plain_text_answer_to_a_tls_hello_is_classified_as_tls():
    """A real ssl.SSLError out of the handshake, without certificates: the peer does not speak TLS."""
    def answer_in_plain_text(conn, received, release):
        conn.recv(65536)  # take the ClientHello so closing sends FIN rather than RST
        conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
    with Loopback(answer_in_plain_text, parse=False) as server:
        config = ProviderConfig('openai', server.endpoint.replace('http://', 'https://') + '/v1', 'fixture',
                                'SESSION_SECRET')
        with pytest.raises(ProviderError) as error:
            call(config)
    assert TLS in str(error.value) and 'SESSION_SECRET' not in str(error.value)
    assert len(server.received) == 1


def chunked(*pieces):
    return b''.join(f'{len(piece):x}\r\n'.encode() + piece + b'\r\n' for piece in pieces) + b'0\r\n\r\n'


def test_chunked_response_is_read_in_full():
    body = json.dumps({'message': {'content': 'x' * 100000}}).encode()
    head = b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n'
    with Loopback(raw_reply(head + chunked(body[:70000], body[70000:]))) as server:
        text = call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert text == 'x' * 100000


def test_large_body_is_read_across_many_reads():
    body, padding = envelope_of_size(1_000_000)
    with Loopback(http_reply('200 OK', body)) as server:
        text = call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert text == 'x' * padding


def test_truncated_chunked_body_is_classified():
    with Loopback(raw_reply(b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n64\r\nshort')) as server:
        with pytest.raises(ProviderError) as error:
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert INVALID_HTTP in str(error.value)


def test_body_shorter_than_its_content_length_is_not_accepted():
    head = b'HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{"message": {"content": "abc'
    with Loopback(raw_reply(head)) as server:
        with pytest.raises(ProviderError) as error:
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert_fixed_text(error, 'malformed provider envelope')


def test_connection_closed_without_response_is_classified_and_not_retried():
    with Loopback(no_reply) as server:
        with pytest.raises(ProviderError) as error:
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert INVALID_HTTP in str(error.value)
    assert len(server.received) == 1


def test_http_error_status_hides_peer_body_and_is_sent_once():
    with Loopback(http_reply('503 Service Unavailable', PEER.encode())) as server:
        with pytest.raises(ProviderError) as error:
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert_fixed_text(error, 'server returned HTTP 503')
    assert len(server.received) == 1


def test_cancelled_before_send_raises_provider_cancelled(monkeypatch):
    opener = install_opener(monkeypatch, FakeOpener(RuntimeError('must not be reached')))
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ProviderCancelled):
        call(cancel=cancel)
    assert opener.calls == []


OLLAMA_ANSWER = http_reply(
    '200 OK', json.dumps({'message': {'role': 'assistant', 'content': 'THE_ANSWER'}}).encode(),
    headers={'Content-Type': 'application/json'})


@pytest.mark.parametrize('suffix', ['', '/', '/api/chat', '/api/chat/'],
                         ids=['bare', 'slash', 'full', 'full-slash'])
def test_ollama_request_and_envelope_shape(suffix):
    with Loopback(OLLAMA_ANSWER) as server:
        config = ProviderConfig('ollama', server.endpoint + suffix, 'llama3', api_key='SESSION_SECRET')
        text = request_completion(config, 'SYSTEM', 'USER_PAYLOAD', threading.Event())
    assert text == 'THE_ANSWER'
    (received,) = server.received
    assert received.request_line == 'POST /api/chat HTTP/1.1'
    assert received.headers['content-type'] == 'application/json'
    assert 'authorization' not in received.headers and b'SESSION_SECRET' not in received.body
    assert json.loads(received.body) == {
        'model': 'llama3', 'stream': False, 'format': 'json',
        'messages': [{'role': 'system', 'content': 'SYSTEM'}, {'role': 'user', 'content': 'USER_PAYLOAD'}]}


def test_openai_request_shape_and_bearer_only_with_a_key(monkeypatch):
    answer = json.dumps({'choices': [{'message': {'content': 'THE_ANSWER'}}]}).encode()
    opener = install_opener(monkeypatch, FakeOpener(lambda: FakeResponse(answer)))
    keyless = ProviderConfig('openai', 'https://api.example.com/v1/chat/completions', 'fixture')
    assert call(OPENAI) == call(keyless) == 'THE_ANSWER'
    (keyed, _), (plain, _) = opener.calls
    assert keyed.full_url == plain.full_url == 'https://api.example.com/v1/chat/completions'
    assert keyed.get_header('Authorization') == 'Bearer SESSION_SECRET'
    assert not plain.has_header('Authorization')
    body = json.loads(keyed.data)
    assert set(body) == {'model', 'messages', 'stream', 'response_format'}
    assert body['stream'] is False and body['response_format'] == {'type': 'json_object'}


@pytest.mark.parametrize('status', ['301 Moved Permanently', '302 Found', '303 See Other',
                                    '307 Temporary Redirect', '308 Permanent Redirect'],
                         ids=['301', '302', '303', '307', '308'])
def test_provider_refuses_redirect(status):
    with Loopback(http_reply(status, headers={'Location': 'http://127.0.0.1:9/elsewhere'})) as server:
        with pytest.raises(ProviderError, match='redirects are refused'):
            call(ProviderConfig('ollama', server.endpoint, 'fixture'))
    assert len(server.received) == 1


def envelope_of_size(size):
    padding = size - len(json.dumps({'message': {'content': ''}}))
    return json.dumps({'message': {'content': 'x' * padding}}).encode(), padding


def test_response_exactly_at_the_cap_is_accepted(monkeypatch):
    body, padding = envelope_of_size(MAX_RESPONSE_BYTES)
    assert len(body) == MAX_RESPONSE_BYTES
    install_opener(monkeypatch, FakeOpener(lambda: FakeResponse(body)))
    assert call() == 'x' * padding


def test_response_over_the_cap_is_cut_off_one_byte_past_the_limit(monkeypatch):
    class Endless(FakeResponse):
        sizes: list = []

        def read1(self, size):
            self.sizes.append(size)
            return b'x' * size

    endless = Endless()
    install_opener(monkeypatch, FakeOpener(endless))
    with pytest.raises(ProviderError, match='response exceeds 2 MiB limit'):
        call()
    assert sum(endless.sizes) == MAX_RESPONSE_BYTES + 1 and max(endless.sizes) == 64 * 1024
    assert endless.closed


def test_abandoned_thread_limit_maps_to_a_retry_message(monkeypatch):
    release = threading.Event()
    entered = []

    def blocked_open():
        entered[-1].set()
        release.wait(10)
        return OSError('released')
    install_opener(monkeypatch, FakeOpener(blocked_open))
    baseline = netutil.abandoned_count()
    try:
        for _ in range(netutil.MAX_ABANDONED - baseline):
            cancel = threading.Event()
            entered.append(threading.Event())
            threading.Thread(target=lambda e=entered[-1], c=cancel: (e.wait(5), c.set()), daemon=True).start()
            with pytest.raises(ProviderCancelled):
                call(cancel=cancel)
        with pytest.raises(ProviderError, match='previous requests are still closing') as error:
            call()
        assert type(error.value) is ProviderError
    finally:
        release.set()
        assert wait_until(lambda: netutil.abandoned_count() == baseline)


@pytest.fixture
def settled():
    """No abandoned worker may outlive a test (the abandoned-thread counter is process-wide)."""
    baseline = netutil.abandoned_count()
    yield
    assert wait_until(lambda: netutil.abandoned_count() == baseline)


def advance_when(event, clock):
    """Push the fake clock past the call deadline once `event` fires."""
    threading.Thread(target=lambda: (event.wait(5), clock.advance(providers.TIMEOUT_SECONDS + 1)),
                     daemon=True).start()


def test_blocked_read_respects_call_deadline(monkeypatch, settled):
    """SPEC-41 R14: the deadline used to be checked only between reads, so a blocked read outlived it."""
    clock = FakeClock()
    monkeypatch.setattr(providers.time, 'monotonic', clock)
    blocked = install_opener(monkeypatch, FakeOpener(BlockedResponse())).outcome
    advance_when(blocked.started, clock)
    begun = time.perf_counter()
    try:
        with pytest.raises(ProviderError, match='timed out') as error:
            call()
        assert type(error.value) is ProviderError and time.perf_counter() - begun < 3.0
        assert not blocked.release.is_set()
    finally:
        blocked.release.set()
    assert wait_until(lambda: blocked.closed)


def test_blocked_connect_respects_call_deadline(monkeypatch, settled):
    clock = FakeClock()
    monkeypatch.setattr(providers.time, 'monotonic', clock)
    entered, release = threading.Event(), threading.Event()

    def blocked_open():
        entered.set()
        release.wait(5)
        return FakeResponse(b'{}')
    install_opener(monkeypatch, FakeOpener(blocked_open))
    advance_when(entered, clock)
    begun = time.perf_counter()
    try:
        with pytest.raises(ProviderError, match='timed out'):
            call()
        assert time.perf_counter() - begun < 3.0 and not release.is_set()
    finally:
        release.set()


def test_cancel_during_a_blocked_read_does_not_wait_for_the_read(monkeypatch, settled):
    """Closing a response waits for its blocked reader, so the reader must be the one that closes it."""
    locked = install_opener(monkeypatch, FakeOpener(LockedResponse())).outcome
    cancel = threading.Event()
    threading.Thread(target=lambda: (locked.started.wait(5), cancel.set()), daemon=True).start()
    begun = time.perf_counter()
    try:
        with pytest.raises(ProviderCancelled):
            call(cancel=cancel)
        assert time.perf_counter() - begun < 3.0 and not locked.release.is_set()
    finally:
        locked.release.set()
    assert wait_until(lambda: locked.closed)


def test_response_arriving_after_cancel_is_closed_unread(monkeypatch, settled):
    entered, release = threading.Event(), threading.Event()
    late = FakeResponse(b'{"message": {"content": "late"}}')

    def blocked_open():
        entered.set()
        release.wait(5)
        return late
    install_opener(monkeypatch, FakeOpener(blocked_open))
    cancel = threading.Event()
    threading.Thread(target=lambda: (entered.wait(5), cancel.set()), daemon=True).start()
    try:
        with pytest.raises(ProviderCancelled):
            call(cancel=cancel)
    finally:
        release.set()
    assert wait_until(lambda: late.closed) and late.reads == 0


def test_real_stalled_body_cancel_returns_promptly(monkeypatch, settled):
    """Ground truth on the real urllib stack: the headers arrive, then the peer goes silent."""
    monkeypatch.setattr(providers, 'TIMEOUT_SECONDS', 5)
    sent = threading.Event()
    inner = stall_after(b'HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\n')

    def reply(conn, received, release):
        threading.Timer(0.3, sent.set).start()  # by then the client is long inside its body read
        inner(conn, received, release)
    cancel = threading.Event()
    threading.Thread(target=lambda: (sent.wait(5), cancel.set()), daemon=True).start()
    with Loopback(reply) as server:
        begun = time.perf_counter()
        with pytest.raises(ProviderCancelled):
            call(ProviderConfig('ollama', server.endpoint, 'fixture'), cancel)
        assert time.perf_counter() - begun < 3.0
