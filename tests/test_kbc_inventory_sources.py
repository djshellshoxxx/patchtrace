"""PW-01 source controls. Authored fixtures and injected transport, never live compatibility evidence."""
from __future__ import annotations

import dataclasses
import io
import json
import socket
import ssl
import threading
import time
from datetime import UTC, datetime
from http.client import HTTPResponse

import pytest

from patchtrace.kbcorrelation.sources import inventory_fetch as fetch
from patchtrace.kbcorrelation.sources import inventory_http as http
from patchtrace.kbcorrelation.sources import support_links as links
from patchtrace.kbcorrelation.sources.cvrf import SourceError

PAGE = 'https://support.microsoft.com/help/5036893'
GO = 'https://go.microsoft.com/fwlink/?LinkId=123456'
CSV = 'https://download.microsoft.com/download/authored/inventory.csv'
NOW = datetime(2026, 11, 18, 0, 0, tzinfo=UTC)


def test_real_http_response_short_content_length_is_not_complete_inventory():
    from patchtrace.acquisition.transport import _Response

    body = b'File name,File version,Architecture\na.dll,1.2.3.4,x64\n'

    class Socket:
        def makefile(self, *_args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n' + body)

    response = HTTPResponse(Socket())
    response.begin()
    plan = fetch.build_plan(CSV)
    error('PT-KBC-SOURCE', lambda: fetch.fetch_source(
        plan, consent_hosts=plan.hosts, consent_plan=plan.plan_sha,
        opener=lambda *_args: _Response(response), now=lambda: NOW))


@pytest.mark.parametrize('headers', [
    b'Content-Length: +3\r\n', b'Content-Length: -1\r\n', b'Content-Length: 1.0\r\n',
    b'Content-Length: 3, 3\r\n', b'Content-Length: \r\n',
    b'Content-Length: 3\r\ncontent-length: 3\r\n',
    b'Content-Length: 3\r\nTransfer-Encoding: chunked\r\n',
    b'Transfer-Encoding: gzip\r\n', b'Content-Range: bytes 0-2/10\r\n',
])
def test_real_http_response_rejects_ambiguous_or_partial_framing(headers):
    from patchtrace.acquisition.transport import _Response

    class Socket:
        def makefile(self, *_args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\nabc')

    response = HTTPResponse(Socket())
    response.begin()
    plan = fetch.build_plan(CSV)
    error('PT-KBC-SOURCE', lambda: run(plan, lambda *_: _Response(response)))


@pytest.mark.parametrize('chunked', [False, True])
def test_real_http_response_accepts_complete_bounded_framing(chunked):
    from patchtrace.acquisition.transport import _Response

    body = b'File name,File version\na.dll,1.2.3.4\n'
    headers = b'Transfer-Encoding: chunked\r\n' if chunked else f'Content-Length: {len(body)}\r\n'.encode()
    wire = f'{len(body):x}\r\n'.encode() + body + b'\r\n0\r\n\r\n' if chunked else body

    class Socket:
        def makefile(self, *_args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n' + wire)

    response = HTTPResponse(Socket())
    response.begin()
    assert run(fetch.build_plan(CSV), lambda *_: _Response(response)).raw == body


def error(code, action):
    with pytest.raises(SourceError) as caught:
        action()
    assert caught.value.code == code
    return caught.value


def test_saved_html_preserves_candidates_and_rejections_without_network(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_a, **_k: pytest.fail('offline parsing attempted DNS'))
    raw = f'''<h2>File information</h2>
    <p>For files in this update, <a href="{GO}">download the <b>file information</b> for cumulative update 5036893</a>.</p>
    <p>For the servicing stack update, <a href="{CSV}">file information</a>.</p>
    <p>Verify checksums: <a href="{CSV}">file information</a>.</p>
    <p><a href="{CSV}?variant=2">File information for cumulative update 5036893</a></p>
    <p><a href="https://example.invalid/">Unrelated download</a></p>
    <script><a href="{CSV}">File information script lure</a></script>
    <style><a href="{CSV}">File information style lure</a></style>'''.encode()
    result = links.extract_links(raw, page_url=PAGE)
    accepted = [row for row in result.links if row.accepted]
    assert [row.url for row in accepted] == [GO, CSV + '?variant=2']
    assert {row.reason for row in result.links if not row.accepted} >= {'servicing-stack', 'hash-list', 'unrelated'}
    assert all('script lure' not in row.text and 'style lure' not in row.text for row in result.links)
    assert result.authenticity == 'unverified-local-file' and result.raw_size == len(raw)
    assert result == links.extract_links(raw, page_url=PAGE)


def test_relative_link_uses_explicit_page_url_and_ignores_html_base():
    raw = b'<base href="https://evil.invalid/"><a href="//download.microsoft.com/download/a.csv">File information</a>'
    result = links.extract_links(raw, page_url=PAGE)
    assert result.links[0].url == 'https://download.microsoft.com/download/a.csv'
    assert result.links[0].accepted
    error('PT-KBC-INPUT', lambda: links.extract_links(raw, page_url='https://evil.invalid/'))


@pytest.mark.parametrize('url', [
    'http://download.microsoft.com/download/a.csv', 'file:///tmp/a.csv',
    'https://download.microsoft.com.evil.invalid/download/a.csv',
    'https://download.microsoft.com@127.0.0.1/download/a.csv',
    'https://u:p@download.microsoft.com/download/a.csv',
    'https://download.microsoft.com:444/download/a.csv',
    'https://download.microsoft.com./download/a.csv',
    'https://download.microsoft.com/download/a.csv#fragment',
    'https://download.microsoft.com\\@evil.invalid/download/a.csv',
    'https://download.microsoft.com/download/a.csv\n',
    'https://download.microsoft.com/download/%0aa.csv',
    'https://download.microsoft.com/download/%2e%2e/a.csv',
    'https://download.microsoft.com/download/../a.csv',
    'https://download.microsoft.com:/download/a.csv',
    'https://download.microsoft.com/download/a.csv#',
    'https://download.microsoft.com/download/%5ca.csv',
    'https://127.0.0.1/download/a.csv', 'https://[::1]/download/a.csv',
    'https://go.microsoft.com/other/?LinkId=1', 'https://go.microsoft.com/fwlink/extra?LinkId=1',
])
def test_unsafe_urls_are_never_plannable_or_accepted_links(url):
    error('PT-KBC-INPUT', lambda: fetch.build_plan(url))
    result = links.extract_links(f'<a href="{url}">File information</a>'.encode(), page_url=PAGE)
    assert not any(row.accepted for row in result.links)


def test_html_bounds_encoding_depth_and_cancellation():
    limits = links.LinkLimits(max_bytes=100, max_links=2)
    error('PT-KBC-LIMIT', lambda: links.extract_links(b' ' * 101, page_url=PAGE, limits=limits))
    error('PT-KBC-SOURCE', lambda: links.extract_links(b'\xffbad', page_url=PAGE))
    error('PT-KBC-LIMIT', lambda: links.extract_links(b'<div>' * 200, page_url=PAGE))
    token = threading.Event()
    token.set()
    error('PT-KBC-CANCEL', lambda: links.extract_links(b'', page_url=PAGE, cancel=token))
    raw = ''.join(f'<a href="{CSV}?n={i}">File information</a>' for i in range(3)).encode()
    result = links.extract_links(raw, page_url=PAGE, limits=links.LinkLimits(max_links=2))
    assert len(result.links) == 2 and result.truncated and result.scanned_links == 3


def test_context_after_anchor_heading_and_table_row_excludes_ssu_and_hashes():
    raw = f'''<p><a href="{CSV}">File information</a> for the servicing stack update.</p>
    <h3>Checksums</h3><p><a href="{GO}">File information</a></p>
    <h2>File information</h2>
    <table><tr><td>SSU</td><td><a href="{CSV}">File information</a></td></tr>
    <tr><td>Cumulative update</td><td><a href="{GO}">File information</a></td></tr></table>'''.encode()
    result = links.extract_links(raw, page_url=PAGE)
    assert [row.reason for row in result.links] == ['servicing-stack', 'hash-list', 'servicing-stack', None]
    assert result.links[-1].accepted and 'Cumulative update' in result.links[-1].context


@pytest.mark.parametrize('markup,reason', [
    (f'<a href="{GO}" href="{CSV}">File information</a>', 'ambiguous-href'),
    (f'<a href="{GO}">File information', 'incomplete-anchor'),
    (f'<a href="{GO}">File information \u202e</a>', 'unsafe-text'),
    (f'<p>{"x" * 4100}<a href="{GO}">File information</a></p>', 'context-limit'),
    (f'<a href="{GO}&#10;">File information</a>', 'invalid-url'),
])
def test_ambiguous_or_incomplete_link_context_never_yields_acceptance(markup, reason):
    result = links.extract_links(markup.encode(), page_url=PAGE)
    assert len(result.links) == 1 and result.links[0].reason == reason and not result.links[0].accepted


def test_html_overlong_href_nodes_and_forged_limits_fail_atomically():
    error('PT-KBC-LIMIT', lambda: links.extract_links(
        ('<a href="' + CSV + '?' + 'x' * 2048 + '">File information</a>').encode(), page_url=PAGE))
    error('PT-KBC-LIMIT', lambda: links.extract_links(b'<p>x</p>' * 3, page_url=PAGE,
                                                    limits=links.LinkLimits(max_nodes=2)))
    error('PT-KBC-INPUT', lambda: links.LinkLimits(max_bytes=4 * 1024 * 1024 + 1))
    forged = links.LinkLimits()
    object.__setattr__(forged, 'max_links', 0)
    error('PT-KBC-INPUT', lambda: links.extract_links(b'', page_url=PAGE, limits=forged))


def test_hidden_template_and_html_base_do_not_change_candidates():
    raw = f'''<base href="https://evil.invalid/"><template><a href="{CSV}">File information</a></template>
    <noscript><a href="{GO}">File information</a></noscript>
    <p><a href="//go.microsoft.com/fwlink/?LinkId=123456">File information</a></p>'''.encode()
    result = links.extract_links(raw, page_url=PAGE)
    assert result.scanned_links == 1 and result.links[0].url == GO


def test_plan_is_pure_exact_and_strict(monkeypatch):
    monkeypatch.setattr(socket, 'getaddrinfo', lambda *_a, **_k: pytest.fail('plan attempted DNS'))
    plan = fetch.build_plan(GO, redirects=(CSV,))
    assert plan.urls == (GO, CSV)
    assert plan.hosts == ('download.microsoft.com', 'go.microsoft.com')
    assert fetch.parse_plan(plan.to_json()) == plan
    assert GO in fetch.render_plan(plan) and CSV in fetch.render_plan(plan)
    assert fetch.build_plan(CSV).plan_sha != plan.plan_sha
    altered = plan.as_dict()
    altered['max_bytes'] = 1
    error('PT-KBC-CONSENT', lambda: fetch.parse_plan(json.dumps(altered)))
    error('PT-KBC-INPUT', lambda: fetch.parse_plan('{"kind":"file-inventory","kind":"support-page"}'))
    error('PT-KBC-INPUT', lambda: fetch.parse_plan('[' * 10000 + '0' + ']' * 10000))
    error('PT-KBC-INPUT', lambda: fetch.parse_plan(plan.to_json()[:-1] + ',"extra":1e999}'))
    for field, value in [('max_redirects', True), ('request_timeout_s', 10.0), ('headers', [])]:
        altered = plan.as_dict()
        altered[field] = value
        error('PT-KBC-CONSENT', lambda value=altered: fetch.parse_plan(json.dumps(value)))
    error('PT-KBC-INPUT', lambda: fetch.build_plan(PAGE, kind='file-inventory'))
    error('PT-KBC-INPUT', lambda: fetch.build_plan(CSV, kind='support-page'))
    error('PT-KBC-INPUT', lambda: fetch.build_plan(GO, redirects=(GO,)))
    error('PT-KBC-LIMIT', lambda: fetch.build_plan(CSV, redirects=tuple(CSV + f'?n={i}' for i in range(5))))


class Response:
    def __init__(self, status=200, body=b'File name,File version\na.dll,1.2.3.4\n', headers=None):
        self.status, self.headers = status, headers or {}
        self.body, self.closed = io.BytesIO(body), False

    def read(self, size):
        return self.body.read(size)

    read1 = read

    def close(self):
        self.closed = True


def run(plan, opener, **kw):
    return fetch.fetch_source(plan, consent_hosts=plan.hosts, consent_plan=plan.plan_sha, opener=opener,
                              now=lambda: NOW, **kw)


def test_offline_bad_consent_and_forged_plan_refuse_before_opener():
    plan = fetch.build_plan(CSV)
    def forbidden(*_a):
        pytest.fail('a refused operation attempted a request')
    error('PT-KBC-INPUT', lambda: run(plan, forbidden, offline=True))
    error('PT-KBC-CONSENT', lambda: fetch.fetch_source(plan, consent_hosts=(), consent_plan=plan.plan_sha,
                                                    opener=forbidden))
    error('PT-KBC-CONSENT', lambda: fetch.fetch_source(plan, consent_hosts=plan.hosts, consent_plan='a' * 64,
                                                    opener=forbidden))
    forged = dataclasses.replace(plan, max_bytes=1)
    error('PT-KBC-CONSENT', lambda: run(forged, forbidden))
    token = threading.Event()
    token.set()
    error('PT-KBC-CANCEL', lambda: run(plan, forbidden, cancel=token))


def test_fetch_records_exact_chain_and_digest_with_response_cleanup():
    plan = fetch.build_plan(GO, redirects=(CSV,))
    first, second = Response(302, headers={'Location': CSV}), Response()
    calls = []
    def opener(method, url, headers, timeout):
        calls.append((method, url, headers, timeout))
        return first if url == GO else second
    result = run(plan, opener)
    assert [call[1] for call in calls] == [GO, CSV]
    assert all(call[0] == 'GET' and call[2] == dict(plan.headers) and 0 < call[3] <= 10 for call in calls)
    assert first.closed and second.closed
    assert result.original_url == GO and result.final_url == CSV and result.redirect_chain == (GO, CSV)
    assert result.raw.startswith(b'File name') and result.retrieved_at == '2026-11-18T00:00:00Z'
    assert result.receipt()['size'] == len(result.raw) and 'raw' not in result.receipt()


def test_redirect_drift_returns_a_new_preview_without_contacting_target():
    plan = fetch.build_plan(GO)
    response, calls = Response(302, headers={'Location': CSV}), []
    def opener(_method, url, _headers, _timeout):
        calls.append(url)
        return response
    problem = error('PT-KBC-CONSENT', lambda: run(plan, opener))
    assert calls == [GO] and response.closed
    proposed = fetch.parse_plan(json.dumps(problem.details['proposed_plan']))
    assert proposed.urls == (GO, CSV) and proposed.plan_sha != plan.plan_sha
    assert CSV in problem.details['preview']


def test_changed_order_and_early_final_response_require_an_exact_new_plan():
    second = CSV + '?second=1'
    plan = fetch.build_plan(GO, redirects=(CSV, second))
    changed = Response(302, headers={'Location': second})
    calls = []
    def opener(_method, url, _headers, _timeout):
        calls.append(url)
        return changed
    problem = error('PT-KBC-CONSENT', lambda: run(plan, opener))
    assert calls == [GO] and changed.closed
    assert problem.details['proposed_plan']['urls'] == [GO, second]
    early = Response()
    problem = error('PT-KBC-CONSENT', lambda: run(plan, lambda *_a: early))
    assert early.closed and early.body.tell() == 0
    assert problem.details['proposed_plan']['urls'] == [GO]


def test_relative_redirect_is_resolved_but_not_silently_consented():
    plan = fetch.build_plan(CSV)
    response = Response(302, headers={'Location': 'second.csv'})
    problem = error('PT-KBC-CONSENT', lambda: run(plan, lambda *_a: response))
    assert problem.details['proposed_plan']['urls'] == [CSV, CSV.replace('inventory.csv', 'second.csv')]


@pytest.mark.parametrize('location', ['http://download.microsoft.com/download/a.csv',
                                      'https://evil.invalid/a.csv', 'https://127.0.0.1/a.csv', None])
def test_bad_redirect_never_yields_a_consent_preview(location):
    response = Response(302, headers={} if location is None else {'Location': location})
    problem = error('PT-KBC-SOURCE', lambda: run(fetch.build_plan(GO), lambda *_a: response))
    assert not problem.details or 'proposed_plan' not in problem.details
    assert response.closed


def test_body_limit_failure_and_http_error_close_response():
    response = Response(headers={'Content-Length': str(16 * 1024 * 1024 + 1)})
    error('PT-KBC-LIMIT', lambda: run(fetch.build_plan(CSV), lambda *_a: response))
    assert response.closed
    response = Response(404)
    error('PT-KBC-SOURCE', lambda: run(fetch.build_plan(CSV), lambda *_a: response))
    assert response.closed


def test_support_page_fetch_returns_raw_bytes_without_following_links():
    plan = fetch.build_plan(PAGE, kind='support-page')
    response = Response(body=f'<a href="{CSV}">File information</a>'.encode())
    calls = []
    def opener(_method, url, _headers, _timeout):
        calls.append(url)
        return response
    result = run(plan, opener)
    assert plan.max_bytes == 4 * 1024 * 1024
    assert calls == [PAGE] and result.raw.startswith(b'<a ') and result.kind == 'support-page'


def test_actual_body_size_and_content_encoding_are_enforced():
    response = Response(body=b'x' * (16 * 1024 * 1024 + 1))
    error('PT-KBC-LIMIT', lambda: run(fetch.build_plan(CSV), lambda *_a: response))
    assert response.closed
    response = Response(headers={'Content-Encoding': 'gzip'})
    error('PT-KBC-SOURCE', lambda: run(fetch.build_plan(CSV), lambda *_a: response))
    assert response.closed and response.body.tell() == 0


def test_body_cancellation_preserves_cleanup_and_no_partial_result():
    token = threading.Event()
    class CancelResponse(Response):
        def read1(self, size):
            token.set()
            return super().read1(size)
    response = CancelResponse()
    error('PT-KBC-CANCEL', lambda: run(fetch.build_plan(CSV), lambda *_a: response, cancel=token))
    assert response.closed


def test_retry_respects_exact_plan_headers_and_closes_failed_response():
    first, second = Response(503, headers={'Retry-After': '1'}), Response(body=b'raw inventory bytes')
    responses, calls, sleeps = iter((first, second)), [], []
    def opener(method, url, headers, timeout):
        calls.append((method, url, headers, timeout))
        return next(responses)
    plan = fetch.build_plan(CSV)
    result = run(plan, opener, sleep=lambda seconds, _token: sleeps.append(seconds))
    assert result.raw == b'raw inventory bytes' and first.closed and second.closed and sleeps == [1]
    assert len(calls) == 2 and all(call[1] == CSV and call[2] == dict(plan.headers) for call in calls)


def test_redirect_loop_is_refused_without_another_request():
    response = Response(302, headers={'Location': GO})
    error('PT-KBC-SOURCE', lambda: run(fetch.build_plan(GO), lambda *_a: response))
    assert response.closed


def test_deadline_and_retry_wait_preserve_budget():
    plan = fetch.build_plan(CSV)
    ticks, calls = [0.0], []
    def opener(*_args):
        calls.append(1)
        ticks[0] += 61
        return Response()
    error('PT-KBC-ACQUIRE', lambda: run(plan, opener, clock=lambda: ticks[0]))
    assert calls == [1]
    calls.clear()
    ticks[0] = 0
    response = Response(429, headers={'Retry-After': '60'})
    def retried(*_args):
        calls.append(1)
        return response
    error('PT-KBC-ACQUIRE', lambda: run(plan, retried, clock=lambda: ticks[0],
                                      sleep=lambda *_a: pytest.fail('sleep exceeds total budget')))
    assert calls == [1] and response.closed


def addr(ip):
    return (socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            '', (ip, 443, 0, 0) if ':' in ip else (ip, 443))


class FakeSocket:
    def __init__(self, *_a):
        self.timeouts, self.connected, self.closed = [], None, False
    def settimeout(self, value):
        self.timeouts.append(value)
    def connect(self, address):
        self.connected = address
    def setsockopt(self, *_a):
        pass
    def close(self):
        self.closed = True


@pytest.mark.parametrize('ip', ['127.0.0.1', '10.1.2.3', '169.254.1.1', '0.0.0.0', '192.0.2.1',
                               '224.0.0.1', '::1', 'fe80::1', 'fec0::1', 'fc00::1', '::ffff:127.0.0.1',
                               '64:ff9b::a00:1'])
def test_private_dns_is_refused_before_socket_creation(ip):
    error('PT-KBC-SOURCE', lambda: http.connect_public(('download.microsoft.com', 443), 1,
          resolver=lambda *_a, **_k: [addr(ip)], socket_factory=lambda *_a: pytest.fail('unsafe socket')))


def test_public_dns_address_is_used_once_without_second_resolution():
    calls, made = [], []
    def resolver(*_args):
        calls.append(1)
        return [addr('8.8.8.8')]
    def factory(*args):
        made.append(FakeSocket(*args))
        return made[-1]
    sock = http.connect_public(('download.microsoft.com', 443), 1, resolver=resolver, socket_factory=factory)
    assert calls == [1] and sock is made[0] and sock.connected == ('8.8.8.8', 443)
    assert all(0 < value <= 1 for value in sock.timeouts)


def test_connect_failure_uses_only_other_prevalidated_answers_and_closes_failed_socket():
    made, resolutions = [], []
    class FirstFails(FakeSocket):
        def connect(self, address):
            super().connect(address)
            if len(made) == 1:
                raise OSError('connection refused')
    def resolver(*_args):
        resolutions.append(1)
        return [addr('8.8.8.8'), addr('1.1.1.1')]
    def factory(*args):
        made.append(FirstFails(*args))
        return made[-1]
    result = http.connect_public(('DOWNLOAD.MICROSOFT.COM', 443), 1, resolver=resolver, socket_factory=factory)
    assert resolutions == [1] and made[0].closed
    assert result is made[1] and result.connected == ('1.1.1.1', 443)


def test_mixed_public_and_private_dns_answers_fail_closed():
    error('PT-KBC-SOURCE', lambda: http.connect_public(('download.microsoft.com', 443), 1,
          resolver=lambda *_a: [addr('8.8.8.8'), addr('127.0.0.1')],
          socket_factory=lambda *_a: pytest.fail('mixed DNS must not connect')))


def test_dns_timeout_is_bounded_and_cancellation_prevents_resolution():
    done = threading.Event()
    try:
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            http.connect_public(('download.microsoft.com', 443), 0.03,
                                resolver=lambda *_a: done.wait(2))
        assert time.monotonic() - started < 1
    finally:
        done.set()
    token = threading.Event()
    token.set()
    error('PT-KBC-CANCEL', lambda: http.connect_public(('download.microsoft.com', 443), 1, cancel=token,
          resolver=lambda *_a: pytest.fail('cancelled DNS was called')))


def test_https_keeps_original_hostname_for_tls():
    context = ssl.create_default_context()
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    captured, made = [], []
    class Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED
        post_handshake_auth = False
        def wrap_socket(self, sock, *, server_hostname):
            captured.append(server_hostname)
            return sock
    def factory(*args):
        made.append(FakeSocket(*args))
        return made[-1]
    conn = http.PublicHTTPSConnection('download.microsoft.com', timeout=1, context=Context(),
          resolver=lambda *_a: [addr('8.8.8.8')], socket_factory=factory)
    conn.connect()
    assert captured == ['download.microsoft.com'] and made[0].connected == ('8.8.8.8', 443)
    conn.close()


def test_connection_dns_tcp_and_tls_share_one_timeout():
    ticks, made = [0.0], []
    class Context:
        check_hostname = True
        verify_mode = ssl.CERT_REQUIRED
        post_handshake_auth = False
        def wrap_socket(self, sock, *, server_hostname):
            ticks[0] += 0.2
            return sock
    class TimedSocket(FakeSocket):
        def connect(self, address):
            ticks[0] += 0.3
            super().connect(address)
    def resolver(*_args):
        ticks[0] += 0.6
        return [addr('8.8.8.8')]
    def factory(*args):
        made.append(TimedSocket(*args))
        return made[-1]
    conn = http.PublicHTTPSConnection('download.microsoft.com', timeout=1, context=Context(),
                                     resolver=resolver, socket_factory=factory, clock=lambda: ticks[0])
    with pytest.raises(TimeoutError):
        conn.connect()
    assert made[0].closed and made[0].timeouts[-1] <= 0.11


def test_insecure_tls_context_is_rejected_before_resolution():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    error('PT-KBC-INPUT', lambda: http.PublicHTTPSConnection('download.microsoft.com', context=context,
          resolver=lambda *_a: pytest.fail('insecure context attempted DNS')))


def test_production_opener_explicitly_disables_proxy_inheritance_and_redirects(monkeypatch):
    captured = []
    response = Response()
    class Opener:
        def open(self, request, *, timeout):
            assert request.full_url == CSV and request.get_method() == 'GET' and timeout == 1
            return response
    def factory(*handlers):
        captured.extend(handlers)
        return Opener()
    monkeypatch.setenv('HTTPS_PROXY', 'http://127.0.0.1:8888')
    monkeypatch.setattr(http.urllib.request, 'build_opener', factory)
    wrapped = http.urllib_open('GET', CSV, {}, 1, kind='file-inventory')
    assert captured[0].proxies == {}
    assert captured[1].redirect_request(None, None, 302, '', {}, CSV) is None
    assert isinstance(captured[2], http.urllib.request.HTTPSHandler)
    assert wrapped.read(4) == b'File'
    wrapped.close()
    assert response.closed


def test_slow_header_drip_is_guarded_before_body_read():
    ticks = [0.0]
    class Wire(FakeSocket):
        def recv_into(self, buffer, *_args):
            ticks[0] += 1
            buffer[:1] = b'H'
            return 1
    class Raw(io.RawIOBase):
        def __init__(self):
            self._sock = Wire()
        def readable(self):
            return True
        def readinto(self, buffer):
            return self._sock.recv_into(buffer)
    class ReaderSocket:
        def makefile(self, _mode):
            return io.BufferedReader(Raw())
    conn = http.PublicHTTPSConnection('download.microsoft.com', timeout=10, deadline=3, clock=lambda: ticks[0])
    response = conn.response_class(ReaderSocket())
    with pytest.raises(TimeoutError):
        response.begin()
    response.close()
    assert ticks[0] == 3
