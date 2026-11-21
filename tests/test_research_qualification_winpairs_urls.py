"""Offline request/redirect boundary regressions; no sockets or target execution."""
from __future__ import annotations

import gzip
import http.client
import io
import json
import urllib.error
import urllib.parse
from email.message import Message

import pytest
from test_research_qualification_winpairs import (
    BIN_A,
    BIN_B,
    IDX_URL,
    URL_A,
    URL_B,
    A,
    B,
    Fake,
    cli,
    index,
)

from tools.research_qualification import winpairs as wp

BAD_URLS = (
    'https://msdl.microsoft.com:notaport/x?sig=PRIVATE',
    'https://msdl.microsoft.com:99999/x?sig=PRIVATE',
    'https://[msdl.microsoft.com/x?sig=PRIVATE',
    'https://msdl.microsoft.com\uff1a443/x?sig=PRIVATE',
    'https://@msdl.microsoft.com/x?sig=PRIVATE',
    'https://:@msdl.microsoft.com/x?sig=PRIVATE',
    '\x00https://msdl.microsoft.com/x?sig=PRIVATE',
    ' https://msdl.microsoft.com/x?sig=PRIVATE',
    'https://msdl.microsoft.com/x y?sig=PRIVATE',
    'https://msdl.microsoft.com/x\ny?sig=PRIVATE',
    'https://msdl.microsoft.com/x\ry?sig=PRIVATE',
    'https://msdl.microsoft.com/x\ty?sig=PRIVATE',
    'https://msdl.microsoft.com/x\x7fy?sig=PRIVATE',
    'https://msdl.microsoft.com/x\u00a0y?sig=PRIVATE',
    'https://msdl.microsoft.com/\u00e9?sig=PRIVATE',
)


@pytest.mark.parametrize('url', BAD_URLS)
def test_invalid_initial_url_is_typed_and_refused_before_dispatch(url):
    fetch = Fake({})
    with pytest.raises(wp.WinpairsError) as error:
        wp.fetch_checked(fetch, url, 100)
    assert fetch.calls == []
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('location', BAD_URLS + ('\n/relative?sig=PRIVATE', '/x y?sig=PRIVATE'))
def test_invalid_raw_redirect_is_refused_before_join_and_dispatch(location):
    fetch = Fake({URL_A: wp.Response(302, location=location)})
    with pytest.raises(wp.WinpairsError) as error:
        wp.fetch_checked(fetch, URL_A, 100)
    assert fetch.calls == [URL_A]
    assert 'PRIVATE' not in str(error.value)


@pytest.mark.parametrize('location', (
    '../next/tcpip.sys?sig=a%2Fb%2Bc%3D&se=2026-11-20T01%3A00%3A00Z',
    '?sig=a%2Fb%2Bc%3D&se=2026-11-20T01%3A00%3A00Z',
    'https://shard.blob.core.windows.net/b/x?sig=a%2Fb%2Bc%3D&sp=r',
    '//shard.blob.core.windows.net/b/x?sig=a%2Fb%2Bc%3D&sp=r',
))
def test_relative_and_signed_redirects_preserve_exact_approved_query(location):
    target = urllib.parse.urljoin(URL_A, location)
    fetch = Fake({URL_A: wp.Response(302, location=location), target: b'verified body'})
    assert wp.fetch_checked(fetch, URL_A, 100) == b'verified body'
    assert fetch.calls == [URL_A, target]
    assert wp.check_url(target, redirect=True) == target


class TrackedBody(io.BytesIO):
    def __init__(self, content=b'', *, status=200):
        super().__init__(content)
        self.status = status
        self.read_calls = 0

    def read(self, *args):
        self.read_calls += 1
        return super().read(*args)


@pytest.mark.parametrize('status', (302, 404))
def test_http_error_response_is_closed_without_draining(monkeypatch, status):
    body = TrackedBody(b'not needed')
    headers = Message()
    headers['Location'] = '/next?sig=PRIVATE'

    class Opener:
        def open(self, request, timeout):
            raise urllib.error.HTTPError(request.full_url, status, 'authored', headers, body)

    monkeypatch.setattr(wp.urllib.request, 'build_opener', lambda *_: Opener())
    result = wp.urllib_fetcher(URL_A, 100, 1)
    assert result.status == status and result.body == b''
    assert result.location == '/next?sig=PRIVATE'
    assert body.closed and body.read_calls == 0


@pytest.mark.parametrize('error', (
    http.client.InvalidURL('PRIVATE'),
    ValueError('PRIVATE'),
    UnicodeEncodeError('ascii', '\u00e9PRIVATE', 0, 1, 'authored'),
))
def test_request_dispatch_error_stays_typed_and_redacted(monkeypatch, error):
    class Opener:
        def open(self, request, timeout):
            raise error

    monkeypatch.setattr(wp.urllib.request, 'build_opener', lambda *_: Opener())
    with pytest.raises(wp.WinpairsError) as caught:
        wp.urllib_fetcher(URL_A, 100, 1)
    assert 'PRIVATE' not in str(caught.value)


def test_direct_fetcher_refuses_invalid_url_before_constructing_opener(monkeypatch):
    def unexpected(*_):
        pytest.fail('invalid URL reached opener construction')

    monkeypatch.setattr(wp.urllib.request, 'build_opener', unexpected)
    with pytest.raises(wp.WinpairsError):
        wp.urllib_fetcher('https://@msdl.microsoft.com/x', 100, 1)


@pytest.mark.parametrize('location', (BAD_URLS[0], BAD_URLS[4], BAD_URLS[8]))
def test_cli_retains_malformed_redirect_as_missing_side_and_keeps_healthy_side(
    tmp_path, monkeypatch, capsys, location,
):
    monkeypatch.chdir(tmp_path)
    calls = []
    redirect_body = TrackedBody()
    bodies = []
    route = {IDX_URL: gzip.compress(json.dumps(index(A, B)).encode()), URL_A: BIN_A, URL_B: BIN_B}

    class Opener:
        def open(self, request, timeout):
            url = request.full_url
            calls.append(url)
            if url == URL_A:
                headers = Message()
                headers['Location'] = location
                raise urllib.error.HTTPError(url, 302, 'authored', headers, redirect_body)
            assert url in route, 'malformed redirect was dispatched'
            response = TrackedBody(route[url])
            bodies.append(response)
            return response

    monkeypatch.setattr(wp.urllib.request, 'build_opener', lambda *_: Opener())
    assert cli(tmp_path, wp.urllib_fetcher) == 1
    manifest = json.loads((tmp_path / 'pm.json').read_text())
    case = manifest['cases'][0]
    assert case['status'] == case['older']['status'] == 'missing'
    assert case['newer']['status'] == 'found' and case['newer']['sha256_verified']
    assert not (tmp_path / 'o/c1/older/tcpip.sys').exists()
    assert (tmp_path / 'o/c1/newer/tcpip.sys').read_bytes() == BIN_B
    assert calls == [IDX_URL, URL_A, URL_B]
    assert redirect_body.closed and redirect_body.read_calls == 0
    assert all(body.closed for body in bodies)
    captured = capsys.readouterr()
    assert 'PRIVATE' not in json.dumps(manifest) + captured.out + captured.err
