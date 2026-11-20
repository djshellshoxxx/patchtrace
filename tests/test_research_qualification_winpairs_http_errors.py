"""Malformed HTTP response controls for the real fetcher adapter; no sockets."""
from __future__ import annotations

import gzip
import http.client
import json

import pytest
from test_research_qualification_winpairs import BIN_A, BIN_B, IDX_URL, URL_A, URL_B, A, B, cli, index
from test_research_qualification_winpairs_urls import TrackedBody

from tools.research_qualification import winpairs as wp


def malformed(kind):
    return {
        'status': lambda: http.client.BadStatusLine('PRIVATE response status'),
        'truncated': lambda: http.client.IncompleteRead(b'PRIVATE body', 100),
        'header': lambda: http.client.LineTooLong('PRIVATE header'),
    }[kind]()


@pytest.mark.parametrize('kind', ['status', 'truncated', 'header'])
@pytest.mark.parametrize('boundary', ['open', 'read'])
def test_malformed_http_is_typed_and_redacted_and_acquired_response_is_closed(monkeypatch, kind, boundary):
    error = malformed(kind)

    class BrokenBody(TrackedBody):
        def read(self, *_args):
            self.read_calls += 1
            raise error

    body = BrokenBody()

    class Opener:
        def open(self, _request, *, timeout):
            if boundary == 'open':
                raise error
            return body

    monkeypatch.setattr(wp.urllib.request, 'build_opener', lambda *_: Opener())
    with pytest.raises(wp.WinpairsError) as caught:
        wp.urllib_fetcher(URL_A, 100, 1)
    assert str(caught.value) == f'network error: {type(error).__name__}'
    assert 'PRIVATE' not in str(caught.value)
    assert body.closed is (boundary == 'read')
    assert body.read_calls == (1 if boundary == 'read' else 0)
    body.close()  # The open-failure test never transfers this authored fixture.


@pytest.mark.parametrize('kind', ['status', 'truncated', 'header'])
def test_cli_malformed_binary_response_keeps_the_healthy_side(tmp_path, monkeypatch, capsys, kind):
    monkeypatch.chdir(tmp_path)
    error = malformed(kind)
    calls, bodies = [], []
    route = {IDX_URL: gzip.compress(json.dumps(index(A, B)).encode()), URL_A: BIN_A, URL_B: BIN_B}

    class BrokenBody(TrackedBody):
        def read(self, *_args):
            raise error

    class Opener:
        def open(self, request, *, timeout):
            url = request.full_url
            calls.append(url)
            response = BrokenBody() if url == URL_A else TrackedBody(route[url])
            bodies.append(response)
            return response

    monkeypatch.setattr(wp.urllib.request, 'build_opener', lambda *_: Opener())
    assert cli(tmp_path, wp.urllib_fetcher) == 1
    manifest = json.loads((tmp_path / 'pm.json').read_text())
    case = manifest['cases'][0]
    assert case['status'] == case['older']['status'] == 'missing'
    assert type(error).__name__ in case['older']['reason']
    assert case['newer']['status'] == 'found' and case['newer']['sha256_verified']
    assert not (tmp_path / 'o/c1/older/tcpip.sys').exists()
    assert (tmp_path / 'o/c1/newer/tcpip.sys').read_bytes() == BIN_B
    assert calls == [IDX_URL, URL_A, URL_B]
    assert all(body.closed for body in bodies)
    captured = capsys.readouterr()
    assert 'PRIVATE' not in json.dumps(manifest) + captured.out + captured.err
